/**
 * @file proxy.c
 * @brief SPI-to-TUN proxy for forwarding IPv4 packets from SPI to Linux TUN interface
 *
 * This program creates a TUN interface, sets its IP address, and forwards
 * IPv4 packets between SPI and the kernel network stack.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/spi/spidev.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <stdbool.h>

#define SPI_DEVICE "/dev/spidev0.0"
#define SPI_MODE 0
#define SPI_BITS 8
#define SPI_SPEED 1000000      /**< SPI speed in Hz */
#define MAX_PKT_SIZE 1500      /**< Maximum packet size for SPI transfer */
#define SPI_MAGIC 0x49504657   /**< Magic constant ('IPFW') for SPI framing */
#define SPI_PROTO_VERSION 1
#define PKT_LEN 128

#define SPI_CHUNK_SIZE 32
#define SPI_CHUNK_PAYLOAD_SIZE (SPI_CHUNK_SIZE - 4)
#define SPI_CHUNK_MAGIC 0xA5

#define GPIO_SPI_READY 25
#define GPIO_READY_SYSFS "/sys/class/gpio/gpio537/value"

uint8_t payload_pack[] = {
    0x45,0x00,0x00,0x54,0x33,0xe1,0x40,0x00,0x3f,0x01,0x3b,0xa7,
    0xc0,0xa8,0x01,0x77,0x0a,0x00,0x00,0x02,0x08,0x00,0xe6,0xce,
    0x12,0x0d,0x00,0x01,0xc9,0xae,0x47,0x69,0x00,0x00,0x00,0x00,
    0x2d,0x38,0x02,0x00,0x00,0x00,0x00,0x00,0x10,0x11,0x12,0x13,
    0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,
    0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37
};

unsigned char icmp_replay[] = {
    0x45, 0x00, 0x00, 0x54, 0xB0, 0xD3, 0x00, 0x00, 0x40, 0x01, 0xFD, 0xB4, 0x0A, 0x00, 0x00, 0x02,
    0xC0, 0xA8, 0x01, 0x77, 0x00, 0x00, 0xE0, 0xE8, 0xF8, 0xF8, 0x00, 0x6C, 0xD0, 0xE9, 0x49, 0x69,
    0x00, 0x00, 0x00, 0x00, 0x4C, 0x8C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37
};

static uint8_t spi_recv_tx_buff[PKT_LEN + 1];
static uint8_t spi_recv_rx_buff[PKT_LEN + 1];
static uint8_t spi_send_tx_buff[PKT_LEN + 1];
static uint8_t spi_send_rx_buff[PKT_LEN + 1];

static uint8_t rx_buff[PKT_LEN];
int gpio_fd = -1;

/**
 * @struct spi_ip_hdr_t
 * @brief Header for framing IPv4 packets over SPI
 */
typedef struct __attribute__((packed)) {
    uint32_t magic;     /**< Magic constant SPI_MAGIC */
    uint8_t version;    /**< Protocol version (0x01) */
    uint8_t flags;      /**< Reserved flags */
    uint16_t length;    /**< IPv4 packet length in bytes */
} spi_ip_hdr_t;

/**
 * @brief Compute CRC32 over a buffer
 *
 * @param crc Initial CRC value
 * @param buf Pointer to buffer
 * @param len Length of buffer in bytes
 * @return Computed CRC32 value
 */
uint32_t crc32(uint32_t crc, const uint8_t *buf, size_t len) {
    uint32_t c = crc ^ 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        c ^= buf[i];
        for (int k = 0; k < 8; k++)
            c = c & 1 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
    }
    return c ^ 0xFFFFFFFF;
}

static inline int64_t timespec_to_ms(struct timespec *ts)
{
    return (int64_t)ts->tv_sec * 1000 +
           ts->tv_nsec / 1000000;
}
/***********************************************************************************************/
static inline uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
/***********************************************************************************************/
static inline uint32_t now_ms(void)
{
    return (uint32_t)(now_ns() / 1000000);
}
/***********************************************************************************************/

/**
 * @brief Allocate a TUN interface
 *
 * @param devname Name of the TUN interface to create
 * @return File descriptor of the TUN interface, or -1 on error
 */
int tun_alloc(char *devname) {
    struct ifreq ifr;
    int fd;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("tun open");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (devname)
        strncpy(ifr.ifr_name, devname, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("tun ioctl");
        close(fd);
        return -1;
    }

    printf("TUN interface %s created\n", ifr.ifr_name);
    return fd;
}

/**
 * @brief Set TUN interface UP
 *
 * @param ifname Interface name
 * @return 0 on success, -1 on error
 */
int tun_set_up(const char *ifname) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror("SIOCGIFFLAGS");
        close(sock);
        return -1;
    }

    if (!(ifr.ifr_flags & IFF_UP)) {
        ifr.ifr_flags |= IFF_UP;
        if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
            perror("SIOCSIFFLAGS");
            close(sock);
            return -1;
        }
        printf("Interface %s set UP\n", ifname);
    }

    close(sock);
    return 0;
}

/**
 * @brief Check if TUN interface has specific IP address
 *
 * @param ifname Interface name
 * @param ip_str IP address as string
 * @return 1 if IP is present, 0 otherwise
 */
int tun_has_ip(const char *ifname, const char *ip_str) {
    struct ifreq ifr;
    struct sockaddr_in *addr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        close(sock);
        return 0;   /**< IP not set yet */
    }

    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    close(sock);

    return strcmp(inet_ntoa(addr->sin_addr), ip_str) == 0;
}

/**
 * @brief Add IP address to TUN interface
 *
 * @param ifname Interface name
 * @param ip_str IP address as string
 * @return 0 on success, -1 on error
 */
int tun_add_ip(const char *ifname, const char *ip_str) {
    struct ifreq ifr;
    struct sockaddr_in addr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip_str, &addr.sin_addr);
    memcpy(&ifr.ifr_addr, &addr, sizeof(addr));

    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        perror("SIOCSIFADDR");
        close(sock);
        return -1;
    }

    close(sock);
    printf("IP %s added to %s\n", ip_str, ifname);
    return 0;
}

/**
 * @brief Initialize SPI device
 *
 * @param device SPI device path
 * @return SPI file descriptor or -1 on error
 */
#if 0
int spi_init(const char *device) {
    int spi_fd = open(device, O_RDWR);
    if (spi_fd < 0) {
        perror("spi open");
        return -1;
    }

    uint8_t mode = SPI_MODE;
    uint8_t bits = SPI_BITS;
    uint32_t speed = SPI_SPEED;

    if (ioctl(spi_fd, SPI_IOC_WR_MODE, &mode) < 0 ||
        ioctl(spi_fd, SPI_IOC_WR_BITS_PER_WORD, &bits) < 0 ||
        ioctl(spi_fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed) < 0) {
        perror("spi setup");
        close(spi_fd);
        return -1;
    }

    return spi_fd;
}
#else
static int spi_init(const char *device)
{
    int fd = open(device, O_RDWR);
    if (fd < 0) {
        perror("open spidev");
        return -1;
    }

    uint8_t mode = SPI_MODE;
    uint8_t bits = SPI_BITS;
    uint32_t speed = SPI_SPEED;

    ioctl(fd, SPI_IOC_WR_MODE, &mode);
    ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);

    return fd;
}
#endif
///**
// * @brief Perform full-duplex SPI transfer
// *
// * @param spi_fd SPI device file descriptor
// * @param tx_buf Transmit buffer
// * @param rx_buf Receive buffer
// * @param len Number of bytes to transfer
// * @return Number of bytes transferred, or -1 on error
// */
//ssize_t spi_transfer(int spi_fd,
//                     uint8_t *tx_buf,
//                     uint8_t *rx_buf,
//                     size_t len)
//{
//    size_t offset = 0;
//    ssize_t total = 0;

//    while (offset < len) {
//        size_t chunk = len - offset;
//        if (chunk > SPI_CHUNK_SIZE)
//            chunk = SPI_CHUNK_SIZE;

//        struct spi_ioc_transfer tr = {
//            .tx_buf = tx_buf ? (unsigned long)(tx_buf + offset) : 0,
//            .rx_buf = rx_buf ? (unsigned long)(rx_buf + offset) : 0,
//            .len = chunk,
//            .speed_hz = SPI_SPEED,
//            .bits_per_word = SPI_BITS,
//            .delay_usecs = 0,
//            .cs_change = 0,
//        };

//        int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), &tr);
//        if (ret < 1) {
//            perror("spi_transfer chunk failed");
//            return -1;
//        }

//        offset += chunk;
//        total  += chunk;

//        usleep(5);
//    }

//    return total;
//}
# if 1
int spi_send_transfer(int spi_fd, const uint8_t *data, size_t len)
{
    uint32_t start = 0;
    bool is_timeout = false;
    char gpio_value;

    if (!data || len == 0)
        return -1;

    /* DEBUG dump */
    printf("\nSPI SEND %zu bytes:", len);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) printf("\n%04zx: ", i);
        printf("%02x ", data[i]);
    }
    printf("\n");

    memcpy(spi_send_tx_buff, data, len);

    start = now_ms();
    struct spi_ioc_transfer tr = {
        .tx_buf        = (unsigned long)spi_send_tx_buff,
        .rx_buf        = (unsigned long)spi_send_rx_buff,
        .len           = len,
        .speed_hz      = SPI_SPEED,
        .bits_per_word = 8,
        .cs_change     = 0,
    };

    while (1) {
        lseek(gpio_fd, 0, SEEK_SET);
        read(gpio_fd, &gpio_value, 1);
        if (gpio_value == '1') break;   // ESP32 READY
        if (now_ms() - start >= 500) {
            is_timeout = true;
            break;
        }
        usleep(100);
    }

    if (!is_timeout) {
        int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), &tr);
        if (ret < 1) {
            perror("spi send");
            return -1;
        }
    }

    return 0;
}

int spi_recv_transfer(int spi_fd, uint8_t *out)
{
    uint32_t start = 0;
    bool is_timeout = false;
    char gpio_value;

    if (!out)
        return -1;

    memset(spi_recv_tx_buff, 0, PKT_LEN);
    start = now_ms();
    struct spi_ioc_transfer tr = {
        .tx_buf        = (unsigned long)spi_recv_tx_buff,
        .rx_buf        = (unsigned long)spi_recv_rx_buff,
        .len           = PKT_LEN,
        .speed_hz      = SPI_SPEED,
        .bits_per_word = 8,
        .cs_change     = 0,
    };

    while (1) {
        lseek(gpio_fd, 0, SEEK_SET);
        read(gpio_fd, &gpio_value, 1);
        if (gpio_value == '1') break;   // ESP32 READY
        if (now_ms() - start >= 100) {
            is_timeout = true;
            break;
        }
        usleep(100);
    }

    if (!is_timeout) {
        int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), &tr);
        if (ret < 1) {
            perror("spi recv");
            return -1;
        }
        else {
            memcpy(out, spi_recv_rx_buff, PKT_LEN);
            /* DEBUG dump */
//            printf("\nSPI RECV %zu bytes:", PKT_LEN);
//            for (size_t i = 0; i < PKT_LEN; i++) {
//                if (i % 16 == 0) printf("\n%04zx: ", i);
//                printf("%02x ", out[i]);
//            }
//            printf("\n");
        }
    }
    else {
        return -1;
    }

    return 0;
}

#else
int spi_send_transfer(int spi_fd, const uint8_t *data, size_t len)
{
    uint8_t tx[SPI_CHUNK_SIZE] = {0};
    uint8_t rx[SPI_CHUNK_SIZE] = {0};

    // [DEBUG] Dump packet ONLY FOR DEBUG!!!
    printf("\nSend %zd bytes to SPI:", len);
    for (ssize_t i = 0; i < len; i++) {
        if (i % 16 == 0) printf("\n%04zx: ", i);
        printf("%02x ", data[i]);
    }
    printf("\n");
    // [DEBUG] End

    uint8_t total_chunks = (len + SPI_CHUNK_PAYLOAD_SIZE - 1) / SPI_CHUNK_PAYLOAD_SIZE;
    size_t offset = 0;

    for (uint8_t seq = 0; seq < total_chunks; seq++) {
        size_t chunk_len = len - offset;
        if (chunk_len > SPI_CHUNK_PAYLOAD_SIZE)
            chunk_len = SPI_CHUNK_PAYLOAD_SIZE;

        memset(tx, 0, sizeof(tx));
        tx[0] = SPI_CHUNK_MAGIC;
        tx[1] = seq;
        tx[2] = total_chunks;
        tx[3] = chunk_len;
        memcpy(&tx[4], data + offset, chunk_len);

        struct spi_ioc_transfer tr = {
            .tx_buf = (unsigned long)tx,
            .rx_buf = (unsigned long)rx,
            .len = SPI_CHUNK_SIZE,
            .speed_hz = SPI_SPEED,
            .bits_per_word = 8,
        };

        if (ioctl(spi_fd, SPI_IOC_MESSAGE(1), &tr) < 1) {
            perror("spi send");
            return -1;
        }

//        // [DEBUG] Dump packet ONLY FOR DEBUG!!!
        printf("Send chunk %u/%u\n", seq, total_chunks);
//        for (ssize_t i = 0; i < SPI_CHUNK_SIZE; i++) {
//            if (i % 16 == 0) printf("\n%04zx: ", i);
//            printf("%02x ", tx[i]);
//        }
//        printf("\n");
//        // [DEBUG] End

        offset += chunk_len;
        usleep(1000);   // 1 ms — критично для slave
    }

    return 0;
}

int spi_recv_transfer(int spi_fd, uint8_t *out)
{
    uint8_t tx[SPI_CHUNK_SIZE] = {0};
    uint8_t rx[SPI_CHUNK_SIZE];

    size_t offset = 0;
    uint8_t expected_chunks = 0;
    uint8_t received_chunks = 0;
    uint8_t matrix[128] = {0};
    uint32_t start = 0;
    const uint32_t timeout = 200;
    bool is_spi_slave_ready = false;

    char gpio_value;
//    printf("...\n");

    start = now_ms();
    while (1) {
        lseek(gpio_fd, 0, SEEK_SET);
        read(gpio_fd, &gpio_value, 1);
        if (gpio_value == '1') {
            is_spi_slave_ready = true;
            break;
        }
        if (now_ms() - start >= 50) {
//            printf("quit\n");
            break;
        }
        usleep(100);
    }

    if (!is_spi_slave_ready) {
        return -1;
    }

    printf("---\n");

    start = now_ms();
    while (1) {
        struct spi_ioc_transfer tr = {
            .tx_buf = (unsigned long)tx,
            .rx_buf = (unsigned long)rx,
            .len = SPI_CHUNK_SIZE,
            .speed_hz = SPI_SPEED,
            .bits_per_word = 8,
        };

        while (1) {
            lseek(gpio_fd, 0, SEEK_SET);
            read(gpio_fd, &gpio_value, 1);
            if (gpio_value == '1') break;   // ESP32 READY
            if (now_ms() - start >= timeout) {
                break;
            }
            usleep(100);
        }
        if (now_ms() - start >= timeout) {
            printf("SPI recv timeout\n");
            break;
        }

//        printf("ESP32 ready.\n");

        if (ioctl(spi_fd, SPI_IOC_MESSAGE(1), &tr) < 1) {
            continue;
        }

        if (rx[0] != SPI_CHUNK_MAGIC) {
//            usleep(1000);
            continue;
        }

        uint8_t seq          = rx[1];
        uint8_t total_chunks = rx[2];
        uint8_t payload_len  = rx[3];

        // [DEBUG] Dump packet ONLY FOR DEBUG!!!
        printf("chunk recv: %u/%u\n", seq+1, total_chunks);
//        for (int i = 0; i < SPI_CHUNK_SIZE; i++)
//            printf("%02x ", rx[i]);
//        printf("\n");
        // [DEBUG] End

        if (matrix[seq]) {
            continue;
        }

        if (payload_len > SPI_CHUNK_PAYLOAD_SIZE) {
            printf("Bad payload len %u\n", payload_len);
//            break;
        }

        if (seq == 0) {
            offset = 0;
            received_chunks = 0;
            expected_chunks = total_chunks;
        }

//        if (seq != received_chunks) {
//            printf("seq != received_chunks: %u != %u\n", seq, received_chunks);
//            break;
//        }

        memcpy(out + offset, &rx[4], payload_len);
        offset += payload_len;
        received_chunks++;
        matrix[seq] = 1;

//        printf("ch %u/%u %02X %02X\n", seq+1, total_chunks, rx[4], rx[5]);
        if (received_chunks == expected_chunks) {
            return 0;
        }

        if (seq + 1 == total_chunks) {
//            printf("seq == total_chunks\n");
            break;
        }

        usleep(1000);
    }

    return -1;
}
#endif
//static void spi_read_packet(int fd)
//{

//    uint8_t tx[PKT_LEN] = {0};
//    uint8_t rx[PKT_LEN];

//    struct spi_ioc_transfer t = {
//        .tx_buf = (unsigned long)tx,
//        .rx_buf = (unsigned long)rx,
//        .len = SPI_CHUNK_SIZE,
//        .speed_hz = SPI_SPEED,
//        .bits_per_word = 8,
//    };

//    ioctl(fd, SPI_IOC_MESSAGE(1), &t);

////    // [DEBUG] Dump packet ONLY FOR DEBUG!!!
////    printf("MASTER received: ");
////    for (int i = 0; i < SPI_CHUNK_SIZE; i++)
////        printf("%02x ", rx[i]);
////    printf("\n");
////    // [DEBUG] End
//}

static void spi_write_packet(int fd, uint8_t base)
{
    uint8_t tx[32];
    uint8_t rx[32] = {0};

    for (int i = 0; i < 32; i++)
        tx[i] = base + i;

    struct spi_ioc_transfer t = {
        .tx_buf = (unsigned long)tx,
        .rx_buf = (unsigned long)rx,
        .len = 32,
        .speed_hz = SPI_SPEED,
        .bits_per_word = 8,
    };

    ioctl(fd, SPI_IOC_MESSAGE(1), &t);

    printf("MASTER sent: ");
    for (int i = 0; i < 32; i++)
        printf("%02x ", tx[i]);
    printf("\n");
}


/**
 * @brief Read a packet from TUN interface
 *
 * @param tun_fd File descriptor of TUN
 * @param buf Buffer to store packet
 * @return Number of bytes read, or -1 on error
 */
//ssize_t read_tun_packet(int tun_fd, uint8_t *buf) {
//    ssize_t n = read(tun_fd, buf, MAX_PKT_SIZE);
//    if (n < 0 && errno != EAGAIN) perror("read tun");
//    return n;
//}

ssize_t read_tun_packet(int tun_fd, uint8_t *buf)
{
    static int nonblock_set = 0;
    if (!nonblock_set) {
        int flags = fcntl(tun_fd, F_GETFL, 0);
        fcntl(tun_fd, F_SETFL, flags | O_NONBLOCK);
        nonblock_set = 1;
    }

    ssize_t n = read(tun_fd, buf, MAX_PKT_SIZE);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("read tun");
        }

        return 0;
    }
    return n;
}

/**
 * @brief Write a packet to TUN interface
 *
 * @param tun_fd File descriptor of TUN
 * @param buf Packet data
 * @param len Length of packet
 * @return Number of bytes written, or -1 on error
 */
ssize_t write_tun_packet(int tun_fd, uint8_t *buf, size_t len) {
    ssize_t n = write(tun_fd, buf, len);
    if (n < 0) perror("write tun");
    return n;
}

/**
 * @brief Send a packet to ESP32 via SPI
 *
 * @param spi_fd SPI file descriptor
 * @param data Packet data
 * @param len Packet length
 * @return 0 on success, -1 on error
 */
int spi_send_packet(int spi_fd, uint8_t *data, uint16_t len)
{
    if (len == 0 || len > PKT_LEN) {
        return -1;
    }

    spi_ip_hdr_t hdr = {
        .magic = SPI_MAGIC,
        .version = 0x01,
        .flags = 0,
        .length = len
    };

    uint32_t crc = crc32(0, data, len);

//    uint8_t buf[sizeof(hdr) + len + sizeof(crc)];
    uint8_t buf[PKT_LEN] = {0};
    size_t offset = 0;
    memcpy(buf + offset, &hdr, sizeof(hdr)); offset += sizeof(hdr);
    memcpy(buf + offset, data, len); offset += len;
    memcpy(buf + offset, &crc, sizeof(crc));

//    // [DEBUG] Dump packet ONLY FOR DEBUG!!!
//    printf("Send %zd bytes to TUN:\n", offset + sizeof(crc));
//    for (ssize_t i = 0; i < offset + sizeof(crc); i++) {
//        if (i % 16 == 0) printf("\n%04zx: ", i);
//        printf("%02x ", buf[i]);
//    }
//    printf("\n");
//    // [DEBUG] End

    if (spi_send_transfer(spi_fd, buf, sizeof(buf)) < 0) return -1;
    return 0;
}

/**
 * @brief Receive a packet from ESP32 via SPI
 *
 * @param spi_fd SPI file descriptor
 * @param out_buf Buffer to store received packet
 * @param length Return length of packet
 * @return Number of bytes received, or -1 on error
 */
int spi_receive(int spi_fd, uint8_t *out_buf, uint16_t *length)
{
    memset(rx_buff, 0 ,sizeof(rx_buff));
    if (!spi_recv_transfer(spi_fd, rx_buff)) {

//        // [DEBUG] Dump packet ONLY FOR DEBUG!!!
//        printf("MASTER received: ");
//        for (int i = 0; i < sizeof(rx_buff); i++)
//            printf("%02x ", rx_buff[i]);
//        printf("\n");
//        // [DEBUG] End

        spi_ip_hdr_t *hdr = (spi_ip_hdr_t *)rx_buff;
        uint32_t magic = hdr->magic;
        if (magic != SPI_MAGIC) {
            printf("Bad magic %08X != %08X\n", magic, SPI_MAGIC);
            return -1;
        }

        uint16_t pkt_len = hdr->length;
        if (pkt_len == 0 || pkt_len > PKT_LEN) {
            printf("Bad length %u\n", pkt_len);
            return -1;
        }

        uint8_t *payload = rx_buff + sizeof(spi_ip_hdr_t);
        uint32_t recv_crc;
        memcpy(&recv_crc, payload + pkt_len, sizeof(recv_crc));
        if (recv_crc != crc32(0, payload, pkt_len)) {
            printf("Bad crc\n");
            return -1;
        }

        memcpy(out_buf, payload, hdr->length);
        *length = hdr->length;

        return 0;
    }

    return -1;
}

/**
 * @brief Forward packets between TUN and SPI, ignore IPv6
 *
 * @param tun_fd TUN file descriptor
 * @param spi_fd SPI file descriptor
 */
void forward_loop(int tun_fd, int spi_fd)
{
    uint8_t tun_buf[MAX_PKT_SIZE];
    static uint8_t spi_rx[PKT_LEN];
    uint16_t length = 0;

    while (1) {
        ssize_t n = read_tun_packet(tun_fd, tun_buf);
        if (n > 0) {
            uint8_t ip_version = tun_buf[0] >> 4;
            if (ip_version == 4) {

                // [DEBUG] Dump packet ONLY FOR DEBUG!!!
                printf("Received %zd bytes from TUN (IPv4)\n", n);
                for (ssize_t i = 0; i < n; i++) {
                    if (i % 16 == 0) printf("\n%04zx: ", i);
                    printf("%02x ", tun_buf[i]);
                }
                printf("\n");
                if (n >= 21 && tun_buf[20] == 0) {
                    printf("This is ICMP Echo Reply\n");
                }
                // [DEBUG] End

                usleep(100000);
                // Forward to SPI
                spi_send_packet(spi_fd, tun_buf, n);
            } else if (ip_version == 6) {
                // Ignore IPv6 packets
                printf("Received IPv6 packet, ignoring\n");
            } else {
                printf("Unknown IP version %d, ignoring\n", ip_version);
            }
        }

//        static uint8_t cntr = 0;
//        printf("%u\n", cntr++);

        length = 0;
        if (!spi_receive(spi_fd, spi_rx, &length)) {

            // [DEBUG] Dump packet ONLY FOR DEBUG!!!
            printf("\nReceived valid SPI packet (%d bytes):", length);
            for (int i = 0; i < length; i++) {
                if (i % 16 == 0) printf("\n%04x: ", i);
                printf("%02x ", spi_rx[i]);
            }
            printf("\n");
            // [DEBUG] End

            write_tun_packet(tun_fd, spi_rx, length);

        }

        usleep(1000);
    }
}

/**
 * @brief Send a test ICMP packet to TUN for verification
 *
 * This function sends one ICMP echo request and reads the reply.
 *
 * @param tun_fd TUN file descriptor
 */
void test_icmp(int tun_fd)
{
    printf("Sending test ICMP packet to TUN...\n");
    write_tun_packet(tun_fd, payload_pack, sizeof(payload_pack));
}

/**
 * @brief Main entry point
 */
int main() {
    const char *tun_name = "tun0";
    const char *tun_ip   = "10.0.0.2";

    int tun_fd = tun_alloc((char *)tun_name);
    if (tun_fd < 0) return 1;

    if (tun_set_up(tun_name) < 0) return 1;

    if (!tun_has_ip(tun_name, tun_ip)) {
        if (tun_add_ip(tun_name, tun_ip) < 0) return 1;
    }

    int spi_fd = spi_init(SPI_DEVICE);
    if (spi_fd < 0) return 1;

    // Disable reverse path filter to prevent kernel from dropping packets
    system("sudo sysctl -w net.ipv4.conf.all.rp_filter=0");
    system("sudo sysctl -w net.ipv4.conf.tun0.rp_filter=0");

    // Policy routing: all packets with src=10.0.0.2 go via tun0
    system("sudo ip rule add from 10.0.0.2/32 table 100");
    system("sudo ip route add default dev tun0 table 100");
    system("sudo ip route flush cache");

    // Disable IPv6 on tun0
    system("sudo sysctl -w net.ipv6.conf.tun0.disable_ipv6=1");

    gpio_fd = open(GPIO_READY_SYSFS, O_RDONLY);

    // [DEBUG] Test ICMP ONLY FOR DEBUG!!!
//    for (int i = 0; i < 5; i++) {
//        spi_write_packet(spi_fd, i * 0x10);
//        usleep(100);
//    }
//    uint8_t rx[5][2048];
//    for (int i = 0; i < 5; i++) {
//        spi_read_packet(spi_fd, rx[i]);
//        usleep(2000);
//    }

//    for (int i = 0; i < 5; i++) {
//        printf("MASTER received [%d]: ", i);
//        for (ssize_t c = 0; c < 128; c++) {
//            if (c % 32 == 0) printf("\n%04zx: ", c);
//            printf("%02x ", rx[i][c]);
//        }
//        printf("\n");
//    }

//    test_icmp(tun_fd);
    // [DEBUG] End

    printf("=== TEST 1: master -> slave ===\n");
    for (int i = 0; i < 10; i++) {
        spi_send_packet(spi_fd, icmp_replay, sizeof(icmp_replay));
        usleep(100000);
    }

//    usleep(100000);
//    printf("=== TEST 2: master <- slave ===\n");
//    for (int i = 0; i < 10; ) {
//        uint16_t length = 0;
//        static uint8_t rx[PKT_LEN];
//        if (!spi_receive(spi_fd, rx, &length)) {
//            printf("\nReceived %d valid SPI packet (%d bytes):", i+1, length);
//            for (int i = 0; i < length; i++) {
//                if (i % 16 == 0) printf("\n%04x: ", i);
//                printf("%02x ", rx[i]);
//            }
//            printf("\n");
//            i++;
//        }
//        else {
//          usleep(10000);
//        }

//        usleep(1000);
//    }

    forward_loop(tun_fd, spi_fd);

//    printf("=== TEST 1: master -> slave ===\n");
//    for (int i = 0; i < 3; i++) {
//        spi_send_packet(spi_fd, payload_pack, sizeof(payload_pack));
//        usleep(1000);
//    }

//    usleep(200000);
//    printf("=== TEST 2: master <- slave ===\n");
//    for (int i = 0; i < 4; i++) {
//        uint16_t length = 0;
//        static uint8_t rx[PKT_LEN];
//        if (!spi_receive(spi_fd, rx, &length)) {
//            printf("\nReceived valid SPI packet (%d bytes):", length);
//            for (int i = 0; i < length; i++) {
//                if (i % 16 == 0) printf("\n%04x: ", i);
//                printf("%02x ", rx[i]);
//            }
//            printf("\n");
//        }

//        usleep(1000);
//    }

    close(gpio_fd);
    close(spi_fd);
    close(tun_fd);
    return 0;
}
