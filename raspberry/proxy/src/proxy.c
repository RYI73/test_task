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

#define SPI_DEVICE "/dev/spidev0.0"
#define SPI_MODE 0
#define SPI_BITS 8
#define SPI_SPEED 1000000      /**< SPI speed in Hz */
#define MAX_PKT_SIZE 1500      /**< Maximum packet size for SPI transfer */
#define SPI_MAGIC 0x49504657   /**< Magic constant ('IPFW') for SPI framing */
#define SPI_PROTO_VERSION 1
#define PKT_LEN 128
#define SPI_CHUNK_MAGIC 0xA5

#define SPI_CHUNK_SIZE 32
#define SPI_CHUNK_PAYLOAD_SIZE 28
#define SPI_CHUNK_MAGIC 0xA5

uint8_t payload_pack[] = {
    0x45,0x00,0x00,0x54,0x33,0xe1,0x40,0x00,0x3f,0x01,0x3b,0xa7,
    0xc0,0xa8,0x01,0x77,0x0a,0x00,0x00,0x02,0x08,0x00,0xe6,0xce,
    0x12,0x0d,0x00,0x01,0xc9,0xae,0x47,0x69,0x00,0x00,0x00,0x00,
    0x2d,0x38,0x02,0x00,0x00,0x00,0x00,0x00,0x10,0x11,0x12,0x13,
    0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,
    0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37
};

static uint8_t rx_buff[PKT_LEN];

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

    uint8_t mode = 0;
    uint8_t bits = 8;
    uint32_t speed = SPI_SPEED;

    ioctl(fd, SPI_IOC_WR_MODE, &mode);
    ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);

    return fd;
}
#endif
/**
 * @brief Perform full-duplex SPI transfer
 *
 * @param spi_fd SPI device file descriptor
 * @param tx_buf Transmit buffer
 * @param rx_buf Receive buffer
 * @param len Number of bytes to transfer
 * @return Number of bytes transferred, or -1 on error
 */
//ssize_t spi_transfer(int spi_fd, uint8_t *tx_buf, uint8_t *rx_buf, size_t len) {
//    struct spi_ioc_transfer tr = {
//        .tx_buf = (unsigned long)tx_buf,
//        .rx_buf = (unsigned long)rx_buf,
//        .len = len,
//        .speed_hz = SPI_SPEED,
//        .bits_per_word = SPI_BITS,
//    };
//    printf("MASTER sent %d byte\ns", len);

//    int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), &tr);
//    if (ret < 1) {
//        perror("ERROR of spi transfer");
//        return -1;
//    }
//    return ret;
//}
ssize_t spi_transfer(int spi_fd,
                     uint8_t *tx_buf,
                     uint8_t *rx_buf,
                     size_t len)
{
    size_t offset = 0;
    ssize_t total = 0;

    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > SPI_CHUNK_SIZE)
            chunk = SPI_CHUNK_SIZE;

        struct spi_ioc_transfer tr = {
            .tx_buf = tx_buf ? (unsigned long)(tx_buf + offset) : 0,
            .rx_buf = rx_buf ? (unsigned long)(rx_buf + offset) : 0,
            .len = chunk,
            .speed_hz = SPI_SPEED,
            .bits_per_word = SPI_BITS,
            .delay_usecs = 0,
            .cs_change = 0,
        };

        int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), &tr);
        if (ret < 1) {
            perror("spi_transfer chunk failed");
            return -1;
        }

        offset += chunk;
        total  += chunk;

        usleep(5);
    }

    return total;
}

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
//        printf("Send %zd chunk:\n", seq);
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
    uint8_t tx[SPI_CHUNK_SIZE] = {0};   // master завжди щось тактує
    uint8_t rx[SPI_CHUNK_SIZE];

    size_t offset = 0;
    uint8_t expected_chunks = 0;
    uint8_t received_chunks = 0;
    uint8_t try_cntr = 0;
    uint8_t matrix[128] = {0};

    while (1) {
        struct spi_ioc_transfer tr = {
            .tx_buf = (unsigned long)tx,
            .rx_buf = (unsigned long)rx,
            .len = SPI_CHUNK_SIZE,
            .speed_hz = SPI_SPEED,
            .bits_per_word = 8,
        };

        if (ioctl(spi_fd, SPI_IOC_MESSAGE(1), &tr) < 1) {
            continue;
        }

        if (rx[0] != SPI_CHUNK_MAGIC) {
            usleep(1000);
            continue;
        }

//        // [DEBUG] Dump packet ONLY FOR DEBUG!!!
//        printf("chunk received: ");
//        for (int i = 0; i < SPI_CHUNK_SIZE; i++)
//            printf("%02x ", rx[i]);
//        printf("\n");
//        // [DEBUG] End

        uint8_t seq          = rx[1];
        uint8_t total_chunks = rx[2];
        uint8_t payload_len  = rx[3];

        if (matrix[seq]) {
            continue;
        }

        if (payload_len > SPI_CHUNK_PAYLOAD_SIZE)
            return -1;

        if (seq == 0) {
            offset = 0;
            received_chunks = 0;
            expected_chunks = total_chunks;
        }

        if (seq != received_chunks)
            return -1;

        memcpy(out + offset, &rx[4], payload_len);
        offset += payload_len;
        received_chunks++;
        matrix[seq] = 1;

//        printf("ch %u/%u %02X %02X\n", seq+1, total_chunks, rx[4], rx[5]);
        if (received_chunks == expected_chunks) {
            return 0;
        }

        if (++try_cntr == (PKT_LEN / SPI_CHUNK_SIZE) * 3) {
            printf("SPI no data\n");
            return -1;
        }
        usleep(1000);
    }

    return -1;
}

static void spi_read_packet(int fd)
{

    uint8_t tx[PKT_LEN] = {0};
    uint8_t rx[PKT_LEN];

    struct spi_ioc_transfer t = {
        .tx_buf = (unsigned long)tx,
        .rx_buf = (unsigned long)rx,
        .len = SPI_CHUNK_SIZE,
        .speed_hz = SPI_SPEED,
        .bits_per_word = 8,
    };

    ioctl(fd, SPI_IOC_MESSAGE(1), &t);

//    // [DEBUG] Dump packet ONLY FOR DEBUG!!!
//    printf("MASTER received: ");
//    for (int i = 0; i < SPI_CHUNK_SIZE; i++)
//        printf("%02x ", rx[i]);
//    printf("\n");
//    // [DEBUG] End
}

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

//    if (spi_transfer(spi_fd, buf, NULL, sizeof(buf)) < 0) return -1;
    if (spi_send_transfer(spi_fd, buf, sizeof(buf)) < 0) return -1;
    return 0;
}

///**
// * @brief Receive a packet from ESP32 via SPI
// *
// * @param spi_fd SPI file descriptor
// * @param data Buffer to store received packet
// * @return Number of bytes received, or -1 on error
// */
//int spi_receive_packet(int spi_fd, uint8_t *data)
//{
//    size_t sz_i = 0;
//    uint8_t buf[sizeof(spi_ip_hdr_t) + PKT_LEN + sizeof(uint32_t)];
//    sz_i = spi_transfer(spi_fd, NULL, buf, sizeof(buf));
//    if (sz_i < 0) {
//        return -1;
//    }

//    // [DEBUG] Dump packet ONLY FOR DEBUG!!!
//    printf("Received %zd bytes from TUN (IPv4)\n", sz_i);
//    for (ssize_t i = 0; i < sz_i; i++) {
//        if (i % 16 == 0) printf("\n%04zx: ", i);
//        printf("%02x ", buf[i]);
//    }
//    printf("\n");
//    // [DEBUG] End

//    spi_ip_hdr_t *hdr = (spi_ip_hdr_t *)buf;
//    if (ntohl(hdr->magic) != SPI_MAGIC) return -1;
//    if (hdr->version != 0x01) return -1;

//    uint16_t pkt_len = ntohs(hdr->length);
//    if (pkt_len == 0 || pkt_len > PKT_LEN) return -1;

//    uint8_t *payload = buf + sizeof(spi_ip_hdr_t);
//    uint32_t recv_crc;
//    memcpy(&recv_crc, payload + pkt_len, sizeof(recv_crc));

//    if (ntohl(recv_crc) != crc32(0, payload, pkt_len)) return -1;

//    memcpy(data, payload, pkt_len);
//    return pkt_len;
//}

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
void forward_loop(int tun_fd, int spi_fd) {
    uint8_t tun_buf[MAX_PKT_SIZE];
    uint8_t spi_buf[MAX_PKT_SIZE];

    int dbg_cntr = 0;
    while (1) {
        ssize_t n = read_tun_packet(tun_fd, tun_buf);
        if (n > 0) {
            uint8_t ip_version = tun_buf[0] >> 4;
            if (ip_version == 4) {
//                // [DEBUG] Dump packet ONLY FOR DEBUG!!!
//                printf("Received %zd bytes from TUN (IPv4)\n", n);
//                for (ssize_t i = 0; i < n; i++) {
//                    if (i % 16 == 0) printf("\n%04zx: ", i);
//                    printf("%02x ", tun_buf[i]);
//                }
//                printf("\n");
//                if (n >= 21 && tun_buf[20] == 0) {
//                    printf("This is ICMP Echo Reply\n");
//                }
//                // [DEBUG] End

                // Forward to SPI
                spi_send_packet(spi_fd, tun_buf, n);
            } else if (ip_version == 6) {
                // Ignore IPv6 packets
                printf("Received IPv6 packet, ignoring\n");
            } else {
                printf("Unknown IP version %d, ignoring\n", ip_version);
            }
        }

//        int rcv_len = spi_receive_packet(spi_fd, spi_buf);
//        if (rcv_len > 0) {
//            uint8_t ip_version = spi_buf[0] >> 4;
//            if (ip_version == 4) {
//                write_tun_packet(tun_fd, spi_buf, rcv_len);
//            }
//        }

        static uint8_t cntr = 0;
        printf("%u\n", cntr++);
//        spi_receive(spi_fd);

        if (dbg_cntr++ > 3) {
          break;
        }
        usleep(1000);
    }
}

void spi_send_incremental(int spi_fd) {
    #define BUF_LEN 32
    uint8_t tx_buf[BUF_LEN];
    uint8_t rx_buf[BUF_LEN];

    // Заповнюємо буфер значеннями від 0 до 31
    for (int i = 0; i < BUF_LEN; i++) {
        tx_buf[i] = i;
    }

    struct spi_ioc_transfer tr = {
        .tx_buf = (unsigned long)tx_buf,
        .rx_buf = (unsigned long)rx_buf, // можемо ігнорувати отримане
        .len = BUF_LEN,
        .speed_hz = SPI_SPEED,
        .bits_per_word = SPI_BITS,
    };

    int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), &tr);
    if (ret < 1) {
        perror("spi transfer");
        return;
    }

    printf("Sent 32 incremental bytes:\n");
    for (int i = 0; i < BUF_LEN; i++) {
        printf("%02x ", tx_buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

/**
 * @brief Send a test ICMP packet to TUN for verification
 *
 * This function sends one ICMP echo request and reads the reply.
 *
 * @param tun_fd TUN file descriptor
 */
void test_icmp(int tun_fd) {

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

//    forward_loop(tun_fd, spi_fd);

    printf("=== TEST 1: master -> slave ===\n");
    for (int i = 0; i < 3; i++) {
        spi_send_packet(spi_fd, payload_pack, sizeof(payload_pack));
        usleep(100000);
    }

    usleep(1000);
    printf("=== TEST 2: master <- slave ===\n");
    for (int i = 0; i < 3; i++) {
//       spi_read_packet(spi_fd);

        uint16_t length = 0;
        static uint8_t rx[PKT_LEN];
        if (!spi_receive(spi_fd, rx, &length)) {
            printf("\nReceived valid SPI packet (%d bytes):", length);
            for (int i = 0; i < length; i++) {
                if (i % 16 == 0) printf("\n%04x: ", i);
                printf("%02x ", rx[i]);
            }
            printf("\n");
        }

//        memset(rx_buff, 0 ,sizeof(rx_buff));
//        if (!spi_recv_transfer(spi_fd, rx_buff)) {
//            // [DEBUG] Dump packet ONLY FOR DEBUG!!!
//            printf("MASTER received: ");
//            for (int i = 0; i < sizeof(rx_buff); i++)
//                printf("%02x ", rx_buff[i]);
//            printf("\n");
//            // [DEBUG] End

//        }
       usleep(200000);
    }

    close(spi_fd);
    close(tun_fd);
    return 0;
}
