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
#define SPI_SPEED 100000      /**< SPI speed in Hz */
#define MAX_PKT_SIZE 1500      /**< Maximum packet size for SPI transfer */
#define SPI_MAGIC 0x49504657   /**< Magic constant ('IPFW') for SPI framing */

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

/**
 * @brief Perform full-duplex SPI transfer
 *
 * @param spi_fd SPI device file descriptor
 * @param tx_buf Transmit buffer
 * @param rx_buf Receive buffer
 * @param len Number of bytes to transfer
 * @return Number of bytes transferred, or -1 on error
 */
ssize_t spi_transfer(int spi_fd, uint8_t *tx_buf, uint8_t *rx_buf, size_t len) {
    struct spi_ioc_transfer tr = {
        .tx_buf = (unsigned long)tx_buf,
        .rx_buf = (unsigned long)rx_buf,
        .len = len,
        .speed_hz = SPI_SPEED,
        .bits_per_word = SPI_BITS,
    };

    int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), &tr);
    if (ret < 1) {
        perror("spi transfer");
        return -1;
    }
    return ret;
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
int spi_send_packet(int spi_fd, uint8_t *data, uint16_t len) {
    if (len == 0 || len > MAX_PKT_SIZE) return -1;

    spi_ip_hdr_t hdr = {
        .magic = htonl(SPI_MAGIC),
        .version = 0x01,
        .flags = 0,
        .length = htons(len)
    };

    uint32_t crc = htonl(crc32(0, data, len));

    uint8_t buf[sizeof(hdr) + len + sizeof(crc)];
    size_t offset = 0;
    memcpy(buf + offset, &hdr, sizeof(hdr)); offset += sizeof(hdr);
    memcpy(buf + offset, data, len); offset += len;
    memcpy(buf + offset, &crc, sizeof(crc));

    if (spi_transfer(spi_fd, buf, NULL, sizeof(buf)) < 0) return -1;
    return 0;
}

/**
 * @brief Receive a packet from ESP32 via SPI
 *
 * @param spi_fd SPI file descriptor
 * @param data Buffer to store received packet
 * @return Number of bytes received, or -1 on error
 */
int spi_receive_packet(int spi_fd, uint8_t *data)
{
    size_t sz_i = 0;
    uint8_t buf[sizeof(spi_ip_hdr_t) + MAX_PKT_SIZE + sizeof(uint32_t)];
    sz_i = spi_transfer(spi_fd, NULL, buf, sizeof(buf));
    if (sz_i < 0) {
        return -1;
    }

    // [DEBUG] Dump packet ONLY FOR DEBUG!!!
    printf("Received %zd bytes from TUN (IPv4)\n", sz_i);
    for (ssize_t i = 0; i < sz_i; i++) {
        if (i % 16 == 0) printf("\n%04zx: ", i);
        printf("%02x ", buf[i]);
    }
    printf("\n");
    // [DEBUG] End

    spi_ip_hdr_t *hdr = (spi_ip_hdr_t *)buf;
    if (ntohl(hdr->magic) != SPI_MAGIC) return -1;
    if (hdr->version != 0x01) return -1;

    uint16_t pkt_len = ntohs(hdr->length);
    if (pkt_len == 0 || pkt_len > MAX_PKT_SIZE) return -1;

    uint8_t *payload = buf + sizeof(spi_ip_hdr_t);
    uint32_t recv_crc;
    memcpy(&recv_crc, payload + pkt_len, sizeof(recv_crc));

    if (ntohl(recv_crc) != crc32(0, payload, pkt_len)) return -1;

    memcpy(data, payload, pkt_len);
    return pkt_len;
}

void spi_receive(int spi_fd) {
    uint8_t tx_buf[MAX_PKT_SIZE + sizeof(spi_ip_hdr_t) + 4] = {0};
    uint8_t rx_buf[MAX_PKT_SIZE + sizeof(spi_ip_hdr_t) + 4];

    ssize_t n = spi_transfer(spi_fd, tx_buf, rx_buf, sizeof(rx_buf));
    if (n < (ssize_t)sizeof(spi_ip_hdr_t)) {
        return;
    }

    //    spi_ip_hdr_t *hdr = (spi_ip_hdr_t *)rx_buf;
    //    uint32_t magic = ntohl(hdr->magic);
    //    if (magic != SPI_MAGIC) {
    //        return;
    //    }

    //    uint16_t pkt_len = ntohs(hdr->length);
    //    if (pkt_len == 0 || pkt_len > MAX_PKT_SIZE) {
    //        return;
    //    }

    //    uint8_t *payload = rx_buf + sizeof(spi_ip_hdr_t);
    //    uint32_t recv_crc;
    //    memcpy(&recv_crc, payload + pkt_len, sizeof(recv_crc));
    //    if (ntohl(recv_crc) != crc32(0, payload, pkt_len)) {
    //        return;
    //    }

    size_t zero_count = 0;
    for (ssize_t i = 0; i < n; i++) {
        if (rx_buf[i] == 0) zero_count++;
    }
    if (zero_count * 10 > (size_t)n * 9) {
        return;
    }

    printf("Received valid SPI packet (%d bytes):\n", n);
    for (int i = 0; i < 32; i++) {
        if (i % 16 == 0) printf("\n%04x: ", i);
        printf("%02x ", rx_buf[i]);
    }
    printf("\n");
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
        spi_receive(spi_fd);

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
    uint8_t payload[] = {
        0x45,0x00,0x00,0x54,0x33,0xe1,0x40,0x00,0x3f,0x01,0x3b,0xa7,
        0xc0,0xa8,0x01,0x77,0x0a,0x00,0x00,0x02,0x08,0x00,0xe6,0xce,
        0x12,0x0d,0x00,0x01,0xc9,0xae,0x47,0x69,0x00,0x00,0x00,0x00,
        0x2d,0x38,0x02,0x00,0x00,0x00,0x00,0x00,0x10,0x11,0x12,0x13,
        0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,
        0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37
    };

    printf("Sending test ICMP packet to TUN...\n");
    write_tun_packet(tun_fd, payload, sizeof(payload));
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
    test_icmp(tun_fd);
    spi_send_incremental(spi_fd);
    // [DEBUG] End

    forward_loop(tun_fd, spi_fd);

    close(spi_fd);
    close(tun_fd);
    return 0;
}
