/**
 * @file proxy.c
 * @brief SPI-to-TUN proxy for forwarding IPv4 packets from SPI to Linux TUN interface
 *
 * This program creates a TUN interface, sets its IP address, and forwards
 * IPv4 packets between SPI and the kernel network stack. It uses a GPIO
 * handshake line to synchronize with the SPI device (ESP32).
 *
 * @author Ruslan
 * @date 2025-12-23
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
#include <time.h>
#include <stdbool.h>
#include <dirent.h>

#include "defaults.h"

/** SPI buffer definitions */
static uint8_t spi_recv_tx_buff[PKT_LEN + 1];
static uint8_t spi_recv_rx_buff[PKT_LEN + 1];
static uint8_t spi_send_tx_buff[PKT_LEN + 1];
static uint8_t spi_send_rx_buff[PKT_LEN + 1];
static uint8_t rx_buff[PKT_LEN + 1];

int gpio_fd = -1;  /**< File descriptor for GPIO handshake */

/***********************************************************************************************/
/**
 * @struct spi_ip_hdr_t
 * @brief Header used to frame IPv4 packets over SPI
 */
typedef struct __attribute__((packed)) {
    uint32_t magic;     /**< SPI_MAGIC constant */
    uint8_t version;    /**< Protocol version (0x01) */
    uint8_t flags;      /**< Reserved flags */
    uint16_t length;    /**< Length of IPv4 packet in bytes */
} spi_ip_hdr_t;
/***********************************************************************************************/
/**
 * @brief Compute CRC32 for data integrity check
 *
 * @param crc Initial CRC value
 * @param buf Pointer to data buffer
 * @param len Length of buffer in bytes
 * @return Computed CRC32 value
 */
uint32_t crc32(uint32_t crc, const uint8_t *buf, size_t len) {
    uint32_t c = crc ^ 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        c ^= buf[i];
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
    }
    return c ^ 0xFFFFFFFF;
}
/***********************************************************************************************/
/**
 * @brief Get current monotonic time in nanoseconds
 * @return Time in nanoseconds
 */
static inline uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
/***********************************************************************************************/
/**
 * @brief Get current monotonic time in milliseconds
 * @return Time in milliseconds
 */
static inline uint32_t now_ms(void)
{
    return (uint32_t)(now_ns() / 1000000);
}
/***********************************************************************************************/
/**
 * @brief Allocate a TUN interface
 *
 * @param devname Desired interface name (e.g., "tun0")
 * @return File descriptor for TUN interface, or -1 on failure
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
/***********************************************************************************************/
/**
 * @brief Set TUN interface UP
 *
 * @param ifname Interface name
 * @return 0 on success, -1 on failure
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
/***********************************************************************************************/
/**
 * @brief Check if TUN interface has specific IP address
 *
 * @param ifname Interface name
 * @param ip_str IP address string (e.g., "10.0.0.2")
 * @return 1 if IP is configured, 0 otherwise
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
/***********************************************************************************************/
/**
 * @brief Add IP address to TUN interface
 *
 * @param ifname Interface name
 * @param ip_str IP address string
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
/***********************************************************************************************/
/**
 * @brief Initialize SPI device
 *
 * @param device SPI device path (e.g., "/dev/spidev0.0")
 * @return SPI file descriptor, or -1 on error
 */
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
/***********************************************************************************************/
/**
 * @brief Send a SPI transfer with timeout waiting for READY GPIO
 *
 * @param spi_fd SPI file descriptor
 * @param data Buffer to send
 * @param len Length of data
 * @return 0 on success, -1 on error
 */
int spi_send_transfer(int spi_fd, const uint8_t *data, size_t len)
{
    uint32_t start = 0;
    bool is_timeout = false;
    char gpio_value;

    if (!data || len == 0)
        return -1;

    /* DEBUG dump */
//    printf("\nSPI transfer %zu bytes:", len);
//    for (size_t i = 0; i < len; i++) {
//        if (i % 16 == 0) printf("\n%04zx: ", i);
//        printf("%02x ", data[i]);
//    }
//    printf("\n");

    memcpy(spi_send_tx_buff, data, len);

    struct spi_ioc_transfer tr = {
        .tx_buf        = (unsigned long)spi_send_tx_buff,
        .rx_buf        = (unsigned long)spi_send_rx_buff,
        .len           = len,
        .speed_hz      = SPI_SPEED,
        .bits_per_word = 8,
        .cs_change     = 0,
    };

    start = now_ms();
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
/***********************************************************************************************/
/**
 * @brief Receive a SPI transfer with timeout waiting for READY GPIO
 *
 * @param spi_fd SPI file descriptor
 * @param out Output buffer
 * @return 0 on success, -1 on error
 */
int spi_recv_transfer(int spi_fd, uint8_t *out)
{
    uint32_t start = 0;
    bool is_timeout = false;
    char gpio_value;
    int res = 0;

    if (!out) {
        res = -1;
    }
    else {
        memset(spi_recv_tx_buff, 0, PKT_LEN);
        struct spi_ioc_transfer tr = {
            .tx_buf        = (unsigned long)spi_recv_tx_buff,
            .rx_buf        = (unsigned long)spi_recv_rx_buff,
            .len           = PKT_LEN,
            .speed_hz      = SPI_SPEED,
            .bits_per_word = 8,
            .cs_change     = 0,
        };

        start = now_ms();
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

        if (is_timeout) {
            res = -1;
        }
        else {
            int ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), &tr);
            if (ret < 1) {
                perror("spi recv");
                res = -1;
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
//            start = now_ms();
//            while (1) {
//                lseek(gpio_fd, 0, SEEK_SET);
//                read(gpio_fd, &gpio_value, 1);
//                if (gpio_value == '0') break;   // ESP32 READY
//                if (now_ms() - start >= 500) {
//                    is_timeout = true;
//                    break;
//                }
//                usleep(100);
//            }
        }
    }

    return res;
}
/***********************************************************************************************/
/**
 * @brief Read a packet from TUN interface
 *
 * @param tun_fd File descriptor of TUN
 * @param buf Buffer to store packet
 * @return Number of bytes read, or -1 on error
 */
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
/***********************************************************************************************/
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
/***********************************************************************************************/
/**
 * @brief Send an SPI packet including header and CRC
 *
 * @param spi_fd SPI file descriptor
 * @param data Packet payload
 * @param len Length of payload
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

    uint8_t buf[PKT_LEN] = {0};
    size_t offset = 0;
    memcpy(buf + offset, &hdr, sizeof(hdr)); offset += sizeof(hdr);
    memcpy(buf + offset, data, len); offset += len;
    memcpy(buf + offset, &crc, sizeof(crc));

    // [DEBUG] Dump packet ONLY FOR DEBUG!!!
//    printf("SPI Send %zd bytes\n", offset + sizeof(crc));
//    for (ssize_t i = 0; i < offset + sizeof(crc); i++) {
//        if (i % 16 == 0) printf("\n%04zx: ", i);
//        printf("%02x ", buf[i]);
//    }
//    printf("\n");
    // [DEBUG] End

    if (spi_send_transfer(spi_fd, buf, sizeof(buf)) < 0) return -1;
    return 0;
}
/***********************************************************************************************/
/**
 * @brief Receive an SPI packet including header and CRC check
 *
 * @param spi_fd SPI file descriptor
 * @param out_buf Buffer to store received payload
 * @param length Pointer to store received length
 * @return 0 on success, -1 on error
 */
int spi_receive(int spi_fd, uint8_t *out_buf, uint16_t *length)
{
    memset(rx_buff, 0 ,sizeof(rx_buff));
    if (!spi_recv_transfer(spi_fd, rx_buff)) {

        // [DEBUG] Dump packet ONLY FOR DEBUG!!!
//        printf("MASTER received: ");
//        for (int i = 0; i < sizeof(rx_buff); i++) {
//            if (i % 16 == 0) printf("\n%04zx: ", i);
//            printf("%02x ", rx_buff[i]);
//        }
//        printf("\n");
        // [DEBUG] End

        spi_ip_hdr_t *hdr = (spi_ip_hdr_t *)rx_buff;
        uint32_t magic = hdr->magic;
        if (magic != SPI_MAGIC) {
//            printf("Bad magic %08X != %08X\n", magic, SPI_MAGIC);
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

//            // [DEBUG] Dump packet ONLY FOR DEBUG!!!
//            printf("MASTER received: ");
//            for (size_t i = 0; i < sizeof(rx_buff); i++) {
//                if (i % 16 == 0) printf("\n%04zx: ", i);
//                printf("%02x ", rx_buff[i]);
//            }
//            printf("\n");
//            // [DEBUG] End

//            // [DEBUG] Dump packet ONLY FOR DEBUG!!!
//            printf("Packet: ");
//            for (size_t i = 0; i < pkt_len; i++) {
//                if (i % 16 == 0) printf("\n%04zx: ", i);
//                printf("%02x ", payload[i]);
//            }
//            printf("\n");
//            // [DEBUG] End

            return -1;
        }

        memcpy(out_buf, payload, hdr->length);
        *length = hdr->length;

        return 0;
    }

    return -1;
}
/***********************************************************************************************/
/**
 * @brief Forward packets between TUN and SPI interface (IPv4 only)
 *
 * @param tun_fd File descriptor of TUN interface
 * @param spi_fd File descriptor of SPI device
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
//                printf("Received %zd bytes from TUN (IPv4)\n", n);
//                for (ssize_t i = 0; i < n; i++) {
//                    if (i % 16 == 0) printf("\n%04zx: ", i);
//                    printf("%02x ", tun_buf[i]);
//                }
//                printf("\n");
//                if (n >= 21 && tun_buf[20] == 0) {
//                    printf("This is ICMP Echo Reply\n");
//                }
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

        length = 0;
        if (!spi_receive(spi_fd, spi_rx, &length)) {

            // [DEBUG] Dump packet ONLY FOR DEBUG!!!
//            printf("\nReceived valid SPI packet (%d bytes):", length);
//            for (int i = 0; i < length; i++) {
//                if (i % 16 == 0) printf("\n%04x: ", i);
//                printf("%02x ", spi_rx[i]);
//            }
//            printf("\n");
            // [DEBUG] End

            write_tun_packet(tun_fd, spi_rx, length);
        }

        usleep(1000);
    }
}
/***********************************************************************************************/
/**
 * @brief Read GPIO chip base number
 *
 * @return Base GPIO number, or -1 on error
 */
int read_gpiochip_base(void)
{
    DIR *dir = opendir(GPIO_CLASS);
    if (!dir) {
        perror("opendir");
        return -1;
    }

    struct dirent *ent;
    char path[256];
    char buf[32];

    while ((ent = readdir(dir)) != NULL) {
        if (strncmp(ent->d_name, "gpiochip", 8) == 0) {
            snprintf(path, sizeof(path),
                     GPIO_BASE, ent->d_name);

            int fd = open(path, O_RDONLY);
            if (fd < 0)
                continue;

            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);

            if (n > 0) {
                buf[n] = '\0';
                closedir(dir);
                return atoi(buf);
            }
        }
    }

    closedir(dir);
    return -1;
}
/***********************************************************************************************/
/**
 * @brief Export a GPIO via sysfs
 *
 * @param gpio Global Linux GPIO number
 * @return 0 on success, -1 on error
 */
int export_gpio(int gpio)
{
    int fd = open(GPIO_EXPORT, O_WRONLY);
    if (fd < 0) {
        perror("open export");
        return -1;
    }

    char buf[16];
    int len = snprintf(buf, sizeof(buf), "%d", gpio);

    if (write(fd, buf, len) < 0) {
        if (errno != EBUSY)   // already exported — не помилка
            perror("write export");
    }

    close(fd);
    return 0;
}
/***********************************************************************************************/
/**
 * @brief Main entry point
 */
int main() {
    const char *tun_name = INTERFACE_NAME_TUN0;
    const char *tun_ip   = SERVER_ADDR;

    int tun_fd = tun_alloc((char *)tun_name);
    if (tun_fd < 0) return 1;

    if (tun_set_up(tun_name) < 0) return 1;

    if (!tun_has_ip(tun_name, tun_ip)) {
        if (tun_add_ip(tun_name, tun_ip) < 0) return 1;
    }

    int spi_fd = spi_init(SPI_DEVICE);
    if (spi_fd < 0) return 1;

    // Disable reverse path filter to prevent kernel from dropping packets
    system("sysctl -w net.ipv4.conf.all.rp_filter=0");
    system("sysctl -w net.ipv4.conf.tun0.rp_filter=0");

    // Policy routing: all packets with src=10.0.0.2 go via tun0
    system("ip rule add from 10.0.0.2/32 table 100");
    system("ip route add default dev tun0 table 100");
    system("ip route flush cache");

    // Disable IPv6 on tun0
    system("sysctl -w net.ipv6.conf.tun0.disable_ipv6=1");

    // Export GPIO
    int base = read_gpiochip_base();
    if (base < 0) {
        fprintf(stderr, "Failed to read gpiochip base\n");
        return 1;
    }

    int gpio = base + GPIO_HANDSHAKE_SPI;

    printf("gpiochip base = %d\n", base);
    printf("Exporting GPIO %d (offset %d)\n", gpio, GPIO_HANDSHAKE_SPI);

    export_gpio(gpio);

    gpio_fd = open(GPIO_READY_SYSFS, O_RDONLY);

//    uint8_t message[] = CLIENT_MESSAGE;
//    spi_send_packet(spi_fd, message, sizeof(message));
//    usleep(100000);
//    spi_send_packet(spi_fd, message, sizeof(message));
//    usleep(100000);

    forward_loop(tun_fd, spi_fd);

    close(gpio_fd);
    close(spi_fd);
    close(tun_fd);
    return 0;
}
/***********************************************************************************************/
