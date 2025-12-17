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

#define SPI_DEVICE "/dev/spidev0.0"
#define SPI_MODE 0
#define SPI_BITS 8
#define SPI_SPEED 1000000      // SPI speed in Hz
#define MAX_PKT_SIZE 1500      // Maximum packet size for SPI transfer
#define SPI_MAGIC              0x49504657

typedef struct __attribute__((packed)) {
    uint32_t magic;     /**< Magic constant SPI_MAGIC ('IPFW') */
    uint8_t version;    /**< Protocol version (0x01) */
    uint8_t flags;      /**< Reserved */
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
 * @brief Initialize SPI device
 *
 * @param device SPI device path (e.g., "/dev/spidev0.0")
 * @return File descriptor of SPI device, or -1 on error
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
 * @param spi_fd File descriptor of SPI device
 * @param tx_buf Pointer to transmit buffer
 * @param rx_buf Pointer to receive buffer
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
 * @param tun_fd File descriptor of TUN interface
 * @param buf Buffer to store packet
 * @return Number of bytes read, or -1 on error
 */
ssize_t read_tun_packet(int tun_fd, uint8_t *buf) {
    ssize_t n = read(tun_fd, buf, MAX_PKT_SIZE);
    if (n < 0 && errno != EAGAIN) perror("read tun");
    return n;
}

/**
 * @brief Write a packet to TUN interface
 *
 * @param tun_fd File descriptor of TUN interface
 * @param buf Pointer to packet data
 * @param len Length of the packet
 * @return Number of bytes written, or -1 on error
 */
ssize_t write_tun_packet(int tun_fd, uint8_t *buf, size_t len) {
    ssize_t n = write(tun_fd, buf, len);
    if (n < 0) perror("write tun");
    return n;
}

/**
 * @brief Send a packet to ESP32 via SPI (framed with magic + version + CRC32)
 *
 * @param spi_fd SPI device file descriptor
 * @param data Pointer to packet data
 * @param len Length of the packet
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
 * @brief Receive a packet from ESP32 via SPI (framed with magic + version + CRC32)
 *
 * @param spi_fd SPI device file descriptor
 * @param data Buffer to store received packet
 * @return Number of bytes received, or -1 on error
 */
int spi_receive_packet(int spi_fd, uint8_t *data) {
    uint8_t buf[sizeof(spi_ip_hdr_t) + MAX_PKT_SIZE + sizeof(uint32_t)];
    if (spi_transfer(spi_fd, NULL, buf, sizeof(buf)) < 0) return -1;

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

/**
 * @brief Main loop for forwarding between TUN and SPI
 *
 * @param tun_fd File descriptor of TUN interface
 * @param spi_fd File descriptor of SPI device
 */
void forward_loop(int tun_fd, int spi_fd) {
    uint8_t tun_buf[MAX_PKT_SIZE];
    uint8_t spi_buf[MAX_PKT_SIZE];

    while (1) {
        ssize_t n = read_tun_packet(tun_fd, tun_buf);
        if (n > 0) spi_send_packet(spi_fd, tun_buf, n);

        int rcv_len = spi_receive_packet(spi_fd, spi_buf);
        if (rcv_len > 0) write_tun_packet(tun_fd, spi_buf, rcv_len);

        usleep(1000);
    }
}

/**
 * @brief Main application entry point
 *
 * Initializes TUN and SPI devices and starts forwarding loop
 *
 * @return Exit code (0 on success, 1 on failure)
 */
int main() {
    int tun_fd = tun_alloc("tun0");
    if (tun_fd < 0) return 1;

    int spi_fd = spi_init(SPI_DEVICE);
    if (spi_fd < 0) return 1;

    forward_loop(tun_fd, spi_fd);

    close(spi_fd);
    close(tun_fd);
    return 0;
}
