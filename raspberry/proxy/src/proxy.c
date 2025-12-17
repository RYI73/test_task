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
#include <sys/select.h>
#include <linux/spi/spidev.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

// Required for TUN/TAP interface
#include <linux/if_tun.h>
#include <net/if.h>        // <- for struct ifreq and IFNAMSIZ
#include <linux/spi/spidev.h>

#define SPI_DEVICE "/dev/spidev0.0"
#define SPI_MODE 0
#define SPI_BITS 8
#define SPI_SPEED 1000000       /**< SPI speed in Hz */
#define MAX_PKT_SIZE 1600       /**< Maximum packet size for SPI transfer */

/**
 * @brief Allocate a TUN interface
 *
 * @param devname Name of the TUN interface to create
 * @return File descriptor of the TUN interface, or -1 on error
 */
int tun_alloc(char *devname) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("tun open");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (devname)
        strncpy(ifr.ifr_name, devname, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
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
 * Opens the SPI device and configures mode, bits per word, and speed.
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
 * @brief Perform a full-duplex SPI transfer
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
 * @param buf Buffer to store the packet
 * @return Number of bytes read, or -1 on error
 */
ssize_t read_tun_packet(int tun_fd, uint8_t *buf) {
    ssize_t n = read(tun_fd, buf, MAX_PKT_SIZE);
    if (n < 0 && errno != EAGAIN) {
        perror("read tun");
    }
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
    if (n < 0) {
        perror("write tun");
    }
    return n;
}

/**
 * @brief Send a packet to ESP32 via SPI with 2-byte length header
 *
 * @param spi_fd SPI device file descriptor
 * @param data Pointer to packet data
 * @param len Length of the packet
 * @return 0 on success, -1 on error
 */
int spi_send_packet(int spi_fd, uint8_t *data, uint16_t len) {
    if (len > MAX_PKT_SIZE) return -1;

    uint8_t buf[MAX_PKT_SIZE + 2];
    buf[0] = (len >> 8) & 0xFF;
    buf[1] = len & 0xFF;
    memcpy(&buf[2], data, len);

    if (spi_transfer(spi_fd, buf, NULL, len + 2) < 0)
        return -1;
    return 0;
}

/**
 * @brief Receive a packet from ESP32 via SPI with 2-byte length header
 *
 * @param spi_fd SPI device file descriptor
 * @param data Buffer to store received packet
 * @return Number of bytes received, or 0 if no packet, or -1 on error
 */
int spi_receive_packet(int spi_fd, uint8_t *data) {
    uint8_t header[2] = {0, 0};
    if (spi_transfer(spi_fd, header, header, 2) < 0) return -1;

    uint16_t pkt_len = (header[0] << 8) | header[1];
    if (pkt_len == 0 || pkt_len > MAX_PKT_SIZE) return 0;

    uint8_t dummy[MAX_PKT_SIZE] = {0};
    if (spi_transfer(spi_fd, dummy, data, pkt_len) < 0) return -1;

    return pkt_len;
}

/**
 * @brief Main loop for TUN <-> SPI forwarding
 *
 * Reads packets from TUN and sends to SPI, and reads packets from SPI
 * and writes them to TUN.
 *
 * @param tun_fd TUN interface file descriptor
 * @param spi_fd SPI device file descriptor
 */
void forward_loop(int tun_fd, int spi_fd) {
    uint8_t tun_buf[MAX_PKT_SIZE];
    uint8_t spi_buf[MAX_PKT_SIZE];

    while (1) {
        // --- TUN -> SPI ---
        ssize_t n = read_tun_packet(tun_fd, tun_buf);
        if (n > 0) {
            spi_send_packet(spi_fd, tun_buf, n);
        }

        // --- SPI -> TUN ---
        int rcv_len = spi_receive_packet(spi_fd, spi_buf);
        if (rcv_len > 0) {
            write_tun_packet(tun_fd, spi_buf, rcv_len);
        }

        usleep(1000); // small sleep to avoid busy-loop
    }
}

/**
 * @brief Main application entry point
 *
 * Initializes TUN and SPI devices, then starts forwarding loop.
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
