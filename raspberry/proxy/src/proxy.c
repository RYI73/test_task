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
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <time.h>
#include <stdbool.h>

#include "defaults.h"
#include "helpers.h"
#include "socket_helpers.h"
#include "spi_helpers.h"
#include "gpio_helpers.h"

/**< File descriptor for GPIO handshake */
int gpio_fd = -1;

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

                // Forward to SPI
                spi_send_packet(spi_fd, gpio_fd, tun_buf, n);
            } else if (ip_version == 6) {
                // Ignore IPv6 packets
                printf("Received IPv6 packet, ignoring\n");
            } else {
                printf("Unknown IP version %d, ignoring\n", ip_version);
            }
        }

        length = 0;
        if (!spi_receive(spi_fd, gpio_fd, spi_rx, &length)) {
            write_tun_packet(tun_fd, spi_rx, length);
        }

        usleep(1000);
    }
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

    forward_loop(tun_fd, spi_fd);

    close(gpio_fd);
    close(spi_fd);
    close(tun_fd);
    return 0;
}
/***********************************************************************************************/
