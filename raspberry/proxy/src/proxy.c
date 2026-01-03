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
#include <sys/types.h>
#include <syslog.h>
#include <signal.h>

#include "defaults.h"
#include "logs.h"
#include "helpers.h"
#include "socket_helpers.h"
#include "spi_helpers.h"
#include "gpio_helpers.h"

/***********************************************************************************************/
/**
 * @brief Main forwarding loop between TUN interface and SPI transport.
 *
 * Continuously processes packets in both directions:
 *  - Reads packets from TUN interface and forwards IPv4 packets over SPI
 *  - Receives packets from SPI and writes them back to TUN interface
 *
 * IPv6 packets received from TUN are ignored.
 *
 * @param[in] tun_fd   File descriptor of the TUN device
 * @param[in] spi_fd   File descriptor of the SPI device
 * @param[in] gpio_fd  File descriptor used for SPI/GPIO synchronization
 *
 * @note
 *  - This function runs an infinite loop and never returns.
 *  - A small delay is inserted to reduce CPU usage.
 *  - Only IPv4 packets (IP version 4) are forwarded to SPI.
 */
void forward_loop(int tun_fd, int spi_fd, int gpio_fd, bool *is_running)
{
    uint8_t tun_buf[MAX_PKT_SIZE];
    static uint8_t spi_rx[PKT_LEN];
    uint16_t length = 0;
    uint8_t ip_version = 0;

    while(*is_running) {
        ssize_t n = read_tun_packet(tun_fd, tun_buf);
        if (n > 0) {
            ip_version = tun_buf[0] >> 4;
            if (ip_version == 4) {
                // Forward to SPI
                spi_send_packet(spi_fd, gpio_fd, tun_buf, n);
            } else if (ip_version == 6) {
                // Ignore IPv6 packets
                log_msg(LOG_DEBUG, "Received IPv6 packet, ignoring\n");
            } else {
                log_msg(LOG_WARNING, "Unknown IP version %d, ignoring\n", ip_version);
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
int main()
{
    bool is_running = true;
    int gpio_fd = -1;
    int spi_fd = -1;
    int tun_fd = -1;
    int result = RESULT_OK;

    // -- SIGNAL handler -----------------------------------------------------
    void sighandler(int signum)
    {
        UNUSED(signum);
        is_running = false;
    }
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    do {
        /* Initialize syslog */
        openlog("poll_proxy", LOG_PID | LOG_CONS, LOG_DAEMON);

        result = tup_init(INTERFACE_NAME_TUN0, SERVER_ADDR, &tun_fd);
        if (!isOk(result)) {
            break;
        }

        result = spi_init(SPI_DEVICE, &spi_fd);
        if (!isOk(result)) {
            break;
        }

        // Disable reverse path filter to prevent kernel from dropping packets
        system("sysctl -w net.ipv4.conf.all.rp_filter=0");
        system("sysctl -w net.ipv4.conf.tun0.rp_filter=0");

        // Policy routing: all packets with src=10.0.0.2 go via tun0
        system("ip rule add from 10.0.0.2/32 table 100");
        system("ip route add default dev tun0 table 100");
        system("ip route flush cache");

        // Disable IPv6 on tun0
        system("sysctl -w net.ipv6.conf.tun0.disable_ipv6=1");

        result = gpio_init(GPIO_READY_SYSFS, GPIO_HANDSHAKE_SPI, &gpio_fd);
        if (!isOk(result)) {
            break;
        }

        forward_loop(tun_fd, spi_fd, gpio_fd, &is_running);
    } while(0);

    if (gpio_fd > 0) {
        close(gpio_fd);
    }
    if (spi_fd > 0) {
        close(spi_fd);
    }
    if (tun_fd > 0) {
        close(tun_fd);
    }

    log_msg(LOG_INFO, "Proxy stopped. Exit code %u", result);

    closelog();

    if (isOk(result)) {
        return EXIT_SUCCESS;
    }
    else {
        fprintf(stderr, "Failed to execute proxy. Error: %u\n", result);
        return EXIT_FAILURE;
    }
}
/***********************************************************************************************/
