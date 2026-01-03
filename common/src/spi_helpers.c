/*******************************************************************************
 *   @file   src/spi_helpers.c
 *   @brief  Implementation of SPI helper functions.
 *   @author Ruslan
********************************************************************************
 * Copyright 2026(c).
*******************************************************************************/

/******************************************************************************/
/***************************** Include Files **********************************/
/******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <poll.h>
#include <net/ethernet.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/spi/spidev.h>

#include "helpers.h"

#include "logs.h"
#include "types.h"
#include "error_code.h"
#include "spi_helpers.h"
#include "defaults.h"

/** SPI buffer definitions */
static uint8_t spi_recv_tx_buff[PKT_LEN + 1];
static uint8_t spi_recv_rx_buff[PKT_LEN + 1];
static uint8_t spi_send_tx_buff[PKT_LEN + 1];
static uint8_t spi_send_rx_buff[PKT_LEN + 1];
static uint8_t rx_buff[PKT_LEN + 1];

/***********************************************************************************************/
/* Internal functions                                                                          */
/***********************************************************************************************/
int spi_recv_transfer(int spi_fd, int gpio_fd, uint8_t *out)
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
            }
        }
    }

    return res;
}
/***********************************************************************************************/
int spi_send_transfer(int spi_fd, int gpio_fd, const uint8_t *data, size_t len)
{
    uint32_t start = 0;
    bool is_timeout = false;
    char gpio_value;

    if (!data || len == 0)
        return -1;


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
int spi_receive(int spi_fd, int gpio_fd, uint8_t *out_buf, uint16_t *length)
{
    memset(rx_buff, 0 ,sizeof(rx_buff));
    if (!spi_recv_transfer(spi_fd, gpio_fd, rx_buff)) {

        spi_ip_hdr_t *hdr = (spi_ip_hdr_t *)rx_buff;
        uint32_t magic = hdr->magic;
        if (magic != SPI_MAGIC) {
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
/***********************************************************************************************/
int spi_send_packet(int spi_fd, int gpio_fd, uint8_t *data, uint16_t len)
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

    if (spi_send_transfer(spi_fd, gpio_fd, buf, sizeof(buf)) < 0) {
        return -1;
    }

    return 0;
}
/***********************************************************************************************/
/* External functions                                                                          */
/***********************************************************************************************/
int spi_init(const char *device, int *spi_fd)
{
    int result = RESULT_OK;
    int fd = -1;

    do {
        fd = open(device, O_RDWR);
        if (fd < 0) {
            log_msg(LOG_ERR, "Unable to open device %s: '%s'", device, strerror(errno));
            result = RESULT_FILE_OPEN_ERROR;
            break;
        }

        uint8_t mode = SPI_MODE;
        uint8_t bits = SPI_BITS;
        uint32_t speed = SPI_SPEED;

        ioctl(fd, SPI_IOC_WR_MODE, &mode);
        ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
        ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);

    } while(0);

    *spi_fd = fd;

    return result;
}
/***********************************************************************************************/
