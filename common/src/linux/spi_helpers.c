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
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>

#include "helpers.h"
#include "logs.h"
#include "types.h"
#include "error_code.h"
#include "spi_helpers.h"
#include "defaults.h"

/** SPI buffer definitions */
static u8 spi_recv_tx_buff[PKT_LEN + 1];
static u8 spi_recv_rx_buff[PKT_LEN + 1];
static u8 spi_send_tx_buff[PKT_LEN + 1];
static u8 spi_send_rx_buff[PKT_LEN + 1];
static u8 rx_buff[PKT_LEN + 1];

/***********************************************************************************************/
/* Internal functions                                                                          */
/***********************************************************************************************/
/**
 * @brief Perform a single SPI receive transaction using ioctl interface.
 *
 * Waits for the SPI slave device to be ready via GPIO before performing
 * the SPI transfer. Copies the received data into the provided output buffer.
 *
 * @param[in]  spi_fd   File descriptor of the SPI device
 * @param[in]  gpio_fd  File descriptor of the GPIO used to check device readiness
 * @param[out] out      Buffer to store received SPI data (must be at least PKT_LEN bytes)
 *
 * @return RESULT_OK if data was successfully received
 * @return RESULT_ARGUMENT_ERROR if the output buffer is NULL
 * @return RESULT_FILE_READ_ERROR if reading the GPIO fails
 * @return RESULT_TIMEOUT if the SPI device does not become ready within 500 ms
 * @return RESULT_INTERNAL_ERROR if ioctl SPI transfer fails
 */
static int spi_recv_transfer(int spi_fd, int gpio_fd, u8 *out)
{
    int result = RESULT_OK;
    u32 start = 0;
    char gpio_value = '0';

    do {
        if (!out) {
            log_msg(LOG_ERR, "NULL output buffer");
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

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
            if (read(gpio_fd, &gpio_value, 1) < 0) {
                log_msg(LOG_ERR, "GPIO read failed: %s", strerror(errno));
                result = RESULT_FILE_READ_ERROR;
                break;
            }
            if (gpio_value == '1') {
                break;
            }
            if (now_ms() - start >= POLL_TIMEOUT_MS) {
                result = RESULT_TIMEOUT;
                break;
            }
            usleep(100);
        }

        if (isOk(result)) {
            if (ioctl(spi_fd, SPI_IOC_MESSAGE(1), &tr) < 1) {
                log_msg(LOG_ERR, "SPI ioctl receive failed: %s", strerror(errno));
                result = RESULT_INTERNAL_ERROR;
                break;
            }

            memcpy(out, spi_recv_rx_buff, PKT_LEN);
        }

    } while(0);

    return result;
}
/***********************************************************************************************/
/**
 * @brief Perform a single SPI send transaction using ioctl interface.
 *
 * Waits for the SPI slave device to be ready via GPIO before performing
 * the SPI transfer. Copies data from the provided buffer to the SPI device.
 *
 * @param[in]  spi_fd   File descriptor of the SPI device
 * @param[in]  gpio_fd  File descriptor of the GPIO used to check device readiness
 * @param[in]  data     Buffer containing data to send
 * @param[in]  len      Length of the data to send (must be <= PKT_LEN)
 *
 * @return RESULT_OK if data was successfully sent
 * @return RESULT_ARGUMENT_ERROR if data is NULL or length is 0
 * @return RESULT_FILE_READ_ERROR if reading the GPIO fails
 * @return RESULT_TIMEOUT if the SPI device does not become ready within 500 ms
 * @return RESULT_INTERNAL_ERROR if ioctl SPI transfer fails
 */
static int spi_send_transfer(int spi_fd, int gpio_fd, const u8 *data, size_t len)
{
    int result = RESULT_OK;
    u32 start = 0;
    char gpio_value = '0';

    do {
        if (!data || len == 0) {
            log_msg(LOG_ERR, "Invalid data pointer or length 0");
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

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
            if (read(gpio_fd, &gpio_value, 1) < 0) {
                log_msg(LOG_ERR, "GPIO read failed: %s", strerror(errno));
                result = RESULT_FILE_READ_ERROR;
                break;
            }
            if (gpio_value == '1') {
                break;
            }
            if (now_ms() - start >= POLL_TIMEOUT_MS) {
                result = RESULT_TIMEOUT;
                break;
            }
            usleep(100);
        }

        if (isOk(result)) {
            if (ioctl(spi_fd, SPI_IOC_MESSAGE(1), &tr) < 1) {
                log_msg(LOG_ERR, "SPI ioctl send failed: %s", strerror(errno));
                result = RESULT_INTERNAL_ERROR;
                break;
            }
        }

    } while(0);

    return result;
}
/***********************************************************************************************/
/* External functions                                                                          */
/***********************************************************************************************/
int spi_init(const char *device, int *spi_fd)
{
    int result = RESULT_NOT_INITED;
    int fd = -1;

    do {
        if (!device || !spi_fd) {
            log_msg(LOG_ERR, "Invalid SPI init arguments");
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        fd = open(device, O_RDWR);
        if (fd < 0) {
            log_msg(LOG_ERR, "Unable to open SPI device %s: '%s'", device, strerror(errno));
            result = RESULT_OPEN_DEVICE_ERROR;
            break;
        }

        u8 mode = SPI_MODE;
        u8 bits = SPI_BITS;
        u32 speed = SPI_SPEED;

        if (ioctl(fd, SPI_IOC_WR_MODE, &mode) < 0 ||
            ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits) < 0 ||
            ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed) < 0) {
            log_msg(LOG_ERR, "SPI ioctl configuration failed: %s", strerror(errno));
            result = RESULT_FILE_IOCTL_ERROR;
            fd_close(fd);
            fd = -1;
            break;
        }

        *spi_fd = fd;
        result = RESULT_OK;

    } while(0);

    return result;
}
/***********************************************************************************************/
int spi_receive(int spi_fd, int gpio_fd, u8 *out_buf, u16 *length)
{
    int result = RESULT_NOT_INITED;

    do {
        memset(rx_buff, 0, sizeof(rx_buff));
        result = spi_recv_transfer(spi_fd, gpio_fd, rx_buff);
        if (!isOk(result)) {
            break;
        }

        spi_ip_hdr_t *hdr = (spi_ip_hdr_t *)rx_buff;
        if (hdr->magic != SPI_MAGIC) {
            result = RESULT_BAD_PREFIX_ERROR;
            break;
        }

        if (hdr->length == 0 || hdr->length > PKT_LEN) {
            log_msg(LOG_ERR, "Bad SPI packet length: %u", hdr->length);
            result = RESULT_FULL_BUFFER_ERROR;
            break;
        }

        u8 *payload = rx_buff + sizeof(spi_ip_hdr_t);
        u32 recv_crc;
        memcpy(&recv_crc, payload + hdr->length, sizeof(recv_crc));

        if (recv_crc != crc32(0, payload, hdr->length)) {
            log_msg(LOG_ERR, "SPI CRC check failed");
            result = RESULT_BAD_CRC_ERROR;
            break;
        }

        memcpy(out_buf, payload, hdr->length);
        *length = hdr->length;
        result = RESULT_OK;

    } while(0);

    return result;
}
/***********************************************************************************************/
int spi_send_packet(int spi_fd, int gpio_fd, u8 *data, u16 len)
{
    int result = RESULT_OK;

    do {
        if (!data || len == 0 || len > PKT_LEN) {
            log_msg(LOG_ERR, "Invalid SPI packet length %u", len);
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        spi_ip_hdr_t hdr = {
            .magic = SPI_MAGIC,
            .version = 0x01,
            .flags = 0,
            .length = len
        };

        u32 crc = crc32(0, data, len);
        u8 buf[PKT_LEN] = {0};
        size_t offset = 0;
        memcpy(buf + offset, &hdr, sizeof(hdr)); offset += sizeof(hdr);
        memcpy(buf + offset, data, len); offset += len;
        memcpy(buf + offset, &crc, sizeof(crc));

        result = spi_send_transfer(spi_fd, gpio_fd, buf, sizeof(buf));

    } while(0);

    return result;
}
/***********************************************************************************************/
