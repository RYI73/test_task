#pragma once

#include "types.h"

/***********************************************************************************************/
/**
 * @struct spi_ip_hdr_t
 * @brief Header used to frame IPv4 packets over SPI
 */
typedef struct __attribute__((packed)) {
    u32 magic;     /**< SPI_MAGIC constant */
    u8 version;    /**< Protocol version (0x01) */
    u8 flags;      /**< Reserved flags */
    u16 length;    /**< Length of IPv4 packet in bytes */
} spi_ip_hdr_t;

/***********************************************************************************************/
/**
 * @brief Initialize SPI device using spidev interface.
 *
 * Opens SPI device file and configures basic SPI parameters:
 * mode, bits per word and clock speed.
 *
 * @param[in] device Path to spidev device (e.g. "/dev/spidev0.0")
 *
 * @return
 *  - File descriptor (>= 0) on success
 *  - -1 on error (open or ioctl failure)
 */
int spi_init(const char *device, int *spi_fd);

/**
 * @brief Receive an SPI packet including header and CRC check
 *
 * @param spi_fd SPI file descriptor
 * @param gpio_fd GPIO file descriptor
 * @param out_buf Buffer to store received payload
 * @param length Pointer to store received length
 * @return 0 on success, -1 on error
 */
int spi_receive(int spi_fd, int gpio_fd, u8 *out_buf, u16 *length);

/**
 * @brief Send an SPI packet including header and CRC
 *
 * @param spi_fd SPI file descriptor
 * @param gpio_fd GPIO file descriptor
 * @param data Packet payload
 * @param len Length of payload
 * @return 0 on success, -1 on error
 */
int spi_send_packet(int spi_fd, int gpio_fd, u8 *data, u16 len);

/**
 * @brief Receive a SPI transfer with timeout waiting for READY GPIO
 *
 * @param spi_fd SPI file descriptor
 * @param gpio_fd GPIO file descriptor
 * @param out Output buffer
 * @return 0 on success, -1 on error
 */
int spi_recv_transfer(int spi_fd, int gpio_fd, u8 *out);

/**
 * @brief Send a SPI transfer with timeout waiting for READY GPIO
 *
 * @param spi_fd SPI file descriptor
 * @param gpio_fd GPIO file descriptor
 * @param data Buffer to send
 * @param len Length of data
 * @return 0 on success, -1 on error
 */
int spi_send_transfer(int spi_fd, int gpio_fd, const u8 *data, size_t len);

/***********************************************************************************************/
