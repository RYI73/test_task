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
 * @brief Initialize SPI as slave with DMA buffers and semaphore
 *
 * @param[in]  device  Not used (for compatibility)
 * @param[out] spi_fd  Pointer to SPI file descriptor placeholder
 *
 * @return RESULT_OK on success, or error code
 */
int spi_init(const char *device, int *spi_fd);

/**
 * @brief Receive a packet from SPI
 *
 * @param[in]  spi_fd   SPI file descriptor placeholder
 * @param[in]  gpio_fd  GPIO FD not used
 * @param[out] out_buf  Buffer to store received data
 * @param[out] length   Length of received data
 *
 * @return RESULT_OK on success, or error code
 */
int spi_receive(int spi_fd, int gpio_fd, u8 *out_buf, u16 *length);

/**
 * @brief Send a packet over SPI
 *
 * @param[in] spi_fd   SPI file descriptor placeholder
 * @param[in] gpio_fd  GPIO FD not used
 * @param[in] data     Data buffer to send
 * @param[in] len      Length of data to send
 *
 * @return RESULT_OK on success, or error code
 */
int spi_send_packet(int spi_fd, int gpio_fd, u8 *data, u16 len);
/***********************************************************************************************/
