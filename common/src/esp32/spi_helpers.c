/*******************************************************************************
 * @file   src/esp32/spi_helpers.c
 * @brief  SPI helper functions for ESP32 (slave mode) with DMA buffers
 *         Provides packet framing for IPv4 + CRC checks.
 * @author Ruslan
 * @date   2026-01-04
 ******************************************************************************/

#include <string.h>
#include <assert.h>

#include "esp_err.h"
#include "esp_crc.h"
#include "driver/spi_slave.h"
#include "driver/gpio.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "spi_helpers.h"
#include "defaults.h"
#include "logs.h"
#include "error_code.h"

/***********************************************************************************************/
static char *tx_dma = NULL;
static char *rx_dma = NULL;
static SemaphoreHandle_t spi_done_sem = NULL; /**< Semaphore to signal transaction done */

/***********************************************************************************************/
/* Internal functions                                                                          */
/***********************************************************************************************/
/**
 * @brief Post setup callback called after SPI transaction setup
 * @param trans SPI transaction handle (unused)
 */
static void post_setup_cb(spi_slave_transaction_t *trans)
{
    UNUSED(trans);
    gpio_set_level(GPIO_SPI_READY, 1);
}
/***********************************************************************************************/
/**
 * @brief Post transaction callback called after SPI transaction completed
 * @param trans SPI transaction handle (unused)
 */
static void post_trans_cb(spi_slave_transaction_t *trans)
{
    UNUSED(trans);
    gpio_set_level(GPIO_SPI_READY, 0);

    /* Give semaphore to signal RX ready */
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    xSemaphoreGiveFromISR(spi_done_sem, &xHigherPriorityTaskWoken);
    if (xHigherPriorityTaskWoken) {
        portYIELD_FROM_ISR();
    }
}
/***********************************************************************************************/
/**
 * @brief Perform a single SPI receive transaction using DMA buffer.
 *
 * Waits for the SPI transaction to complete and copies received data into the output buffer.
 *
 * @param[in]  spi_fd   SPI file descriptor placeholder (not used)
 * @param[in]  gpio_fd  GPIO FD placeholder (not used)
 * @param[out] out      Buffer to store received SPI data (must be at least PKT_LEN bytes)
 *
 * @return RESULT_OK on success
 * @return RESULT_ARGUMENT_ERROR if out is NULL or DMA buffer not allocated
 * @return RESULT_IO_ERROR if spi_slave_transmit fails
 * @return RESULT_TIMEOUT if semaphore wait times out
 * @return RESULT_NODATA if no data received
 */
int spi_recv_transfer(int spi_fd, int gpio_fd, uint8_t *out)
{
    UNUSED(spi_fd);
    UNUSED(gpio_fd);
    int result = RESULT_NODATA;

    do {
        if (!out || !rx_dma) {
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        memset(tx_dma, 0, PKT_LEN);
        memset(rx_dma, 0, PKT_LEN);

        spi_slave_transaction_t t = {
            .length = PKT_LEN * 8,
            .tx_buffer = tx_dma,
            .rx_buffer = rx_dma
        };

        /* Wait for transaction done semaphore instead of polling */
        esp_err_t ret = spi_slave_transmit(SPI_HOST, &t, pdMS_TO_TICKS(POLL_TIMEOUT_MS));
        if (ret != ESP_OK) {
            log_msg(LOG_WARNING, "SPI recv transfer failed: %d", ret);
            result = RESULT_IO_ERROR;
            break;
        }

        /* Wait semaphore from ISR signaling transaction done */
        if (xSemaphoreTake(spi_done_sem, pdMS_TO_TICKS(POLL_TIMEOUT_MS)) != pdTRUE) {
            log_msg(LOG_WARNING, "SPI receive timeout");
            result = RESULT_TIMEOUT;
            break;
        }

        memcpy(out, rx_dma, PKT_LEN);
        result = RESULT_OK;
    } while(0);

    return result;
}
/***********************************************************************************************/
/**
 * @brief Perform a single SPI send transaction using DMA buffer.
 *
 * Copies data into the DMA buffer and transmits it over SPI.
 *
 * @param[in]  spi_fd   SPI file descriptor placeholder (not used)
 * @param[in]  gpio_fd  GPIO FD placeholder (not used)
 * @param[in]  data     Data buffer to send (must be at most PKT_LEN bytes)
 * @param[in]  len      Length of data to send in bytes
 *
 * @return RESULT_OK on success
 * @return RESULT_ARGUMENT_ERROR if data is NULL, DMA buffer not allocated, or len is invalid
 * @return RESULT_IO_ERROR if spi_slave_transmit fails
 */
int spi_send_transfer(int spi_fd, int gpio_fd, const uint8_t *data, size_t len)
{
    UNUSED(spi_fd);
    UNUSED(gpio_fd);
    int result = RESULT_OK;

    do {
        if (!data || !tx_dma || len == 0 || len > PKT_LEN) {
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        memcpy(tx_dma, data, len);

        spi_slave_transaction_t t = {
            .length = PKT_LEN * 8,
            .tx_buffer = tx_dma,
            .rx_buffer = rx_dma
        };

        esp_err_t ret = spi_slave_transmit(SPI_HOST, &t, pdMS_TO_TICKS(POLL_TIMEOUT_MS));
        if (ret != ESP_OK) {
            log_msg(LOG_WARNING, "SPI send transfer failed: %d", ret);
            result = RESULT_IO_ERROR;
        }
    } while(0);

    return result;
}
/***********************************************************************************************/
/* External functions                                                                          */
/***********************************************************************************************/
int spi_init(const char *device, int *spi_fd)
{
    UNUSED(device);
    int result = RESULT_OK;

    do {
        spi_done_sem = xSemaphoreCreateBinary();
        if (!spi_done_sem) {
            log_msg(LOG_ERR, "Failed to create SPI semaphore");
            result = RESULT_MEMORY_ERROR;
            break;
        }

        if (!spi_fd) {
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        spi_bus_config_t buscfg = {
            .mosi_io_num = GPIO_MOSI,
            .miso_io_num = GPIO_MISO,
            .sclk_io_num = GPIO_SCLK,
            .quadwp_io_num = -1,
            .quadhd_io_num = -1,
        };

        spi_slave_interface_config_t slvcfg = {
            .mode = 0,
            .spics_io_num = GPIO_CS,
            .queue_size = 3,
            .flags = 0,
            .post_setup_cb = post_setup_cb,
            .post_trans_cb = post_trans_cb
        };

        esp_err_t ret = spi_slave_initialize(SPI_HOST, &buscfg, &slvcfg, SPI_DMA_CH_AUTO);
        if (ret != ESP_OK) {
            log_msg(LOG_ERR, "SPI init failed: %d", ret);
            result = RESULT_NOT_INITED_ERROR;
            break;
        }

        tx_dma = spi_bus_dma_memory_alloc(SPI_HOST, PKT_LEN*2, 0);
        rx_dma = spi_bus_dma_memory_alloc(SPI_HOST, PKT_LEN*2, 0);
        if (!tx_dma || !rx_dma) {
            log_msg(LOG_ERR, "DMA buffer allocation failed");
            result = RESULT_MEMORY_ERROR;
            break;
        }

        *spi_fd = 1; // dummy fd for compatibility
        log_msg(LOG_INFO, "SPI initialized with DMA buffers and semaphore");
    } while(0);

    return result;
}
/***********************************************************************************************/
int spi_receive(int spi_fd, int gpio_fd, uint8_t *out_buf, uint16_t *length)
{
    UNUSED(gpio_fd);
    int result = RESULT_NODATA;

    do {
        if (!out_buf || !length) {
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        if (spi_fd < 0) {
            result = RESULT_NOT_INITED_ERROR;
            break;
        }

        result = spi_recv_transfer(spi_fd, gpio_fd, (uint8_t *)rx_dma);
        if (result != RESULT_OK) {
            break;
        }

        spi_ip_hdr_t *hdr = (spi_ip_hdr_t *)rx_dma;

        if (hdr->magic != SPI_MAGIC) {
            result = RESULT_BAD_PREFIX_ERROR;
            break;
        }

        if (hdr->version != SPI_PROTO_VERSION) {
            result = RESULT_TYPE_UNKNOWN_ERROR;
            break;
        }

        if (hdr->length == 0 || hdr->length > PKT_LEN - sizeof(spi_ip_hdr_t) - sizeof(uint32_t)) {
            result = RESULT_BROKEN_MSG_ERROR;
            break;
        }

        uint8_t *payload = (uint8_t *)rx_dma + sizeof(spi_ip_hdr_t);
        uint32_t rx_crc;
        memcpy(&rx_crc, payload + hdr->length, sizeof(rx_crc));

        if (rx_crc != esp_crc32_le(0, payload, hdr->length)) {
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
int spi_send_packet(int spi_fd, int gpio_fd, uint8_t *data, uint16_t len)
{
    UNUSED(gpio_fd);
    int result = RESULT_OK;

    do {
        if (!data || !tx_dma) {
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        if (spi_fd < 0) {
            result = RESULT_NOT_INITED_ERROR;
            break;
        }

        if (len == 0 || len > PKT_LEN - sizeof(spi_ip_hdr_t)) {
            result = RESULT_BAD_PREFIX_ERROR;
            break;
        }

        spi_ip_hdr_t hdr = {
            .magic = SPI_MAGIC,
            .version = SPI_PROTO_VERSION,
            .flags = 0,
            .length = len
        };

        uint32_t crc = esp_crc32_le(0, data, len);
        size_t off = 0;

        memcpy(tx_dma + off, &hdr, sizeof(hdr)); off += sizeof(hdr);
        memcpy(tx_dma + off, data, len);        off += len;
        memcpy(tx_dma + off, &crc, sizeof(crc)); off += sizeof(crc);

        result = spi_send_transfer(spi_fd, gpio_fd, (uint8_t *)tx_dma, off);
    } while(0);

    return result;
}
/***********************************************************************************************/
