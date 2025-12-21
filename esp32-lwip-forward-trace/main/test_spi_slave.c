// slave.c
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "driver/spi_slave.h"

#define TAG "SPI_SLAVE"
#define SPI_HOST SPI2_HOST
#define PKT_LEN 32

static uint8_t rx_buf[PKT_LEN];
static uint8_t tx_buf[PKT_LEN];

static void spi_slave_init(void)
{
    spi_bus_config_t buscfg = {
        .mosi_io_num = 13,
        .miso_io_num = 12,
        .sclk_io_num = 14,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = PKT_LEN
    };

    spi_slave_interface_config_t slvcfg = {
        .mode = 0,
        .spics_io_num = 15,  
        .queue_size = 3,
    };

    ESP_ERROR_CHECK(
        spi_slave_initialize(SPI_HOST, &buscfg, &slvcfg, SPI_DMA_CH_AUTO)
    );

    ESP_LOGI(TAG, "SPI slave initialized");
}

static void spi_slave_receive(void)
{
    spi_slave_transaction_t t = {
        .length = PKT_LEN * 8,
        .rx_buffer = rx_buf,
        .tx_buffer = NULL,
    };

    esp_err_t r = spi_slave_transmit(SPI_HOST, &t, portMAX_DELAY);
    if (r == ESP_OK) {
        ESP_LOGI(TAG, "SLAVE received:");
        for (int i = 0; i < PKT_LEN; i++)
            printf("%02x ", rx_buf[i]);
        printf("\n");
    }
}

static void spi_slave_send(uint8_t base)
{
    for (int i = 0; i < PKT_LEN; i++)
        tx_buf[i] = base + i;

    spi_slave_transaction_t t = {
        .length = PKT_LEN * 8,
        .tx_buffer = tx_buf,
        .rx_buffer = NULL,
    };

    esp_err_t r = spi_slave_transmit(SPI_HOST, &t, portMAX_DELAY);
    if (r == ESP_OK) {
        ESP_LOGI(TAG, "SLAVE sent packet base=0x%02x", base);
    }
}

void app_main(void)
{
    spi_slave_init();

    printf("=== TEST 1: master -> slave ===\n");
    for (int i = 0; i < 3; i++) {
        spi_slave_receive();
    }

    printf("=== TEST 2: master <- slave ===\n");
    for (int i = 0; i < 3; i++) {
        spi_slave_send(i * 0x20);
    }

    while (1) vTaskDelay(portMAX_DELAY);
}
