// slave.c
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "driver/spi_slave.h"

#define TAG "SPI_SLAVE"
#define SPI_HOST SPI2_HOST
#define PKT_LEN 128
#define SPI_CHUNK_SIZE 32
#define SPI_CHUNK_PAYLOAD_SIZE (SPI_CHUNK_SIZE - 4)
#define SPI_CHUNK_MAGIC 0xA5
#define MAX_CHUNK_PACKET_SIZE 512

static uint8_t rx_buf[10][PKT_LEN] = {0};
static uint8_t tx_buf[PKT_LEN];

static uint8_t packet_buf[MAX_CHUNK_PACKET_SIZE];
static size_t packet_len = 0;
static uint8_t expected_chunks = 0;
static uint8_t received_chunks = 0;


static void dump_bytes(const uint8_t *buf, int len)
{
    for (int i = 0; i < len && i < 128; i += 16) {
        char line[96];
        int n = snprintf(line, sizeof(line), "%04x: ", i);
        for (int j = 0; j < 16 && i + j < len; j++) {
            n += snprintf(line + n, sizeof(line) - n,
                          "%02x ", buf[i + j]);
        }
        ESP_LOGI("DUMP", "%s", line);
    }
}

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
        .queue_size = 5,
    };

    ESP_ERROR_CHECK(
        spi_slave_initialize(SPI_HOST, &buscfg, &slvcfg, 0)
    );

    ESP_LOGI(TAG, "SPI slave initialized");
}

esp_err_t spi_slave_recv_packet(uint8_t *rx_packet, TickType_t timeout_ms)
{
    if (!rx_packet) return ESP_FAIL;

    uint8_t chunk_buf[SPI_CHUNK_SIZE];
    size_t total_received = 0;
    uint8_t cntr = 0;
    uint8_t try_cntr = 0;
    uint8_t matrix[128] = {0};

    while (total_received < PKT_LEN) {
        spi_slave_transaction_t t = {
            .length = SPI_CHUNK_SIZE * 8,
            .rx_buffer = chunk_buf,
            .tx_buffer = NULL,
        };

        esp_err_t r = spi_slave_transmit(SPI_HOST, &t, pdMS_TO_TICKS(timeout_ms));
        if (r != ESP_OK) {
            if (++try_cntr == 5) {
                printf("SPI no data\n");
                return ESP_FAIL;
            }
            continue;
        }


        if (chunk_buf[0] != SPI_CHUNK_MAGIC) {
//            printf("SPI chunk magic mismatch: 0x%02x\n", chunk_buf[0]);
//            return ESP_FAIL;
            continue;
        }

        uint8_t seq       = chunk_buf[1];
        uint8_t total_chunks = chunk_buf[2];
        uint8_t chunk_len   = chunk_buf[3];

        if (matrix[seq]) {
            continue;
        }

        if (chunk_len > SPI_CHUNK_PAYLOAD_SIZE) {
//            printf("SPI chunk_len too big: %d\n", chunk_len);
//            return ESP_FAIL;
            continue;
        }

        size_t offset = seq * SPI_CHUNK_PAYLOAD_SIZE;
        if (offset + chunk_len > PKT_LEN) {
//            printf("SPI chunk overflow\n");
//            return ESP_FAIL;
            continue;
        }

        memcpy(rx_packet + offset, &chunk_buf[4], chunk_len);
        total_received += chunk_len;
        matrix[seq] = 1;

        cntr++;
        printf("ch %u/%u %02X %02X\n", seq+1, total_chunks, chunk_buf[4], chunk_buf[5]);
//        dump_bytes(&chunk_buf[4], 2);
        if (seq+1 == total_chunks) {
            printf("OK\n");
            break;
        }

        vTaskDelay(pdMS_TO_TICKS(1));
    }

    return ESP_OK;
}

void spi_slave_send_packet(const uint8_t *data, size_t len)
{
    uint8_t tx[SPI_CHUNK_SIZE];
    uint8_t rx[SPI_CHUNK_SIZE];

    uint8_t total_chunks = (len + SPI_CHUNK_PAYLOAD_SIZE - 1) / SPI_CHUNK_PAYLOAD_SIZE;
    size_t offset = 0;

    for (uint8_t seq = 0; seq < total_chunks; seq++) {
        size_t chunk_len = len - offset;
        if (chunk_len > SPI_CHUNK_PAYLOAD_SIZE)
            chunk_len = SPI_CHUNK_PAYLOAD_SIZE;

        memset(tx, 0, sizeof(tx));
        tx[0] = SPI_CHUNK_MAGIC;
        tx[1] = seq;
        tx[2] = total_chunks;
        tx[3] = chunk_len;
        memcpy(&tx[4], data + offset, chunk_len);

        spi_slave_transaction_t t = {
            .length    = SPI_CHUNK_SIZE * 8,
            .tx_buffer = tx,
            .rx_buffer = rx,   // master щось пришле — не важливо
        };

        spi_slave_transmit(SPI_HOST, &t, pdMS_TO_TICKS(50));

        offset += chunk_len;
    }
}


//static void spi_slave_receive(uint8_t *rx_buf, int dly)
//{
//    size_t offset = 0;
//    ssize_t total = 0;

//    while (offset < PKT_LEN) {
//        size_t chunk = PKT_LEN - offset;
//        if (chunk > SPI_CHUNK_SIZE)
//            chunk = SPI_CHUNK_SIZE;

//        spi_slave_transaction_t t = {
//            .length = SPI_CHUNK_SIZE * 8,
//            .rx_buffer = rx_buf ? ((void *)(rx_buf + offset)) : NULL,
//            .tx_buffer = NULL,
//        };

//        esp_err_t r = spi_slave_transmit(SPI_HOST, &t, pdMS_TO_TICKS(dly));
//        if (r != ESP_OK) {
//            return;
//        }
//        offset += chunk;
//        total  += chunk;

//        vTaskDelay(pdMS_TO_TICKS(1));
//    }
//}

//static void spi_slave_receive(uint8_t *rx, int dly)
//{
//    spi_slave_transaction_t t = {
//        .length = PKT_LEN * 8,
//        .rx_buffer = rx,
//        .tx_buffer = NULL,
//    };

////    esp_err_t r =
//        spi_slave_transmit(SPI_HOST, &t, pdMS_TO_TICKS(dly));
////    if (r == ESP_OK) {
////    }
//}

static void spi_slave_send(uint8_t base)
{
    for (int i = 0; i < PKT_LEN; i++)
        tx_buf[i] = base + i;

    spi_slave_transaction_t t = {
        .length = PKT_LEN * 8,
        .tx_buffer = tx_buf,
        .rx_buffer = NULL,
    };

//    esp_err_t r =
      spi_slave_transmit(SPI_HOST, &t, pdMS_TO_TICKS(50));
//    if (r == ESP_OK) {
//        ESP_LOGI(TAG, "SLAVE sent packet base=0x%02x", base);
//    }
}

void app_main(void)
{
    spi_slave_init();

//    printf("=== TEST 1: master -> slave ===\n");
    for (int i = 0; i < 3; i++) {
//        spi_slave_receive(rx_buf[i], i == 0 ? 5000 : 50);
        size_t out_len = 0;
        spi_slave_recv_packet(rx_buf[i], i==0 ? 5000 : 300);
//        vTaskDelay(pdMS_TO_TICKS(2));
    }

//    printf("=== TEST 2: master <- slave ===\n");
//    for (int i = 0; i < 3; i++) {
//        spi_slave_send(i * 0x20);
//        vTaskDelay(pdMS_TO_TICKS(2));
//    }

    for (int i = 0; i < 3; i++) {
        ESP_LOGI(TAG, "Received [%d]:", i);
        dump_bytes(rx_buf[i], PKT_LEN);
    }

    while (1) vTaskDelay(portMAX_DELAY);
}
