// slave.c
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_system.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_crc.h"
#include "nvs_flash.h"

#include "lwip/netif.h"
#include "lwip/ip4.h"
#include "lwip/ip.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include "driver/spi_slave.h"

#include "lwip/netif.h"
#include "lwip/ip4.h"
#include "lwip/ip.h"
#include "lwip/pbuf.h"

#include "lwip/prot/ip4.h"
#include "lwip/prot/tcp.h"
#include "freertos/event_groups.h"

#include "lwip/icmp.h"
#include "lwip/inet_chksum.h"
#include "lwip/tcpip.h"

#define TAG "SPI_SLAVE"
#define SPI_HOST SPI2_HOST
#define PKT_LEN 128
#define SPI_CHUNK_SIZE 32
#define SPI_CHUNK_PAYLOAD_SIZE (SPI_CHUNK_SIZE - 4)
#define SPI_CHUNK_MAGIC 0xA5
#define MAX_CHUNK_PACKET_SIZE 512
#define SPI_MAGIC 0x49504657   /**< Magic constant ('IPFW') for SPI framing */
#define SPI_PROTO_VERSION 1

/**
 * @struct spi_ip_hdr_t
 * @brief Header for framing IPv4 packets over SPI
 */
typedef struct __attribute__((packed)) {
    uint32_t magic;     /**< Magic constant SPI_MAGIC */
    uint8_t version;    /**< Protocol version (0x01) */
    uint8_t flags;      /**< Reserved flags */
    uint16_t length;    /**< IPv4 packet length in bytes */
} spi_ip_hdr_t;


static uint8_t rx_buf[10][PKT_LEN] = {0};
static uint8_t tx_buf[PKT_LEN];

static uint8_t packet_buf[MAX_CHUNK_PACKET_SIZE];
static size_t packet_len = 0;
static uint8_t expected_chunks = 0;
static uint8_t received_chunks = 0;

uint8_t payload_pack[] = {
    0xc0,0xa8,0x01,0x77,0x0a,0x00,0x00,0x02,0x08,0x00,0xe6,0xce,
    0x12,0x0d,0x00,0x01,0xc9,0xae,0x47,0x69,0x00,0x00,0x00,0x00,
    0x2d,0x38,0x02,0x00,0x00,0x00,0x00,0x00,0x10,0x11,0x12,0x13,
    0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,
};

static uint8_t spi_rx_buf[PKT_LEN];
static uint8_t spi_tx_buf[PKT_LEN];

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
        .max_transfer_sz = SPI_CHUNK_SIZE
    };

    spi_slave_interface_config_t slvcfg = {
        .mode = 0,
        .spics_io_num = 15,
        .queue_size = 3,
    };

    ESP_ERROR_CHECK(
//        spi_slave_initialize(SPI_HOST, &buscfg, &slvcfg, 0)
        spi_slave_initialize(SPI_HOST, &buscfg, &slvcfg, SPI_DMA_CH_AUTO)
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

void spi_slave_send_packet(const uint8_t *data)
{
    uint8_t tx[SPI_CHUNK_SIZE];
//    uint8_t rx[SPI_CHUNK_SIZE];

    uint8_t total_chunks = (PKT_LEN + SPI_CHUNK_PAYLOAD_SIZE - 1) / SPI_CHUNK_PAYLOAD_SIZE;
    size_t offset = 0;

    for (uint8_t seq = 0; seq < total_chunks; seq++) {
        size_t chunk_len = PKT_LEN - offset;
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
            .rx_buffer = NULL,
        };

        esp_err_t r =
            spi_slave_transmit(SPI_HOST, &t, portMAX_DELAY);
        if (r == ESP_OK) {
            ESP_LOGI(TAG, "Sent chunk %u", seq);
        }
        else {
            return;
        }

        offset += chunk_len;
    }
    ESP_LOGI(TAG, "Sent packet");
}

//static void spi_slave_send(uint8_t base)
//{
//    for (int i = 0; i < SPI_CHUNK_SIZE; i++)
//        tx_buf[i] = base + i;

//    spi_slave_transaction_t t = {
//        .length = SPI_CHUNK_SIZE * 8,
//        .tx_buffer = tx_buf,
//        .rx_buffer = NULL,
//    };

//    esp_err_t r =
//        spi_slave_transmit(SPI_HOST, &t, portMAX_DELAY);
//    if (r == ESP_OK) {
//        ESP_LOGI(TAG, "SLAVE sent packet base=0x%02x", base);
//    }
//}


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

/**
 * @brief Send IPv4 packet to SPI master
 *
 * @param data Pointer to IPv4 packet
 * @param len  Packet length
 *
 * @return ESP_OK on success
 */
static esp_err_t spi_send_ip(const uint8_t *data, size_t len)
{
    if (!data || len == 0 || len > PKT_LEN - sizeof(spi_ip_hdr_t)) {
        return ESP_ERR_INVALID_ARG;
    }

    spi_ip_hdr_t hdr = {
        .magic   = SPI_MAGIC,
        .version = SPI_PROTO_VERSION,
        .flags   = 0,
        .length  = len
    };

    uint32_t crc = esp_crc32_le(0, data, len);
    size_t off = 0;

    memcpy(&spi_tx_buf[off], &hdr, sizeof(hdr)); off += sizeof(hdr);
    memcpy(&spi_tx_buf[off], data, len);         off += len;
    memcpy(&spi_tx_buf[off], &crc, sizeof(crc)); off += sizeof(crc);

    dump_bytes(spi_tx_buf, off);

    spi_slave_send_packet(spi_tx_buf);

//    spi_slave_transaction_t t = {
//        .length    = off * 8,
//        .tx_buffer = spi_tx_buf,
//        .rx_buffer = NULL,
//    };

//    xSemaphoreTake(spi_mutex, portMAX_DELAY);
//    esp_err_t ret = spi_slave_transmit(SPI_HOST, &t, pdMS_TO_TICKS(50));
//    xSemaphoreGive(spi_mutex);

//    if (ret == ESP_OK) {
//        ESP_LOGI(TAG, "sent OK");
//    }
//    else {
//        ESP_LOGI(TAG, "not sent, ret %d", ret);
//    }

    return ESP_OK;
}

void app_main(void)
{
    spi_slave_init();

    for (int i = 0; i < 3; i++) {
        spi_slave_recv_packet(rx_buf[i], i==0 ? 5000 : 300);
    }
    for (int i = 0; i < 3; i++) {
        ESP_LOGI(TAG, "Received [%d]:", i);
        dump_bytes(rx_buf[i], PKT_LEN);
    }

//     vTaskDelay(pdMS_TO_TICKS(100000));
    printf("=== TEST 2: master <- slave ===\n");
    for (int i = 0; i < 3; i++) {
//        spi_slave_send(i * 0x20);
//        spi_slave_send_packet(payload_pack);
        spi_send_ip(payload_pack, sizeof(payload_pack));
//        vTaskDelay(pdMS_TO_TICKS(2));
    }


    while (1) vTaskDelay(portMAX_DELAY);
}
