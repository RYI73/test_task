/**
 * @file esp32_spi_router.c
 * @brief L3 IPv4 forwarder between Wi-Fi STA and SPI (ESP-IDF v5+ compatible)
 *
 * This application forwards raw IPv4 packets between:
 *   - Wi-Fi STA (lwIP IPv4 stack)
 *   - SPI slave interface (custom framed protocol)
 *
 * It uses lwIP RAW PCB (raw_new(0)) to intercept all IPv4 packets
 * without relying on private esp-netif APIs.
 *
 * Designed to compile with ESP-IDF v5.x and lwIP 2.2.x
 */

#include <string.h>
#include <stdint.h>

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

#include "driver/spi_slave.h"

#include "lwip/raw.h"
#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/ip4.h"
#include "lwip/inet.h"

#define WIFI_SSID              "YOUR_WIFI_SSID"
#define WIFI_PASS              "YOUR_WIFI_PASSWORD"

#define SPI_HOST               SPI2_HOST
#define SPI_MTU                1500
#define SPI_MAGIC              0x49504657u
#define SPI_PROTO_VERSION      1

/**
 * @brief SPI framed IPv4 packet header
 */
typedef struct __attribute__((packed)) {
    uint32_t magic;     /**< Frame magic */
    uint8_t  version;   /**< Protocol version */
    uint8_t  flags;     /**< Reserved */
    uint16_t length;    /**< IPv4 packet length */
} spi_ip_hdr_t;

static const char *TAG = "ESP32_SPI_ROUTER";

static SemaphoreHandle_t spi_mutex;
static struct raw_pcb *raw_pcb_ip;

static uint8_t spi_rx_buf[sizeof(spi_ip_hdr_t) + SPI_MTU + sizeof(uint32_t)];
static uint8_t spi_tx_buf[sizeof(spi_ip_hdr_t) + SPI_MTU + sizeof(uint32_t)];

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
    if (!data || len == 0 || len > SPI_MTU) {
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

    spi_slave_transaction_t t = {
        .length    = off * 8,
        .tx_buffer = spi_tx_buf,
        .rx_buffer = NULL,
    };

    xSemaphoreTake(spi_mutex, portMAX_DELAY);
    esp_err_t ret = spi_slave_transmit(SPI_HOST, &t, portMAX_DELAY);
    xSemaphoreGive(spi_mutex);

    return ret;
}

/**
 * @brief Receive IPv4 packet from SPI master
 *
 * @param out_buf Output buffer
 * @param max_len Buffer size
 * @param out_len Received packet length
 *
 * @return ESP_OK if packet received
 */
static esp_err_t spi_recv_ip(uint8_t *out_buf, size_t max_len, size_t *out_len)
{
    spi_slave_transaction_t t = {
        .length    = sizeof(spi_rx_buf) * 8,
        .tx_buffer = NULL,
        .rx_buffer = spi_rx_buf,
    };

    esp_err_t ret = spi_slave_transmit(SPI_HOST, &t, portMAX_DELAY);
    if (ret != ESP_OK) return ret;

    spi_ip_hdr_t *hdr = (spi_ip_hdr_t *)spi_rx_buf;
    if (hdr->magic != SPI_MAGIC || hdr->version != SPI_PROTO_VERSION)
        return ESP_FAIL;

    if (hdr->length == 0 || hdr->length > max_len || hdr->length > SPI_MTU)
        return ESP_FAIL;

    uint8_t *payload = spi_rx_buf + sizeof(spi_ip_hdr_t);
    uint32_t rx_crc;
    memcpy(&rx_crc, payload + hdr->length, sizeof(rx_crc));

    if (rx_crc != esp_crc32_le(0, payload, hdr->length))
        return ESP_FAIL;

    memcpy(out_buf, payload, hdr->length);
    *out_len = hdr->length;

    return ESP_OK;
}

/**
 * @brief RAW callback for Wi-Fi -> SPI forwarding
 */
static u8_t raw_rx_cb(void *arg, struct raw_pcb *pcb,
                      struct pbuf *p, const ip_addr_t *addr)
{
    (void)arg; (void)pcb; (void)addr;

    if (!p || p->tot_len > SPI_MTU)
        return 0;

    uint8_t buf[SPI_MTU];
    pbuf_copy_partial(p, buf, p->tot_len, 0);
    spi_send_ip(buf, p->tot_len);

    return 1; /* packet eaten */
}

/**
 * @brief Initialize lwIP RAW PCB (IPv4 any protocol)
 */
static void raw_ip_init(void)
{
    raw_pcb_ip = raw_new(0); /* 0 = all IPv4 protocols */
    raw_bind(raw_pcb_ip, IP_ADDR_ANY);
    raw_recv(raw_pcb_ip, raw_rx_cb, NULL);
}

/**
 * @brief SPI -> lwIP RX task
 */
static void spi_rx_task(void *arg)
{
    (void)arg;

    uint8_t buf[SPI_MTU];
    size_t len;

    ip_addr_t dest;
    IP_ADDR4(&dest, 0,0,0,0); /* IPv4 wildcard */

    while (1) {
        if (spi_recv_ip(buf, sizeof(buf), &len) == ESP_OK) {
            struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
            if (p) {
                pbuf_take(p, buf, len);
                raw_sendto(raw_pcb_ip, p, &dest);
                pbuf_free(p);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

/**
 * @brief Initialize Wi-Fi STA
 */
static void wifi_init_sta(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t wifi_cfg = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_connect());
}

/**
 * @brief Application entry point
 */
void app_main(void)
{
    spi_mutex = xSemaphoreCreateMutex();

    /* SPI slave init */
    spi_bus_config_t buscfg = {
        .mosi_io_num = 13,   // MOSI pin ESP32 (Master MISO)
        .miso_io_num = 12,   // MISO pin ESP32 (Master MOSI)
        .sclk_io_num = 14,   // SCLK
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = SPI_MTU + sizeof(spi_ip_hdr_t) + 4,
    };

    spi_slave_interface_config_t slvcfg = {
        .mode = 0,
        .spics_io_num = 15,  // CS
        .queue_size = 3,
        .flags = 0,
    };

    ESP_ERROR_CHECK(spi_slave_initialize(SPI_HOST, &buscfg, &slvcfg, 0));

    wifi_init_sta();
    raw_ip_init();

    xTaskCreate(spi_rx_task,
                "spi_rx_task",
                4096,
                NULL,
                5,
                NULL);

    ESP_LOGI(TAG, "L3 WiFi <-> SPI router started");
}
