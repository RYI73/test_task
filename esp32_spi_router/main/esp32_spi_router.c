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
#include "nvs_flash.h"

#include "driver/spi_slave.h"

#include "lwip/raw.h"
#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/ip4.h"
#include "lwip/inet.h"

#define WIFI_SSID              "Linksys00283"
#define WIFI_PASS              "@Valovyi_Ruslan1973"

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
    esp_err_t ret = spi_slave_transmit(SPI_HOST, &t, pdMS_TO_TICKS(50));
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

//    esp_err_t ret = spi_slave_transmit(SPI_HOST, &t, pdMS_TO_TICKS(50));
    esp_err_t ret = spi_slave_transmit(SPI_HOST, &t, 0);
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

#if 1
static volatile uint32_t pkt_count = 0;
static SemaphoreHandle_t count_mutex;

//static void wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
//{
//    if (type != WIFI_PKT_DATA)
//        return;

//    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
//    const uint8_t *frame = ppkt->payload;
//    uint16_t len = ppkt->rx_ctrl.sig_len;

//    /* Мінімум: 802.11 + LLC */
//    if (len < 36)
//        return;

//    /* LLC/SNAP header (offset залежить від ToDS/FromDS, тут типовий STA<-AP) */
//    const uint8_t *llc = frame + 24;

//    /* SNAP: AA AA 03 00 00 00 08 00 */
//    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03)
//        return;

//    /* IPv4 */
//    if (llc[6] != 0x08 || llc[7] != 0x00)
//        return;

//    const struct ip_hdr *ip = (struct ip_hdr *)(llc + 8);

//    ESP_LOGI(TAG, "IP pkt proto=%d len=%d",
//             IPH_PROTO(ip),
//             ntohs(IPH_LEN(ip)));

//    /* Тут ТИ ОТРИМУЄШ УСІ IP ПАКЕТИ */
//    /* хоч ICMP, хоч UDP, хоч TCP, хоч не на нашу IP */

//    /* якщо треба → копіюєш і шлеш по SPI */
//    /*
//    size_t ip_len = ntohs(IPH_LEN(ip));
//    if (ip_len <= SPI_MTU)
//        spi_send_ip((uint8_t *)ip, ip_len);
//    */
//}
static void wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    (void)buf; (void)type;

    // просто інкрементуємо лічильник у критичній секції
    if (count_mutex) {
        if (xSemaphoreTake(count_mutex, 0) == pdTRUE) {
            pkt_count++;
            xSemaphoreGive(count_mutex);
        }
    }
}

static void wifi_sniffer_init(void)
{
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));

    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    ESP_LOGI(TAG, "WiFi promiscuous sniffer started");
}
#else
/**
 * @brief RAW callback for Wi-Fi -> SPI forwarding
 */
static u8_t raw_rx_cb(void *arg, struct raw_pcb *pcb,
                      struct pbuf *p, const ip_addr_t *addr)
{
    (void)arg; (void)pcb; (void)addr;
    ESP_LOGI(TAG, "recv ln %d", p->tot_len);

    if (!p || p->tot_len > SPI_MTU)
        return 0;


    uint8_t buf[SPI_MTU];
    pbuf_copy_partial(p, buf, p->tot_len, 0);
//    spi_send_ip(buf, p->tot_len);

    return 1; /* packet eaten */
}

/**
 * @brief Initialize lwIP RAW PCB (IPv4 any protocol)
 */
static void raw_ip_init(void)
{
//    ESP_LOGI(TAG, "raw_ip_init()");
    raw_pcb_ip = raw_new(0); /* 0 = all IPv4 protocols */
    raw_bind(raw_pcb_ip, IP_ADDR_ANY);
    raw_recv(raw_pcb_ip, raw_rx_cb, NULL);
}
#endif
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
        vTaskDelay(pdMS_TO_TICKS(2000));
        uint32_t count = 0;

        if (count_mutex && xSemaphoreTake(count_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
            count = pkt_count;
            xSemaphoreGive(count_mutex);
        }

        ESP_LOGI(TAG, "Packets received in last 2s: %u", count);
    }
}

/**
 * @brief Initialize Wi-Fi STA
 */
static void wifi_init_sta(void)
{
//    ESP_LOGI(TAG, "wifi_init_sta()");
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
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    esp_log_level_set("spi_slave", ESP_LOG_NONE);

//    ESP_LOGI(TAG, "Start ESP32 utility");
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
//    raw_ip_init();
    wifi_sniffer_init();

    xTaskCreate(spi_rx_task,
                "spi_rx_task",
                4096,
                NULL,
                3,
                NULL);

    ESP_LOGI(TAG, "L3 WiFi <-> SPI router started");
}
