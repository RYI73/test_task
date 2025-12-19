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
#include "lwip/etharp.h"
#include "lwip/ip4_addr.h"

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

//static SemaphoreHandle_t count_mutex;
//static volatile uint32_t pkt_count = 0;
//static volatile uint32_t udp_count = 0;
//static volatile uint32_t tcp_count = 0;
//static volatile uint32_t icmp_count = 0;
//static volatile uint32_t arp_count = 0;
typedef struct {
    int arp;
    int icmp;
    int tcp;
    int udp;
    int all;
} packet_counter_t;

packet_counter_t counters = {0};
static portMUX_TYPE counter_mux = portMUX_INITIALIZER_UNLOCKED;

static uint8_t spi_rx_buf[sizeof(spi_ip_hdr_t) + SPI_MTU + sizeof(uint32_t)];
static uint8_t spi_tx_buf[sizeof(spi_ip_hdr_t) + SPI_MTU + sizeof(uint32_t)];

typedef struct __attribute__((packed)) {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
} eth_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t  v_hl;
    uint8_t  tos;
    uint16_t len;
    uint16_t id;
    uint16_t offset;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t chksum;
    uint32_t src;
    uint32_t dst;
} ip_hdr_t;

#define WLAN_FC_TYPE(fc)        (((fc) >> 2) & 0x3)
#define WLAN_FC_SUBTYPE(fc)     (((fc) >> 4) & 0xF)
#define WLAN_FC_TO_DS(fc)       ((fc) & 0x0100)
#define WLAN_FC_FROM_DS(fc)     ((fc) & 0x0200)

#define WLAN_TYPE_DATA          2
#define WLAN_QOS_DATA           8

// -------------------------- NETIF --------------------------
struct netif netif_wifi;
struct netif netif_spi;

// -------------------------- UTILITIES --------------------------
void dump_hex(const uint8_t* data, int len) {
    char line[80];
    for (int i = 0; i < len; i += 16) {
        int l = snprintf(line, sizeof(line), "%04x: ", i);
        for (int j = 0; j < 16 && (i+j) < len; j++) {
            l += snprintf(line+l, sizeof(line)-l, "%02x ", data[i+j]);
        }
        ESP_LOGI(TAG, "%s", line);
    }
}

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

//static void wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
//{
//    (void)buf; (void)type;

//    if (count_mutex) {
//        if (xSemaphoreTake(count_mutex, 0) == pdTRUE) {
//            pkt_count++;
//            xSemaphoreGive(count_mutex);
//        }
//    }
//}

//void wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
//{
//    if (type != WIFI_PKT_DATA)
//        return;

//    if (count_mutex) {
//        if (xSemaphoreTake(count_mutex, 0) == pdTRUE) {
//            pkt_count++;
//            xSemaphoreGive(count_mutex);
//        }
//    }

//    const wifi_promiscuous_pkt_t *pkt = buf;
//    const uint8_t *payload = pkt->payload;

////    ESP_LOGI(TAG, "Packet received, len=%d", pkt->rx_ctrl.sig_len);
////    ESP_LOG_BUFFER_HEXDUMP(TAG, payload, 32, ESP_LOG_INFO);
//    ESP_LOGI(TAG, "802.11 header:");
//    ESP_LOG_BUFFER_HEXDUMP(TAG, payload, 24, ESP_LOG_INFO); // перші 24 байти MAC header
//    ESP_LOGI(TAG, "LLC/SNAP:");
//    ESP_LOG_BUFFER_HEXDUMP(TAG, payload + 24, 8, ESP_LOG_INFO); // наступні 8 байт
//    ESP_LOGI(TAG, "Payload (possible Ethernet):");
//    ESP_LOG_BUFFER_HEXDUMP(TAG, payload + 24 + 8, 32, ESP_LOG_INFO); // наступні 32 байти

//    // 802.11 data header (звичайно 24 байти)
//    const uint8_t *llc = payload + 24;

//    // LLC + SNAP = 8 байт
//    const eth_hdr_t *eth =
//        (const eth_hdr_t *)(llc + 8);

//    uint16_t ethertype = ntohs(eth->type);

//    if (ethertype == 0x0806) {
//        // ARP
//        if (count_mutex) {
//            if (xSemaphoreTake(count_mutex, 0) == pdTRUE) {
//                arp_count++;
//                xSemaphoreGive(count_mutex);
//            }
//        }
//        return;
//    }

//    if (ethertype != 0x0800)
//        return; // не IPv4

//    const ip_hdr_t *ip =
//        (const ip_hdr_t *)(eth + 1);

//    uint32_t src = ntohl(ip->src);
//    uint32_t dst = ntohl(ip->dst);

//    // мережа 10.0.0.0/8
//    if ((src & 0xFF000000) != 0x0A000000 &&
//        (dst & 0xFF000000) != 0x0A000000)
//        return;

//    if (ip->proto == 1) {
//        if (count_mutex) {
//            if (xSemaphoreTake(count_mutex, 0) == pdTRUE) {
//                icmp_count++;
//                xSemaphoreGive(count_mutex);
//            }
//        }
//    } else if (ip->proto == 6) {
//        if (count_mutex) {
//            if (xSemaphoreTake(count_mutex, 0) == pdTRUE) {
//                tcp_count++;
//                xSemaphoreGive(count_mutex);
//            }
//        }
//    } else if (ip->proto == 17) {
//        if (count_mutex) {
//            if (xSemaphoreTake(count_mutex, 0) == pdTRUE) {
//                udp_count++;
//                xSemaphoreGive(count_mutex);
//            }
//        }
//    }
//}

//static void dump_hex(const char *tag, const uint8_t *buf, int len)
//{
//    char line[80];
//    int pos = 0;

//    for (int i = 0; i < len && i < 64; i++) { // не більше 64 байт
//        pos += snprintf(line + pos, sizeof(line) - pos,
//                        "%02x ", buf[i]);
//        if ((i & 0x0F) == 0x0F) {
//            ESP_LOGI(tag, "%s", line);
//            pos = 0;
//        }
//    }
//    if (pos)
//        ESP_LOGI(tag, "%s", line);
//}

//void wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
//{
//    if (type != WIFI_PKT_DATA || !buf) return;

//    const wifi_promiscuous_pkt_t *ppkt = buf;
//    const uint8_t *p = ppkt->payload;
//    int len = ppkt->rx_ctrl.sig_len;

//    ESP_LOGI(TAG, "---------------- PACKET ----------------");
//    ESP_LOGI(TAG, "RSSI=%d len=%d", ppkt->rx_ctrl.rssi, len);

//    ESP_LOGI(TAG, "802.11 header (raw):");
//    dump_hex(TAG, p, 32);

//    uint16_t fc = p[0] | (p[1] << 8);
//    bool to_ds   = fc & BIT(8);
//    bool from_ds = fc & BIT(9);
//    bool qos     = ((fc & 0x0C) == 0x08);

//    int hdr_len = 24;
//    if (to_ds && from_ds) hdr_len = 30;
//    if (qos) hdr_len += 2;

//    ESP_LOGI(TAG,
//        "FC=0x%04x toDS=%d fromDS=%d qos=%d hdr_len=%d",
//        fc, to_ds, from_ds, qos, hdr_len);

//    if (len < hdr_len + 8) {
//        ESP_LOGW(TAG, "Frame too short for LLC");
//        return;
//    }

//    const uint8_t *llc = p + hdr_len;

//    ESP_LOGI(TAG, "LLC/SNAP:");
//    dump_hex(TAG, llc, 8);

//    if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03)) {
//        ESP_LOGW(TAG, "No SNAP header");
//        return;
//    }

//    uint16_t ethertype = (llc[6] << 8) | llc[7];
//    ESP_LOGI(TAG, "Ethertype=0x%04x", ethertype);

//    portENTER_CRITICAL_ISR(&counter_mux);
//    counters.all++;

//    if (ethertype == 0x0806) {
//        counters.arp++;
//        ESP_LOGI(TAG, "Parsed: ARP");
//    }
//    else if (ethertype == 0x0800) {
//        const uint8_t *ip = llc + 8;
//        uint8_t proto = ip[9];

//        ESP_LOGI(TAG, "IPv4 proto=%u", proto);

//        if (proto == 1) {
//            counters.icmp++;
//            ESP_LOGI(TAG, "Parsed: ICMP");
//        } else if (proto == 6) {
//            counters.tcp++;
//            ESP_LOGI(TAG, "Parsed: TCP");
//        } else if (proto == 17) {
//            counters.udp++;
//            ESP_LOGI(TAG, "Parsed: UDP");
//        } else {
//            ESP_LOGI(TAG, "Parsed: IPv4 other");
//        }
//    }
//    else {
//        ESP_LOGI(TAG, "Unknown ethertype");
//    }

//    portEXIT_CRITICAL_ISR(&counter_mux);
//}



//static void wifi_sniffer_init(void)
//{
//    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));

//    wifi_promiscuous_filter_t filter = {
//        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA
//    };
//    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));

//    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb));
//    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

//    ESP_LOGI(TAG, "WiFi promiscuous sniffer started");
//}
#else
/**
 * @brief RAW callback for Wi-Fi -> SPI forwarding
 */
static u8_t raw_rx_cb(void *arg, struct raw_pcb *pcb,
                      struct pbuf *p, const ip_addr_t *addr)
{
    (void)arg; (void)pcb; (void)addr;

    if (count_mutex) {
        if (xSemaphoreTake(count_mutex, 0) == pdTRUE) {
            pkt_count++;
            xSemaphoreGive(count_mutex);
        }
    }

//    ESP_LOGI(TAG, "recv ln %d", p->tot_len);

//    if (!p || p->tot_len > SPI_MTU)
//        return 0;


//    uint8_t buf[SPI_MTU];
//    pbuf_copy_partial(p, buf, p->tot_len, 0);
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
//        if (spi_recv_ip(buf, sizeof(buf), &len) == ESP_OK) {
//            struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
//            if (p) {
//                pbuf_take(p, buf, len);
//                raw_sendto(raw_pcb_ip, p, &dest);
//                pbuf_free(p);
//            }
//        }
        vTaskDelay(pdMS_TO_TICKS(2000));

        packet_counter_t c;
        portENTER_CRITICAL(&counter_mux);
        c = counters;
        portEXIT_CRITICAL(&counter_mux);

        ESP_LOGI(TAG, "Packets received: ALL=%d ARP=%d ICMP=%d TCP=%d UDP=%d",
                 c.all, c.arp, c.icmp, c.tcp, c.udp);
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


// -------------------------- PACKET PARSING --------------------------
void parse_ethernet(struct pbuf *p) {
    if (!p) return;
    struct eth_hdr *eth = (struct eth_hdr *)p->payload;

    portENTER_CRITICAL(&counter_mux);
    counters.all++;
    switch (htons(eth->type)) {
        case ETHTYPE_ARP: counters.arp++; break;
        case ETHTYPE_IP: {
            struct ip_hdr *iph = (struct ip_hdr *)((uint8_t*)eth + sizeof(struct eth_hdr));
            switch (IPH_PROTO(iph)) {
                case IP_PROTO_ICMP: counters.icmp++; break;
                case IP_PROTO_TCP: counters.tcp++; break;
                case IP_PROTO_UDP: counters.udp++; break;
            }
            break;
        }
    }
    portEXIT_CRITICAL(&counter_mux);

    ESP_LOGI(TAG, "Packet received: eth_type=0x%04x len=%d", htons(eth->type), p->len);
    dump_hex((uint8_t*)p->payload, p->len);
}

// -------------------------- RAW HOOK --------------------------
// --- lwIP hook для перехоплення вхідних пакетів ---
err_t lwip_hook_netif_input(struct pbuf *p, struct netif *inp) {
    if (!p) return ERR_OK;

    // --- Простий парсинг: лише IP/ARP ---
    uint16_t eth_type = (p->payload[12] << 8) | p->payload[13];

    portENTER_CRITICAL(&counter_mux);
    counters.all++;
    if (eth_type == 0x0806) counters.arp++;
    else if (eth_type == 0x0800) {
        uint8_t proto = ((uint8_t *)p->payload)[23];
        if (proto == 1) counters.icmp++;
        else if (proto == 6) counters.tcp++;
        else if (proto == 17) counters.udp++;
    }
    portEXIT_CRITICAL(&counter_mux);

    ESP_LOGI(TAG, "Packet received: eth_type=0x%04x len=%d", eth_type, p->len);
    hexdump(p->payload, p->len);

    // --- let lwIP continue processing normally ---
    return ERR_OK;
}

// --- Ініціалізація SPI netif ---
struct netif netif_spi;
static void init_spi_netif(void) {
    ip4_addr_t ip, gw, mask;
    IP4_ADDR(&ip, 10,0,0,2);
    IP4_ADDR(&gw, 10,0,0,1); // RP Zero
    IP4_ADDR(&mask, 255,255,255,0);

    memset(&netif_spi, 0, sizeof(netif_spi));
    netif_add(&netif_spi, &ip, &mask, &gw, NULL, NULL, tcpip_input);
    netif_set_up(&netif_spi);
    ESP_LOGI(TAG, "SPI netif initialized: 10.0.0.2/24");

    add_static_arp_for_rp_zero(&netif_spi);
}

// -------------------------- NETIF INIT --------------------------
void init_netif(void) {
    ip4_addr_t ip_wifi, gw_wifi, mask_wifi;
    ip4_addr_t ip_spi, gw_spi, mask_spi;

    IP4_ADDR(&ip_wifi, 192,168,1,123);
    IP4_ADDR(&gw_wifi, 192,168,1,1);
    IP4_ADDR(&mask_wifi, 255,255,255,0);

    IP4_ADDR(&ip_spi, 10,0,0,2);
    IP4_ADDR(&gw_spi, 10,0,0,1);
    IP4_ADDR(&mask_spi, 255,255,255,0);

    netif_add(&netif_wifi, &ip_wifi, &mask_wifi, &gw_wifi,
              NULL, ethernetif_init, tcpip_input);
    netif_set_default(&netif_wifi);
    netif_set_up(&netif_wifi);

    netif_add(&netif_spi, &ip_spi, &mask_spi, &gw_spi,
              NULL, spiif_init, tcpip_input);
    netif_set_up(&netif_spi);

    // Proxy ARP для 10.0.0.1
    struct eth_addr mac;
    mac.addr[0]=0x02; mac.addr[1]=0x00; mac.addr[2]=0x00;
    mac.addr[3]=0x00; mac.addr[4]=0x00; mac.addr[5]=0x02;
    ip4_addr_t ip;
    IP4_ADDR(&ip, 10,0,0,1);
    etharp_add_static_entry(&ip, &mac);
}

// Ініціалізація статичного ARP для 10.0.0.1
void add_static_arp_for_rp_zero() {
    ip4_addr_t ip;
    IP4_ADDR(&ip, 10, 0, 0, 1);

    struct eth_addr mac = {{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}};

    err_t res = etharp_add_static_entry(&ip, &mac);
    if(res == ERR_OK) {
        ESP_LOGI(TAG, "Static ARP entry added for 10.0.0.1 -> 02:00:00:00:00:02");
    } else {
        ESP_LOGE(TAG, "Failed to add static ARP entry: %d", res);
    }
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
//    count_mutex = xSemaphoreCreateMutex();

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
//    wifi_sniffer_init();
    tcpip_adapter_init();
    tcpip_init(NULL, NULL);

    init_netif();

    init_spi_netif();       // SPI netif (10.0.0.2)

    // --- Регіструємо lwIP hook ---
    ip_input_hook = lwip_hook_netif_input;

    xTaskCreate(spi_rx_task,
                "spi_rx_task",
                4096,
                NULL,
                3,
                NULL);

    ESP_LOGI(TAG, "L3 WiFi <-> SPI router started");
}
