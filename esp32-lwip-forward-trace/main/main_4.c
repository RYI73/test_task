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

#define WIFI_GOT_IP_BIT BIT0

#define WIFI_SSID "Linksys00283"
#define WIFI_PASS "@Valovyi_Ruslan1973"

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

static uint8_t spi_rx_buf[sizeof(spi_ip_hdr_t) + SPI_MTU + sizeof(uint32_t)];
static uint8_t spi_tx_buf[sizeof(spi_ip_hdr_t) + SPI_MTU + sizeof(uint32_t)];

static const char *TAG = "ROUTER";
static EventGroupHandle_t wifi_event_group;
static SemaphoreHandle_t spi_mutex;

static struct netif vnetif;

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

    dump_bytes(spi_tx_buf, off);

    spi_slave_transaction_t t = {
        .length    = off * 8,
        .tx_buffer = spi_tx_buf,
        .rx_buffer = NULL,
    };

    xSemaphoreTake(spi_mutex, portMAX_DELAY);
    esp_err_t ret = spi_slave_transmit(SPI_HOST, &t, pdMS_TO_TICKS(50));
    xSemaphoreGive(spi_mutex);

    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "sent OK");
    }
    else {
        ESP_LOGI(TAG, "not sent, ret %d", ret);
    }

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

    esp_err_t ret = spi_slave_transmit(SPI_HOST, &t, pdMS_TO_TICKS(50));
//    esp_err_t ret = spi_slave_transmit(SPI_HOST, &t, 0);
    if (ret != ESP_OK) {
        return ret;
    }

    dump_bytes(spi_rx_buf, 32);

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

static void spi_ipv4_input(const uint8_t *buf, size_t len)
{
    if (len < sizeof(struct ip_hdr)) {
        return;
    }

    struct ip_hdr *iph = (struct ip_hdr *)buf;

    /* Basic IPv4 sanity */
    if (IPH_V(iph) != 4) {
        ESP_LOGW(TAG, "Not IPv4");
        return;
    }

    uint16_t ip_hlen = IPH_HL_BYTES(iph);
    if (ip_hlen < sizeof(struct ip_hdr) || ip_hlen > len) {
        ESP_LOGW(TAG, "Bad IP header length");
        return;
    }

    /* allocate RAW pbuf (contains full IP packet) */
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
    if (!p) {
        return;
    }

    memcpy(p->payload, buf, len);

    switch (IPH_PROTO(iph)) {

    case IP_PROTO_ICMP:
        ESP_LOGD(TAG, "ICMP packet");
        ip4_input(p, netif_default);
        break;

    case IP_PROTO_TCP:
        ESP_LOGD(TAG, "TCP packet");
        ip4_input(p, netif_default);
        break;

    case IP_PROTO_UDP:
        ESP_LOGD(TAG, "UDP packet");
        ip4_input(p, netif_default);
        break;

    default:
        ESP_LOGW(TAG, "Unknown L4 proto: %u", IPH_PROTO(iph));
        pbuf_free(p);
        return;
    }

    /* ip4_input takes ownership of pbuf */
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
            spi_ipv4_input(buf, len);
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }

}


/* ===================== ONLY FOR DEBUG (ICMP replay's simulator)  ===================== */

static void icmp_echo_reply(struct pbuf *p)
{
    struct ip_hdr *iph = (struct ip_hdr *)p->payload;
    uint16_t ip_hlen = IPH_HL_BYTES(iph);

    struct icmp_echo_hdr *icmp =
        (struct icmp_echo_hdr *)((uint8_t *)iph + ip_hlen);

    if (icmp->type != ICMP_ECHO) return;

    uint16_t icmp_len = p->tot_len - ip_hlen;

    /* allocate TRANSPORT level pbuf */
    struct pbuf *q = pbuf_alloc(PBUF_TRANSPORT, icmp_len, PBUF_RAM);
    if (!q) return;

    memcpy(q->payload, icmp, icmp_len);

    struct icmp_echo_hdr *qicmp =
        (struct icmp_echo_hdr *)q->payload;

    qicmp->type = ICMP_ER;
    qicmp->chksum = 0;
    qicmp->chksum = inet_chksum(qicmp, icmp_len);

    /* extract IPs safely */
    ip4_addr_t src, dst;
    ip4_addr_copy(src, iph->dest);  // reply src
    ip4_addr_copy(dst, iph->src);   // reply dst

    ip4_output_if(q,
                  &src,
                  &dst,
                  IPH_TTL(iph),
                  IPH_TOS(iph),
                  IP_PROTO_ICMP,
                  netif_default);

    pbuf_free(q);

    ESP_LOGI(TAG, "ICMP echo reply sent (correct)");
}

/* ===================== L3 + TCP LOGGER ===================== */

void log_l3_tcp(struct pbuf *p)
{
    if (p->len < sizeof(struct ip_hdr)) return;

    struct ip_hdr *iph = (struct ip_hdr *)p->payload;
    if (IPH_V(iph) != 4) return;

//    dump_bytes(p->payload, p->len);

    uint32_t src = ip4_addr_get_u32(&iph->src);
    uint32_t dst = ip4_addr_get_u32(&iph->dest);

    ESP_LOGI(TAG,
        "IP proto=%d %d.%d.%d.%d -> %d.%d.%d.%d len=%d",
        IPH_PROTO(iph),
        src & 0xff, (src>>8)&0xff, (src>>16)&0xff, (src>>24)&0xff,
        dst & 0xff, (dst>>8)&0xff, (dst>>16)&0xff, (dst>>24)&0xff,
        p->tot_len
    );

    if (IPH_PROTO(iph) == IP_PROTO_TCP) {

        uint16_t ip_hlen = IPH_HL_BYTES(iph);
        if (p->len < ip_hlen + sizeof(struct tcp_hdr)) return;

        struct tcp_hdr *tcph =
            (struct tcp_hdr *)((uint8_t *)iph + ip_hlen);

        uint8_t f = TCPH_FLAGS(tcph);

        ESP_LOGI(TAG,
            " TCP %s%s%s%s %u -> %u seq=%u ack=%u",
            (f & TCP_SYN) ? "SYN " : "",
            (f & TCP_ACK) ? "ACK " : "",
            (f & TCP_FIN) ? "FIN " : "",
            (f & TCP_RST) ? "RST " : "",
            lwip_ntohs(tcph->src),
            lwip_ntohs(tcph->dest),
            lwip_ntohl(tcph->seqno),
            lwip_ntohl(tcph->ackno)
        );
    }
    else if (IPH_PROTO(iph) == IP_PROTO_ICMP) {
        icmp_echo_reply(p);
    }

}

/* ===================== VIRTUAL NETIF ===================== */

static err_t virtual_netif_output(struct netif *netif,
                                  struct pbuf *p,
                                  const ip4_addr_t *ipaddr)
{
//    log_l3_tcp(p);
    spi_send_ip(p->payload, p->len);

    return ERR_OK; // sink
}

static err_t virtual_netif_netif_init(struct netif *netif)
{
    netif->name[0] = 'v';
    netif->name[1] = 'n';
    netif->mtu = 1500;

    netif->flags =
        NETIF_FLAG_UP |
        NETIF_FLAG_LINK_UP |
        NETIF_FLAG_BROADCAST |
        NETIF_FLAG_ETHARP;

    netif->output = virtual_netif_output;
    netif->linkoutput = NULL; // L3 only

    return ERR_OK;
}

static void virtual_netif_init(void)
{
    ip4_addr_t ip, netmask, gw;

    IP4_ADDR(&ip,      10,0,0,1);
    IP4_ADDR(&netmask, 255,255,255,0);
    IP4_ADDR(&gw,      0,0,0,0);

    netif_add(&vnetif,
              &ip, &netmask, &gw,
              NULL,
              virtual_netif_netif_init,
              tcpip_input);

    vnetif.flags |= NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;

    ESP_LOGI(TAG, "Virtual netif UP: 10.0.0.1/24");
}

/* ===================== WIFI STA ===================== */

static void wifi_event_handler(void *arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data)
{
    if (event_base == WIFI_EVENT &&
        event_id == WIFI_EVENT_STA_START) {

        ESP_LOGI(TAG, "WiFi started, connecting...");
        esp_wifi_connect();
    }
    else if (event_base == WIFI_EVENT &&
             event_id == WIFI_EVENT_STA_DISCONNECTED) {

        ESP_LOGW(TAG, "WiFi disconnected, retry...");
        esp_wifi_connect();
    }
    else if (event_base == IP_EVENT &&
             event_id == IP_EVENT_STA_GOT_IP) {

        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;

        ESP_LOGI(TAG, "WiFi GOT IP: " IPSTR,
                 IP2STR(&event->ip_info.ip));

        xEventGroupSetBits(wifi_event_group, WIFI_GOT_IP_BIT);
    }
}


static void wifi_init(void)
{
    wifi_event_group = xEventGroupCreate();

    esp_netif_create_default_wifi_sta();

    ESP_ERROR_CHECK(
        esp_event_handler_register(WIFI_EVENT,
                                   ESP_EVENT_ANY_ID,
                                   &wifi_event_handler,
                                   NULL));

    ESP_ERROR_CHECK(
        esp_event_handler_register(IP_EVENT,
                                   IP_EVENT_STA_GOT_IP,
                                   &wifi_event_handler,
                                   NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t sta_cfg = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        }
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
}

/* ===================== APP MAIN ===================== */

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    spi_mutex = xSemaphoreCreateMutex();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

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
        .spics_io_num = 4,  // CS
        .queue_size = 3,
        .flags = 0,
    };

    esp_log_level_set("spi_slave", ESP_LOG_NONE);

    ESP_ERROR_CHECK(spi_slave_initialize(SPI_HOST, &buscfg, &slvcfg, 0));

    wifi_init();

    ESP_LOGI(TAG, "Waiting for IP...");
    xEventGroupWaitBits(wifi_event_group,
                        WIFI_GOT_IP_BIT,
                        pdFALSE,
                        pdTRUE,
                        portMAX_DELAY);

    virtual_netif_init();

    ESP_LOGI(TAG, "lwIP router + virtual sink ready");

    if (netif_default) {
        const ip4_addr_t *ip = netif_ip4_addr(netif_default);
        ESP_LOGI(TAG,
            "default netif: %c%c%d ip=%s",
            netif_default->name[0],
            netif_default->name[1],
            netif_default->num,
            ip ? ip4addr_ntoa(ip) : "none");
    }

    xTaskCreate(spi_rx_task, "spi_rx_task", 4096, NULL, 3, NULL);

}
