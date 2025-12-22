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

#define WIFI_GOT_IP_BIT BIT0

#define WIFI_SSID "Linksys00283"
#define WIFI_PASS "@Valovyi_Ruslan1973"


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
        spi_slave_initialize(SPI_HOST, &buscfg, &slvcfg, SPI_DMA_CH_AUTO)
    );

    ESP_LOGI(TAG, "SPI slave initialized");
}

esp_err_t spi_slave_recv_packet(uint8_t *rx_packet, TickType_t timeout_ms)
{
    if (!rx_packet) return ESP_FAIL;

    uint8_t chunk_buf[SPI_CHUNK_SIZE];
    size_t total_received = 0;
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
            continue;
        }

        size_t offset = seq * SPI_CHUNK_PAYLOAD_SIZE;
        if (offset + chunk_len > PKT_LEN) {
//            printf("SPI chunk overflow\n");
            continue;
        }

        memcpy(rx_packet + offset, &chunk_buf[4], chunk_len);
        total_received += chunk_len;
        matrix[seq] = 1;

//        printf("ch %u/%u %02X %02X\n", seq+1, total_chunks, chunk_buf[4], chunk_buf[5]);
        if (seq+1 == total_chunks) {
            return ESP_OK;
        }

        vTaskDelay(pdMS_TO_TICKS(1));
    }

    return ESP_FAIL;
}

void spi_slave_send_packet(const uint8_t *data)
{
    uint8_t tx[SPI_CHUNK_SIZE];

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

//        esp_err_t r =
//            spi_slave_transmit(SPI_HOST, &t, portMAX_DELAY);

        esp_err_t r = spi_slave_queue_trans(SPI_HOST, &t, portMAX_DELAY);
        if (r != ESP_OK)
            return;

        spi_slave_transaction_t *ret;
        r = spi_slave_get_trans_result(SPI_HOST, &ret, portMAX_DELAY);

        if (r == ESP_OK) {
            ESP_LOGI(TAG, "Sent chunk %u", seq);
//            vTaskDelay(pdMS_TO_TICKS(200));
        }
        else {
            return;
        }

        offset += chunk_len;
    }
    ESP_LOGI(TAG, "Sent packet");
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

//    dump_bytes(spi_tx_buf, off);

    spi_slave_send_packet(spi_tx_buf);

    return ESP_OK;
}

/**
 * @brief Receive IPv4 packet from SPI master
 *
 * @param out_buf Output buffer
 * @param timeout_ms receive timeout in ms
 *
 * @return ESP_OK if packet received
 */
static esp_err_t spi_recv_ip(uint8_t *out_buf, uint16_t *length, TickType_t timeout_ms)
{
    memset(spi_rx_buf, 0 ,sizeof(spi_rx_buf));
    esp_err_t ret = spi_slave_recv_packet(spi_rx_buf, timeout_ms);
    if (ret != ESP_OK) {
        return ret;
    }

//    dump_bytes(spi_rx_buf, PKT_LEN);

    spi_ip_hdr_t *hdr = (spi_ip_hdr_t *)spi_rx_buf;
    if (hdr->magic != SPI_MAGIC || hdr->version != SPI_PROTO_VERSION) {
        printf("Bad magic %08lX != %08X\n", hdr->magic, SPI_MAGIC);
        return ESP_FAIL;
    }

    if (hdr->length == 0 || hdr->length > PKT_LEN) {
        printf("Bad length %u\n", hdr->length);
        return ESP_FAIL;
    }

    uint8_t *payload = spi_rx_buf + sizeof(spi_ip_hdr_t);
    uint32_t rx_crc;
    memcpy(&rx_crc, payload + hdr->length, sizeof(rx_crc));

    if (rx_crc != esp_crc32_le(0, payload, hdr->length)) {
        printf("Bad crc\n");
        return ESP_FAIL;
    }

    memcpy(out_buf, payload, hdr->length);
    *length = hdr->length;

    printf("SPI packet recv OK\n");
    return ESP_OK;
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


//void app_main(void)
//{
//    int idx = 0;
//    spi_slave_init();
//    uint16_t length[3];

//    printf("=== TEST 1: master -> slave ===\n");
//    for (int i = 0; i < 3; i++) {
//        if (spi_recv_ip(rx_buf[idx], &length[idx], i==0 ? 5000 : 300) == ESP_OK) {
//            idx++;
//        }
//    }
//    for (int i = 0; i < idx; i++) {
//        ESP_LOGI(TAG, "\nReceived valid SPI [%d] packet (%d bytes):", i, length[i]);
//        dump_bytes(rx_buf[i], length[i]);
//    }

//    printf("=== TEST 2: master <- slave ===\n");
//    for (int i = 0; i < 3; i++) {
//        spi_send_ip(payload_pack, sizeof(payload_pack));
//        vTaskDelay(pdMS_TO_TICKS(200));
//    }


//    while (1) vTaskDelay(portMAX_DELAY);
//}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

//    esp_log_level_set("spi_slave", ESP_LOG_NONE);

    spi_slave_init();

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
