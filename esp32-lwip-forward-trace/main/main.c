/**
 * @file slave.c
 * @brief ESP32 SPI slave router forwarding IPv4 packets to lwIP stack
 *
 * This program initializes the ESP32 as an SPI slave, receives IPv4 packets
 * from SPI master, forwards them into the lwIP stack, and optionally
 * sends packets back to the master. It also handles WiFi STA connection
 * and implements a virtual network interface (vnetif) for routing.
 *
 * @author Ruslan
 * @date 2025-12-23
 */

#include <string.h>
#include <assert.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "esp_err.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_crc.h"

#include "driver/spi_slave.h"
#include "driver/gpio.h"

#include "lwip/netif.h"
#include "lwip/ip4.h"
#include "lwip/ip.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/icmp.h"
#include "lwip/inet_chksum.h"
#include "lwip/tcpip.h"
#include "lwip/err.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/tcp.h"

/* ===================== CONFIG ===================== */
#define TAG                         "L3_ROUTER"
#define SPI_HOST                    SPI2_HOST
#define PKT_LEN                     256
#define SPI_MAGIC                   0x49504657   /**< Magic constant ('IPFW') for SPI framing */
#define SPI_PROTO_VERSION           1
#define WIFI_GOT_IP_BIT             BIT0

/* SPI GPIOs */
#define GPIO_SPI_READY              GPIO_NUM_16
#define GPIO_MOSI                   13
#define GPIO_MISO                   12
#define GPIO_SCLK                   14
#define GPIO_CS                     15

#define SPI_TX_QUEUE_LEN            8

#define WIFI_SSID "D-Link"
#define WIFI_PASS "12345678"

/* ===================== GLOBALS ===================== */
static EventGroupHandle_t wifi_event_group;

static uint8_t spi_rx_buf[PKT_LEN*2];
static uint8_t spi_tx_buf[PKT_LEN*2];

static char *send_tx_buf = NULL;
static char *send_rx_buf = NULL;
static char *recv_tx_buf = NULL;
static char *recv_rx_buf = NULL;

static QueueHandle_t spi_tx_queue;
static struct netif vnetif;

/* ===================== STRUCTURES ===================== */
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

/**
 * @struct spi_pkt_t
 * @brief SPI packet structure for internal queue
 */
typedef struct {
    uint16_t len;              /**< Real payload length */
    uint8_t  data[PKT_LEN];    /**< Payload buffer */
} spi_pkt_t;

/***********************************************************************************************/
/**
 * @brief Initialize SPI handshake GPIO and enable pull-ups on SPI lines
 */
static void gpio_ready_init(void)
{
    gpio_config_t io = {
        .pin_bit_mask = BIT64(GPIO_SPI_READY),
        .mode = GPIO_MODE_OUTPUT,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };

    gpio_config(&io);
    gpio_set_level(GPIO_SPI_READY, 0);

    /* Enable pull-ups on SPI lines to prevent spurious pulses */
    gpio_set_pull_mode(GPIO_MOSI, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(GPIO_SCLK, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(GPIO_CS, GPIO_PULLUP_ONLY);
}
/***********************************************************************************************/
/**
 * @brief Dump memory in hex format (max 128 bytes)
 */
void dump_bytes(const uint8_t *buf, int len)
{
    for (int i = 0; i < len && i < 128; i += 16) {
        char line[96];
        int n = snprintf(line, sizeof(line), "%04x: ", i);
        for (int j = 0; j < 16 && i + j < len; j++) {
            n += snprintf(line + n, sizeof(line) - n, "%02x ", buf[i + j]);
        }
        ESP_LOGI("DUMP", "%s", line);
    }
}
/***********************************************************************************************/
/**
 * @brief Called after SPI transaction setup, sets handshake high
 */
void my_post_setup_cb(spi_slave_transaction_t *trans)
{
    gpio_set_level(GPIO_SPI_READY, 1);
}
/***********************************************************************************************/
/**
 * @brief Called after SPI transaction complete, sets handshake low
 */
void my_post_trans_cb(spi_slave_transaction_t *trans)
{
    gpio_set_level(GPIO_SPI_READY, 0);
}
/***********************************************************************************************/
/**
 * @brief Forward an IPv4 packet from SPI to lwIP stack
 * @param buf Pointer to packet
 * @param len Packet length
 */
static void spi_ipv4_forward(const uint8_t *buf, size_t len)
{
    if (len < sizeof(struct ip_hdr)) return;

    struct ip_hdr *iph = (struct ip_hdr *)buf;
    if (IPH_V(iph) != 4) {
        ESP_LOGI(TAG, "Not IPv4");
        return;
    }

    uint16_t ip_hlen = IPH_HL_BYTES(iph);
    if (ip_hlen < sizeof(struct ip_hdr) || ip_hlen > len) {
        ESP_LOGI(TAG, "Bad IP header length");
        return;
    }

    uint16_t l4_len = len - ip_hlen;
    uint8_t *l4 = (uint8_t *)buf + ip_hlen;

    struct pbuf *q = pbuf_alloc(PBUF_TRANSPORT, l4_len, PBUF_RAM);
    if (!q) {
        ESP_LOGI(TAG, "pbuf_alloc failed");
        return;
    }

    memcpy(q->payload, l4, l4_len);

    ip4_addr_t src, dst;
    ip4_addr_copy(src, iph->src);
    ip4_addr_copy(dst, iph->dest);

    err_t err = ip4_output_if(q, &src, &dst, IPH_TTL(iph), IPH_TOS(iph), IPH_PROTO(iph), netif_default);
    if (err != ERR_OK) {
        ESP_LOGW(TAG, "ip4_output_if failed: %d", err);
    }

    pbuf_free(q);
}
/***********************************************************************************************/
/**
 * @brief Initialize SPI slave interface and allocate DMA memory
 */
static void spi_slave_init(void)
{
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
        .post_setup_cb = my_post_setup_cb,
        .post_trans_cb = my_post_trans_cb
    };

    ESP_ERROR_CHECK(spi_slave_initialize(SPI_HOST, &buscfg, &slvcfg, SPI_DMA_CH_AUTO));

    send_tx_buf = spi_bus_dma_memory_alloc(SPI_HOST, PKT_LEN*2, 0);
    send_rx_buf = spi_bus_dma_memory_alloc(SPI_HOST, PKT_LEN*2, 0);
    recv_tx_buf = spi_bus_dma_memory_alloc(SPI_HOST, PKT_LEN*2, 0);
    recv_rx_buf = spi_bus_dma_memory_alloc(SPI_HOST, PKT_LEN*2, 0);
    assert(send_tx_buf && send_rx_buf && recv_tx_buf && recv_rx_buf);

    ESP_LOGI(TAG, "SPI slave initialized");
}
/***********************************************************************************************/
/**
 * @brief Send raw SPI packet to master
 * @param data Pointer to payload
 * @return ESP_OK if success
 */
esp_err_t spi_slave_send_packet(const uint8_t *data)
{
    if (!data || !send_tx_buf || !send_rx_buf) {
        ESP_LOGI(TAG, "Send NULL ptr.)", PKT_LEN);
        return ESP_FAIL;
    }

    memcpy(send_tx_buf, data, PKT_LEN);

    spi_slave_transaction_t t = {
        .length    = PKT_LEN * 8,
        .tx_buffer = send_tx_buf,
        .rx_buffer = send_rx_buf,
    };

    esp_err_t ret = spi_slave_transmit(SPI_HOST, &t, pdMS_TO_TICKS(1000));
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "SPI send failed: %d", ret);
        return ret;
    }

//    ESP_LOGI(TAG, "SPI packet sent (%d bytes)", PKT_LEN);
    return ESP_OK;
}
/***********************************************************************************************/
/**
 * @brief Receive raw SPI packet from master
 * @param rx_packet Pointer to output buffer
 * @param timeout_ms Timeout in ms
 * @return ESP_OK if success
 */
esp_err_t spi_slave_recv_packet(uint8_t *rx_packet, TickType_t timeout_ms)
{
    if (!rx_packet || !recv_tx_buf || !recv_rx_buf) {
        ESP_LOGI(TAG, "Recv NULL ptr.)", PKT_LEN);
        return ESP_FAIL;
    }

    memset(recv_rx_buf, 0, PKT_LEN);

    spi_slave_transaction_t t = {
        .length    = PKT_LEN * 8,
        .tx_buffer = recv_tx_buf,
        .rx_buffer = recv_rx_buf,
    };

    esp_err_t ret = spi_slave_transmit(SPI_HOST, &t, timeout_ms);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "SPI recv failed: %d", ret);
        return ret;
    }

    memcpy(rx_packet, recv_rx_buf, PKT_LEN);
//    ESP_LOGI(TAG, "SPI packet received (%d bytes)", PKT_LEN);
    return ESP_OK;
}
/***********************************************************************************************/
/**
 * @brief Send IPv4 packet to SPI master with header + CRC32
 */
static esp_err_t spi_send_ip(const uint8_t *data, size_t len)
{
    if (!data || len == 0 || len > PKT_LEN - sizeof(spi_ip_hdr_t)) return ESP_ERR_INVALID_ARG;

    spi_ip_hdr_t hdr = { .magic = SPI_MAGIC, .version = SPI_PROTO_VERSION, .flags = 0, .length = len };
    uint32_t crc = esp_crc32_le(0, data, len);
    size_t off = 0;

    memcpy(&spi_tx_buf[off], &hdr, sizeof(hdr)); off += sizeof(hdr);
    memcpy(&spi_tx_buf[off], data, len);         off += len;
    memcpy(&spi_tx_buf[off], &crc, sizeof(crc)); off += sizeof(crc);

    return spi_slave_send_packet(spi_tx_buf);
}
/***********************************************************************************************/
/**
 * @brief Receive IPv4 packet from SPI master with CRC check
 */
static esp_err_t spi_recv_ip(uint8_t *out_buf, uint16_t *length, TickType_t timeout_ms)
{
    memset(spi_rx_buf, 0, sizeof(spi_rx_buf));
    esp_err_t ret = spi_slave_recv_packet(spi_rx_buf, timeout_ms);
    if (ret != ESP_OK) return ret;

    spi_ip_hdr_t *hdr = (spi_ip_hdr_t *)spi_rx_buf;
    if (hdr->magic != SPI_MAGIC || hdr->version != SPI_PROTO_VERSION) return ESP_FAIL;

    if (hdr->length == 0 || hdr->length > PKT_LEN - sizeof(spi_ip_hdr_t) - sizeof(uint32_t)) return ESP_FAIL;

    uint8_t *payload = spi_rx_buf + sizeof(spi_ip_hdr_t);
    uint32_t rx_crc;
    memcpy(&rx_crc, payload + hdr->length, sizeof(rx_crc));

    if (rx_crc != esp_crc32_le(0, payload, hdr->length)) return ESP_FAIL;

    memcpy(out_buf, payload, hdr->length);
    *length = hdr->length;

    return ESP_OK;
}
/***********************************************************************************************/
/**
 * @brief Log IPv4 and TCP packet details for debugging.
 *
 * This function inspects the provided pbuf and prints information about
 * the IPv4 header (source, destination, protocol) and TCP header (flags,
 * ports, sequence and acknowledgment numbers) if the packet is TCP.
 *
 * @param p Pointer to the pbuf containing the packet. The pbuf must
 *          contain at least the IPv4 header.
 *
 * @note Only IPv4 packets are processed. Non-IPv4 packets are ignored.
 * @note TCP fields are logged only if the packet's protocol is TCP and
 *       the pbuf length is sufficient to contain a TCP header.
 */
void log_l3_tcp(struct pbuf *p)
{
    if (p->len < sizeof(struct ip_hdr)) return;

    struct ip_hdr *iph = (struct ip_hdr *)p->payload;
    if (IPH_V(iph) != 4) return;

    uint32_t src = ip4_addr_get_u32(&iph->src);
    uint32_t dst = ip4_addr_get_u32(&iph->dest);

    ESP_LOGI(TAG, "IP proto=%d %d.%d.%d.%d -> %d.%d.%d.%d len=%d",
        IPH_PROTO(iph),
        src & 0xff, (src>>8)&0xff, (src>>16)&0xff, (src>>24)&0xff,
        dst & 0xff, (dst>>8)&0xff, (dst>>16)&0xff, (dst>>24)&0xff,
        p->tot_len
    );

    if (IPH_PROTO(iph) == IP_PROTO_TCP) {
        uint16_t ip_hlen = IPH_HL_BYTES(iph);
        if (p->len < ip_hlen + sizeof(struct tcp_hdr)) return;

        struct tcp_hdr *tcph = (struct tcp_hdr *)((uint8_t *)iph + ip_hlen);
        uint8_t f = TCPH_FLAGS(tcph);

        ESP_LOGI(TAG, " TCP %s%s%s%s %u -> %u seq=%u ack=%u",
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
}
/***********************************************************************************************/
/**
 * @brief Output function for virtual netif
 */
static err_t virtual_netif_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    (void)netif;
    (void)ipaddr;

    log_l3_tcp(p);

    if (p->tot_len < PKT_LEN) {
        spi_pkt_t pkt = {0};
        pkt.len = p->tot_len;
        pbuf_copy_partial(p, pkt.data, pkt.len, 0);

        xQueueSend(spi_tx_queue, &pkt, 0);
    }
    return ERR_OK;
}
/***********************************************************************************************/
/**
 * @brief Initialize virtual netif structure
 */
static err_t virtual_netif_netif_init(struct netif *netif)
{
    netif->name[0] = 'v';
    netif->name[1] = 'n';
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP | NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;
    netif->output = virtual_netif_output;
    netif->linkoutput = NULL;
    return ERR_OK;
}
/***********************************************************************************************/
/**
 * @brief Add and configure virtual netif in lwIP
 */
static void virtual_netif_init(void)
{
    ip4_addr_t ip, netmask, gw;
    IP4_ADDR(&ip,      10,0,0,1);
    IP4_ADDR(&netmask, 255,255,255,0);
    IP4_ADDR(&gw,      0,0,0,0);

    netif_add(&vnetif, &ip, &netmask, &gw, NULL, virtual_netif_netif_init, tcpip_input);
    vnetif.flags |= NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    ESP_LOGI(TAG, "Virtual netif UP: 10.0.0.1/24");
}
/***********************************************************************************************/
/**
 * @brief Event handler for WiFi events
 */
static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG, "WiFi started, connecting...");
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "WiFi disconnected, retry...");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "WiFi GOT IP: " IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(wifi_event_group, WIFI_GOT_IP_BIT);
    }
}
/***********************************************************************************************/
/**
 * @brief Initialize WiFi STA
 */
static void wifi_init(void)
{
    wifi_event_group = xEventGroupCreate();
    esp_netif_create_default_wifi_sta();

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));

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
/***********************************************************************************************/
/**
 * @brief Task to receive SPI packets and forward to lwIP
 */
static void spi_rx_task(void *arg)
{
    (void)arg;

    uint8_t buf[PKT_LEN*2];
    uint16_t length = 0;
    spi_pkt_t tx_pkt = {0};

    while (1) {
        if (spi_recv_ip(buf, &length, pdMS_TO_TICKS(1000)) == ESP_OK && length != 0) {
            ESP_LOGI(TAG, "\nReceived valid SPI packet (%d bytes):", length);
//            dump_bytes(buf, length);
            spi_ipv4_forward(buf, length);
        }

        if (xQueueReceive(spi_tx_queue, &tx_pkt, 0)) {
            spi_send_ip(tx_pkt.data, tx_pkt.len);
        }

        vTaskDelay(pdMS_TO_TICKS(5));
    }
}
/***********************************************************************************************/
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

    gpio_ready_init();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    spi_tx_queue = xQueueCreate(SPI_TX_QUEUE_LEN, sizeof(spi_pkt_t));
    assert(spi_tx_queue != NULL);

    spi_slave_init();
    wifi_init();

    ESP_LOGI(TAG, "Waiting for IP...");
    xEventGroupWaitBits(wifi_event_group, WIFI_GOT_IP_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    virtual_netif_init();

    ESP_LOGI(TAG, "lwIP router + virtual sink ready");

    if (netif_default) {
        const ip4_addr_t *ip = netif_ip4_addr(netif_default);
        ESP_LOGI(TAG, "default netif: %c%c%d ip=%s",
                 netif_default->name[0], netif_default->name[1], netif_default->num,
                 ip ? ip4addr_ntoa(ip) : "none");
    }

    memset(send_tx_buf, 0, PKT_LEN);

    xTaskCreate(spi_rx_task, "spi_rx_task", 4096, NULL, 3, NULL);
}
/***********************************************************************************************/
