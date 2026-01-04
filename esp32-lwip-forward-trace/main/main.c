/**
 * @file main.c
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
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_crc.h"

#include "driver/spi_slave.h"
#include "driver/gpio.h"

#include "lwip/netif.h"
#include "lwip/ip4.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
#include "lwip/err.h"
#include "lwip/prot/tcp.h"

#include "logs.h"
#include "defaults.h"
#include "error_code.h"
#include "spi_helpers.h"

/* ===================== GLOBALS ===================== */
static EventGroupHandle_t wifi_event_group;

static QueueHandle_t spi_tx_queue;
static struct netif vnetif;

/***********************************************************************************************/
/**
 * @struct queue_pkt_t
 * @brief Packet structure for internal queue
 */
typedef struct {
    u16 len;              /**< Real payload length */
    u8  data[PKT_LEN];    /**< Payload buffer */
} queue_pkt_t;

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
 * @brief Forward an IPv4 packet from SPI to lwIP stack
 * @param buf Pointer to packet
 * @param len Packet length
 */
static void spi_ipv4_forward(const uint8_t *buf, size_t len)
{
    if (len < sizeof(struct ip_hdr)) return;

    struct ip_hdr *iph = (struct ip_hdr *)buf;
    if (IPH_V(iph) != 4) {
        log_msg(LOG_WARNING, "Not IPv4");
        return;
    }

    uint16_t ip_hlen = IPH_HL_BYTES(iph);
    if (ip_hlen < sizeof(struct ip_hdr) || ip_hlen > len) {
        log_msg(LOG_WARNING, "Bad IP header length");
        return;
    }

    uint16_t l4_len = len - ip_hlen;
    uint8_t *l4 = (uint8_t *)buf + ip_hlen;

    struct pbuf *q = pbuf_alloc(PBUF_TRANSPORT, l4_len, PBUF_RAM);
    if (!q) {
        log_msg(LOG_WARNING, "pbuf_alloc failed");
        return;
    }

    memcpy(q->payload, l4, l4_len);

    ip4_addr_t src, dst;
    ip4_addr_copy(src, iph->src);
    ip4_addr_copy(dst, iph->dest);

    err_t err = ip4_output_if(q, &src, &dst, IPH_TTL(iph), IPH_TOS(iph), IPH_PROTO(iph), netif_default);
    if (err != ERR_OK) {
        log_msg(LOG_WARNING, "ip4_output_if failed: %d", err);
    }

    pbuf_free(q);
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

    log_msg(LOG_INFO, "IP proto=%d %d.%d.%d.%d -> %d.%d.%d.%d len=%d",
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

        log_msg(LOG_INFO, " TCP %s%s%s%s %u -> %u seq=%u ack=%u",
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
        queue_pkt_t pkt = {0};
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
    log_msg(LOG_INFO, "Virtual netif UP: 10.0.0.1/24");
}
/***********************************************************************************************/
/**
 * @brief Event handler for WiFi events
 */
static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        log_msg(LOG_INFO, "WiFi started, connecting...");
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        log_msg(LOG_WARNING, "WiFi disconnected, retry...");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        log_msg(LOG_INFO, "WiFi GOT IP: " IPSTR, IP2STR(&event->ip_info.ip));
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
    int *spi_fd_ptr = (int *)arg;
    int spi_fd = *spi_fd_ptr;

    uint8_t buf[PKT_LEN*2];
    uint16_t length = 0;
    queue_pkt_t tx_pkt = {0};

    while (1) {
        /* Wait for SPI transaction done event via semaphore */
        if (isOk(spi_receive(spi_fd, 0, buf, &length))) {
            log_msg(LOG_INFO, "Received valid SPI packet (%d bytes)", length);
            spi_ipv4_forward(buf, length);
        }

        if (xQueueReceive(spi_tx_queue, &tx_pkt, 0)) {
            spi_send_packet(spi_fd, 0, tx_pkt.data, tx_pkt.len);
        }
    }
}
/***********************************************************************************************/
/**
 * @brief Application entry point
 */
void app_main(void)
{
    int spi_fd = -1;
    int result = RESULT_OK;

    do {
        esp_err_t ret = nvs_flash_init();
        if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
            ESP_ERROR_CHECK(nvs_flash_erase());
            ret = nvs_flash_init();
        }
        ESP_ERROR_CHECK(ret);

        gpio_ready_init();

        ESP_ERROR_CHECK(esp_netif_init());
        ESP_ERROR_CHECK(esp_event_loop_create_default());

        spi_tx_queue = xQueueCreate(SPI_TX_QUEUE_LEN, sizeof(queue_pkt_t));
        assert(spi_tx_queue != NULL);

        result = spi_init(NULL, &spi_fd);
        if (!isOk(result)) {
            log_msg(LOG_ERR, "Spi initialization error: %u", result);
            break;
        }

        wifi_init();

        log_msg(LOG_INFO, "Waiting for IP...");
        EventBits_t bits = xEventGroupWaitBits(
            wifi_event_group,
            WIFI_GOT_IP_BIT,
            pdFALSE,
            pdTRUE,
            pdMS_TO_TICKS(WAIT_IP_TIMEOUT_MS)
        );

        if ((bits & WIFI_GOT_IP_BIT) == 0) {
            log_msg(LOG_ERR, "WiFi IP not acquired within %u ms, timeout", WAIT_IP_TIMEOUT_MS);
            result = RESULT_TIMEOUT;
            break;
        }

        virtual_netif_init();

        log_msg(LOG_INFO, "lwIP router + virtual sink ready");

        if (netif_default) {
            const ip4_addr_t *ip = netif_ip4_addr(netif_default);
            log_msg(LOG_INFO, "default netif: %c%c%d ip=%s",
                     netif_default->name[0], netif_default->name[1], netif_default->num,
                     ip ? ip4addr_ntoa(ip) : "none");
        }

        xTaskCreate(spi_rx_task, "spi_rx_task", 4096, &spi_fd, 3, NULL);
    } while(0);

    if (!isOk(result)) {
        while(1) {
            log_msg(LOG_INFO, "The ESP32 app has finished its work with error: %u", result);
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }

    log_msg(LOG_INFO, "The ESP32 app has started successfuly");
}
/***********************************************************************************************/
