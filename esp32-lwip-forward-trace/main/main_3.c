#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/ip4.h"
#include "lwip/etharp.h"
#include "lwip/tcpip.h"

#include "lwip/raw.h"
#include "lwip/icmp.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/udp.h"
#include "lwip/prot/icmp.h"

/* =======================================================
 * CONFIG
 * ===================================================== */

#define WIFI_STA_SSID "Linksys00283"
#define WIFI_STA_PASS "@Valovyi_Ruslan1973"

#define SPI_NETIF_MTU 1400

static const char *TAG = "SPI_FWD";

/* =======================================================
 * EVENTS
 * ===================================================== */

static EventGroupHandle_t wifi_event_group;
#define WIFI_GOT_IP_BIT BIT0


//static void dump_bytes(const uint8_t *d, uint16_t len)
//{
//    uint16_t max = (len > 64) ? 64 : len;
//    for (uint16_t i = 0; i < max; i++) {
//        if ((i % 16) == 0) printf("\n%04X: ", i);
//        printf("%02X ", d[i]);
//    }
//    printf("\n");
//}

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


/* =======================================================
 * SPI NETIF
 * ===================================================== */

static struct netif spi_netif;

/* ---- TX: lwIP -> SPI ---- */
static err_t spi_linkoutput(struct netif *netif, struct pbuf *p)
{
    LWIP_UNUSED_ARG(netif);

    if (!p || p->len < sizeof(struct ip_hdr)) {
        return ERR_OK;
    }

    struct ip_hdr *iph = (struct ip_hdr *)p->payload;
    if (IPH_V(iph) != 4) {
        return ERR_OK;
    }

    ip4_addr_t src, dst;
    ip4_addr_copy(src, iph->src);
    ip4_addr_copy(dst, iph->dest);

    ESP_LOGI(TAG,
        "SPI TX: %s -> %s proto=%d ttl=%d len=%d",
        ip4addr_ntoa(&src),
        ip4addr_ntoa(&dst),
        IPH_PROTO(iph),
        IPH_TTL(iph),
        p->tot_len);

    /* Тут буде spi_send(p->payload, p->tot_len); */

    return ERR_OK;
}

//int lwip_hook_ip4_input(struct pbuf *p, struct netif *inp)
//{
//    struct ip_hdr iph;

//    if (!p || p->len < sizeof(struct ip_hdr)) {
//        return 0;
//    }

//    pbuf_copy_partial(p, &iph, sizeof(iph), 0);

//    if (IPH_V(&iph) != 4) {
//        return 0;
//    }

//    /* ЦІКАВИТЬ ЛИШЕ 10.0.0.2 */
//    if (iph.dest.addr == PP_HTONL(0x0A000002)) {

//        ip4_addr_t src, dst;
//        src.addr = iph.src.addr;
//        dst.addr = iph.dest.addr;

//        ESP_LOGW("FWD",
//            "FORWARD %s -> %s via SPI (len=%d)",
//            ip4addr_ntoa(&src),
//            ip4addr_ntoa(&dst),
//            p->tot_len
//        );

//        /* ❗ ТУТ ТИ ВІДПРАВЛЯЄШ В SPI */
//        /* spi_send(p->payload, p->tot_len); */

//        return 1;   // ❗ ЗУПИНИТИ lwIP
//    }

//    return 0;
//}

int lwip_hook_ip4_input(struct pbuf *p, struct netif *inp)
{
    ESP_LOGW("IP4_HOOK", "CALLED p=%p netif=%c%c%d",
             p,
             inp->name[0], inp->name[1], inp->num);
    return 0;
}

static err_t spi_ip4_output(struct netif *netif,
                            struct pbuf *p,
                            const ip4_addr_t *ipaddr)
{
    struct ip_hdr iph;
    ip4_addr_t src;

    if (!p || p->len < sizeof(struct ip_hdr)) {
        return ERR_OK;
    }

    /* безпечне копіювання IP header */
    pbuf_copy_partial(p, &iph, sizeof(iph), 0);

    /* packed → normal */
    src.addr = iph.src.addr;

    return ip4_output_if(
        p,
        &src,          // ✔ NORMAL ip4_addr_t
        ipaddr,        // dest
        IPH_TTL(&iph),
        IPH_TOS(&iph),
        IPH_PROTO(&iph),
        netif
    );
}



/* ---- netif init ---- */
static err_t spi_netif_init(struct netif *netif)
{
    netif->name[0] = 's';
    netif->name[1] = 'p';

//    netif->output     = etharp_output;
    netif->output     = spi_ip4_output;
    netif->linkoutput = spi_linkoutput;

    netif->mtu   = SPI_NETIF_MTU;
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;

    ESP_LOGI(TAG, "SPI netif initialized");
    return ERR_OK;
}

//static err_t spi_netif_input(struct pbuf *p, struct netif *netif)
//{
//    struct eth_hdr *eth = (struct eth_hdr *)p->payload;

//    ESP_LOGI("L2",
//        "ETH: %02x:%02x:%02x:%02x:%02x:%02x -> "
//        "%02x:%02x:%02x:%02x:%02x:%02x type=0x%04x len=%d",
//        eth->src.addr[0], eth->src.addr[1], eth->src.addr[2],
//        eth->src.addr[3], eth->src.addr[4], eth->src.addr[5],
//        eth->dest.addr[0], eth->dest.addr[1], eth->dest.addr[2],
//        eth->dest.addr[3], eth->dest.addr[4], eth->dest.addr[5],
//        htons(eth->type),
//        p->tot_len);

//    return netif->input(p, netif);
//}

static netif_input_fn orig_spi_input;

static err_t spi_netif_input(struct pbuf *p, struct netif *netif)
{
    if (!p) {
        return ERR_OK;
    }

    /* ---- L3 LOG (IP) ---- */
    if (p->len >= sizeof(struct ip_hdr)) {
        struct ip_hdr iph;
        pbuf_copy_partial(p, &iph, sizeof(iph), 0);

        if (IPH_V(&iph) == 4) {
            ip4_addr_t src, dst;
            ip4_addr_copy(src, iph.src);
            ip4_addr_copy(dst, iph.dest);

            ESP_LOGI("L3",
                "IP %s -> %s proto=%d len=%d",
                ip4addr_ntoa(&src),
                ip4addr_ntoa(&dst),
                IPH_PROTO(&iph),
                p->tot_len);
        }
    }

    /* ---- ВАЖЛИВО: передати далі ---- */
    return orig_spi_input(p, netif);
}

/* ---- create SPI netif ---- */
static void spi_netif_create(void)
{
    ip4_addr_t ip, mask, gw;

    IP4_ADDR(&ip,   10, 0, 0, 1);
    IP4_ADDR(&mask, 255,255,255,0);
    IP4_ADDR(&gw,   0, 0, 0, 0);

    netif_add(&spi_netif,
              &ip,
              &mask,
              &gw,
              NULL,
              spi_netif_init,
              tcpip_input);

    orig_spi_input = spi_netif.input;

    spi_netif.input = spi_netif_input;

//    spi_netif.flags |= NETIF_FLAG_IP_FORWARD;
    netif_set_up(&spi_netif);
    netif_set_link_up(&spi_netif);

    const ip4_addr_t *ip_a   = netif_ip4_addr(&spi_netif);
    const ip4_addr_t *mask_a = netif_ip4_netmask(&spi_netif);

    ESP_LOGI(TAG,
        "spi_netif: ip=" IPSTR " mask=" IPSTR " up=%d link=%d",
        IP2STR(netif_ip4_addr(&spi_netif)),
        IP2STR(netif_ip4_netmask(&spi_netif)),
        netif_is_up(&spi_netif),
        netif_is_link_up(&spi_netif));
}

/* =======================================================
 * WIFI EVENT HANDLER
 * ===================================================== */

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

/* =======================================================
 * WIFI INIT
 * ===================================================== */

static void wifi_init(void)
{
    wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

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
            .ssid = WIFI_STA_SSID,
            .password = WIFI_STA_PASS,
        }
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
}

//static u8_t raw_rx_cb(void *arg,
//                      struct raw_pcb *pcb,
//                      struct pbuf *p,
//                      const ip_addr_t *addr)
//{
//    LWIP_UNUSED_ARG(arg);
//    LWIP_UNUSED_ARG(pcb);
//    LWIP_UNUSED_ARG(addr);

//    if (!p || p->len < sizeof(struct ip_hdr)) {
//        return 0;
//    }

//    /* ip_hdr у lwIP packed → копіюємо */
//    struct ip_hdr iph;
//    pbuf_copy_partial(p, &iph, sizeof(iph), 0);

//    if (IPH_V(&iph) != 4) {
//        return 0;
//    }

//    ip4_addr_t src, dst;
//    ip4_addr_copy(src, iph.src);
//    ip4_addr_copy(dst, iph.dest);

//    u16_t ip_hdr_len = IPH_HL(&iph) * 4;
//    u8_t proto = IPH_PROTO(&iph);

//    dump_bytes(p->payload, p->len);

//    switch (proto) {

//    case IP_PROTO_ICMP: {
//        if (p->len < ip_hdr_len + sizeof(struct icmp_echo_hdr)) {
//            break;
//        }

//        struct icmp_echo_hdr icmp;
//        pbuf_copy_partial(p, &icmp, sizeof(icmp), ip_hdr_len);

//        ESP_LOGI("RAW",
//            "ICMP %s -> %s type=%d code=%d len=%d",
//            ip4addr_ntoa(&src),
//            ip4addr_ntoa(&dst),
//            ICMPH_TYPE(&icmp),
//            ICMPH_CODE(&icmp),
//            p->tot_len);
//        break;
//    }

//    case IP_PROTO_TCP: {
//        struct tcp_hdr tcp;
//        if (p->len < ip_hdr_len + sizeof(tcp)) {
//            break;
//        }

//        pbuf_copy_partial(p, &tcp, sizeof(tcp), ip_hdr_len);

//        ESP_LOGI("RAW",
//            "TCP  %s:%d -> %s:%d flags=0x%02x len=%d",
//            ip4addr_ntoa(&src), lwip_ntohs(tcp.src),
//            ip4addr_ntoa(&dst), lwip_ntohs(tcp.dest),
//            TCPH_FLAGS(&tcp),
//            p->tot_len);
//        break;
//    }

//    case IP_PROTO_UDP: {
//        struct udp_hdr udp;
//        if (p->len < ip_hdr_len + sizeof(udp)) {
//            break;
//        }

//        pbuf_copy_partial(p, &udp, sizeof(udp), ip_hdr_len);

//        ESP_LOGI("RAW",
//            "UDP  %s:%d -> %s:%d len=%d",
//            ip4addr_ntoa(&src), lwip_ntohs(udp.src),
//            ip4addr_ntoa(&dst), lwip_ntohs(udp.dest),
//            p->tot_len);
//        break;
//    }

//    default:
//        ESP_LOGI("RAW",
//            "IP   %s -> %s proto=%d len=%d",
//            ip4addr_ntoa(&src),
//            ip4addr_ntoa(&dst),
//            proto,
//            p->tot_len);
//        break;
//    }

//    //    return 0;   // НЕ ковтаємо, lwIP відповість на ping
//    return 1;   // ковтаємо
//}

static u8_t raw_rx_cb(void *arg,
                      struct raw_pcb *pcb,
                      struct pbuf *p,
                      const ip_addr_t *addr)
{
    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(pcb);
    LWIP_UNUSED_ARG(addr);

    if (!p || p->len < sizeof(struct ip_hdr)) {
        return 0;
    }

    /* IP header */
    struct ip_hdr iph;
    pbuf_copy_partial(p, &iph, sizeof(iph), 0);

    if (IPH_V(&iph) != 4) {
        return 0;
    }

    u16_t ip_hdr_len = IPH_HL(&iph) * 4;
    u8_t proto = IPH_PROTO(&iph);

    ip4_addr_t src, dst;
    ip4_addr_copy(src, iph.src);
    ip4_addr_copy(dst, iph.dest);

    dump_bytes(p->payload, p->len);

    switch (proto) {

    /* ================= ICMP ================= */
    case IP_PROTO_ICMP: {
        if (p->len < ip_hdr_len + sizeof(struct icmp_echo_hdr)) {
            break;
        }

        struct icmp_echo_hdr icmp;
        pbuf_copy_partial(p, &icmp, sizeof(icmp), ip_hdr_len);

        ESP_LOGI("RAW",
            "ICMP %s -> %s type=%d code=%d len=%d",
            ip4addr_ntoa(&src),
            ip4addr_ntoa(&dst),
            ICMPH_TYPE(&icmp),
            ICMPH_CODE(&icmp),
            p->tot_len);
        break;
    }

    /* ================= UDP ================= */
    case IP_PROTO_UDP: {
        if (p->len < ip_hdr_len + sizeof(struct udp_hdr)) {
            break;
        }

        struct udp_hdr udp;
        pbuf_copy_partial(p, &udp, sizeof(udp), ip_hdr_len);

        ESP_LOGI("RAW",
            "UDP  %s:%d -> %s:%d len=%d",
            ip4addr_ntoa(&src), lwip_ntohs(udp.src),
            ip4addr_ntoa(&dst), lwip_ntohs(udp.dest),
            p->tot_len);
        break;
    }

    /* ================= TCP ================= */
    case IP_PROTO_TCP: {
        if (p->len < ip_hdr_len + sizeof(struct tcp_hdr)) {
            break;
        }

        struct tcp_hdr tcp;
        pbuf_copy_partial(p, &tcp, sizeof(tcp), ip_hdr_len);

        u8_t flags = TCPH_FLAGS(&tcp);

        /* Загальний лог TCP */
        ESP_LOGI("RAW",
            "TCP  %s:%d -> %s:%d flags=%c%c%c%c%c%c seq=%"PRIu32" ack=%"PRIu32" len=%d",
            ip4addr_ntoa(&src), lwip_ntohs(tcp.src),
            ip4addr_ntoa(&dst), lwip_ntohs(tcp.dest),

            (flags & TCP_FIN) ? 'F' : '-',
            (flags & TCP_SYN) ? 'S' : '-',
            (flags & TCP_RST) ? 'R' : '-',
            (flags & TCP_PSH) ? 'P' : '-',
            (flags & TCP_ACK) ? 'A' : '-',
            (flags & TCP_URG) ? 'U' : '-',

            lwip_ntohl(tcp.seqno),
            lwip_ntohl(tcp.ackno),
            p->tot_len
        );

        /* === ЛОГ САМЕ TCP HANDSHAKE === */
        if ((flags & TCP_SYN) && !(flags & TCP_ACK)) {
            ESP_LOGW("TCP-HS", "SYN      %s:%d -> %s:%d",
                ip4addr_ntoa(&src), lwip_ntohs(tcp.src),
                ip4addr_ntoa(&dst), lwip_ntohs(tcp.dest));
        }
        else if ((flags & TCP_SYN) && (flags & TCP_ACK)) {
            ESP_LOGW("TCP-HS", "SYN-ACK  %s:%d -> %s:%d",
                ip4addr_ntoa(&src), lwip_ntohs(tcp.src),
                ip4addr_ntoa(&dst), lwip_ntohs(tcp.dest));
        }
        else if ((flags & TCP_ACK) && !(flags & TCP_SYN)) {
            ESP_LOGW("TCP-HS", "ACK      %s:%d -> %s:%d",
                ip4addr_ntoa(&src), lwip_ntohs(tcp.src),
                ip4addr_ntoa(&dst), lwip_ntohs(tcp.dest));
        }

        break;
    }

    /* ================= OTHER ================= */
    default:
        ESP_LOGI("RAW",
            "IP   %s -> %s proto=%d len=%d",
            ip4addr_ntoa(&src),
            ip4addr_ntoa(&dst),
            proto,
            p->tot_len);
        break;
    }

    /* 1 = packet consumed (не піде далі в lwIP) */
    return 1;
}

#include "lwip/udp.h"

static struct udp_pcb *udp;

static void udp_rx_cb(void *arg,
                      struct udp_pcb *pcb,
                      struct pbuf *p,
                      const ip_addr_t *addr,
                      u16_t port)
{
    ESP_LOGI("UDP",
        "RX %d bytes from %s:%d",
        p->len,
        ipaddr_ntoa(addr),
        port);

    pbuf_free(p);
}

void udp_test_init(void)
{
    udp = udp_new_ip_type(IPADDR_TYPE_V4);
    udp_bind(udp, IP4_ADDR_ANY, 25826);
    udp_recv(udp, udp_rx_cb, NULL);
}

static void raw_icmp_init(void)
{
    struct raw_pcb *pcb = raw_new(IP_PROTO_ICMP);
    if (!pcb) {
        ESP_LOGE("RAW", "raw_new failed");
        return;
    }

    raw_bind(pcb, IP_ADDR_ANY);
    raw_recv(pcb, raw_rx_cb, NULL);

    ESP_LOGI("RAW", "raw ICMP pcb registered");
}

static netif_input_fn orig_wifi_input;

static err_t wifi_netif_input(struct pbuf *p, struct netif *netif)
{
    if (p && p->len >= sizeof(struct ip_hdr)) {
        struct ip_hdr *iph = (struct ip_hdr *)p->payload;

        if (IPH_V(iph) == 4) {
            ip4_addr_t src, dst;
            ip4_addr_copy(src, iph->src);
            ip4_addr_copy(dst, iph->dest);

            ESP_LOGI("WIFI_L3",
                "IP %s -> %s proto=%d len=%d",
                ip4addr_ntoa(&src),
                ip4addr_ntoa(&dst),
                IPH_PROTO(iph),
                p->tot_len);
        }
    }

    return orig_wifi_input(p, netif);
}

/* =======================================================
 * APP MAIN
 * ===================================================== */

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());

    tcpip_init(NULL, NULL);

    raw_icmp_init();
    udp_test_init();

    wifi_init();

    ESP_LOGI(TAG, "Waiting for IP...");
    xEventGroupWaitBits(wifi_event_group,
                        WIFI_GOT_IP_BIT,
                        pdFALSE,
                        pdTRUE,
                        portMAX_DELAY);

    /* ТУТ netif_default ГАРАНТОВАНО ІСНУЄ */
    if (netif_default) {
        const ip4_addr_t *ip = netif_ip4_addr(netif_default);

        ESP_LOGI(TAG,
            "default netif: %c%c%d ip=%s",
            netif_default->name[0],
            netif_default->name[1],
            netif_default->num,
            ip ? ip4addr_ntoa(ip) : "none");
    } else {
        ESP_LOGE(TAG, "default netif is STILL NULL (unexpected)");
    }

    spi_netif_create();

//    esp_netif_t *wifi_esp = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
//    assert(wifi_esp);
//    struct netif *wifi_lwip =
//        (struct netif *)esp_netif_get_netif_impl(wifi_esp);
//    assert(wifi_lwip);


//    orig_wifi_input = wifi_lwip->input;
//    wifi_lwip->input = wifi_netif_input;


    ESP_LOGI(TAG, "IP_FORWARD=%d", IP_FORWARD);
    ESP_LOGI(TAG, "System ready: WiFi -> SPI forwarding");
}
