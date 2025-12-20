#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#include "lwip/netif.h"
#include "lwip/ip4.h"
#include "lwip/ip.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"


#include "lwip/netif.h"
#include "lwip/ip4.h"
#include "lwip/ip.h"
#include "lwip/pbuf.h"

#include "lwip/prot/ip4.h"
#include "lwip/prot/tcp.h"
#include "freertos/event_groups.h"

#define WIFI_GOT_IP_BIT BIT0

#define WIFI_SSID "Linksys00283"
#define WIFI_PASS "@Valovyi_Ruslan1973"

static const char *TAG = "ROUTER";
static EventGroupHandle_t wifi_event_group;

/* ===================== L3 + TCP LOGGER ===================== */

static void log_l3_tcp(struct pbuf *p)
{
    if (p->len < sizeof(struct ip_hdr)) return;

    struct ip_hdr *iph = (struct ip_hdr *)p->payload;
    if (IPH_V(iph) != 4) return;

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
}

/* ===================== VIRTUAL NETIF ===================== */

static struct netif vnetif;

static err_t virtual_netif_output(struct netif *netif,
                                  struct pbuf *p,
                                  const ip4_addr_t *ipaddr)
{
    log_l3_tcp(p);
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
              ip4_input);

    vnetif.flags |= NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;

    ESP_LOGI(TAG, "Virtual netif UP: 10.0.0.1/24");
}

static void on_got_ip(void *arg,
                      esp_event_base_t event_base,
                      int32_t event_id,
                      void *event_data)
{
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    esp_netif_ip_info_t *ip = &event->ip_info;

    ESP_LOGI(TAG, "ESP32 STA IP: " IPSTR, IP2STR(&ip->ip));
    ESP_LOGI(TAG, "GW: " IPSTR, IP2STR(&ip->gw));
    ESP_LOGI(TAG, "NETMASK: " IPSTR, IP2STR(&ip->netmask));
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
}

/* ===================== APP MAIN ===================== */

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

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
}
