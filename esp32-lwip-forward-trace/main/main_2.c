#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#include "lwip/netif.h"
#include "lwip/ip4.h"
#include "lwip/pbuf.h"
#include "esp_netif_net_stack.h"

static const char *TAG = "FWD_TRACE";

/* Оригінальні callbacks */
static netif_input_fn  orig_input  = NULL;
static netif_output_fn orig_output = NULL;

/* ---------- IPv4 лог ---------- */
static void log_ipv4_packet(const char *dir,
                            struct netif *netif,
                            struct pbuf *p)
{
    if (!p || p->len < sizeof(struct ip_hdr)) return;

    struct ip_hdr *iph = (struct ip_hdr *)p->payload;
    if (IPH_V(iph) != 4) return;

    ip4_addr_t src, dst;
    ip4_addr_copy(src, iph->src);
    ip4_addr_copy(dst, iph->dest);

    ESP_LOGI(TAG,
        "[%s] netif=%c%c%d %s -> %s proto=%d ttl=%d len=%d",
        dir,
        netif->name[0], netif->name[1], netif->num,
        ip4addr_ntoa(&src),
        ip4addr_ntoa(&dst),
        IPH_PROTO(iph),
        IPH_TTL(iph),
        p->tot_len);
}

/* ---------- input wrapper ---------- */
static err_t my_netif_input(struct pbuf *p, struct netif *netif)
{
    log_ipv4_packet("IN ", netif, p);
    return orig_input(p, netif);
}

/* ---------- output wrapper ---------- */
static err_t my_netif_output(struct netif *netif,
                             struct pbuf *p,
                             const ip4_addr_t *ipaddr)
{
    log_ipv4_packet("OUT", netif, p);
    return orig_output(netif, p, ipaddr);
}

/* ---------- hook ---------- */
static void hook_netif(esp_netif_t *esp_netif)
{
    struct netif *lwip_netif = esp_netif_get_netif_impl(esp_netif);
    if (!lwip_netif) return;

    ESP_LOGI(TAG, "Hooking %c%c%d",
             lwip_netif->name[0],
             lwip_netif->name[1],
             lwip_netif->num);

    orig_input  = lwip_netif->input;
    orig_output = lwip_netif->output;

    lwip_netif->input  = my_netif_input;
    lwip_netif->output = my_netif_output;
}

/*
static void hook_netif(esp_netif_t *esp_netif)
{
    struct netif *lwip_netif =
        esp_netif_get_netif_from_esp_netif(esp_netif);

    if (!lwip_netif) {
        ESP_LOGW(TAG, "No lwIP netif");
        return;
    }

    ESP_LOGI(TAG, "Hooking %c%c%d",
             lwip_netif->name[0],
             lwip_netif->name[1],
             lwip_netif->num);

    orig_input  = lwip_netif->input;
    orig_output = lwip_netif->output;

    lwip_netif->input  = my_netif_input;
    lwip_netif->output = my_netif_output;
}
*/
/* ---------- Wi-Fi ---------- */
static void wifi_init(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_sta();
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t sta_cfg = {
        .sta = {
            .ssid = "YOUR_STA_SSID",
            .password = "YOUR_STA_PASS",
        }
    };

    wifi_config_t ap_cfg = {
        .ap = {
            .ssid = "ESP32_AP",
            .ssid_len = 0,
            .password = "12345678",
            .channel = 6,
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK
        }
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_cfg));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
}

/* ---------- main ---------- */
void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    wifi_init();

    vTaskDelay(pdMS_TO_TICKS(2000));

    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_t *ap  = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");

    hook_netif(sta);
    hook_netif(ap);

    ESP_LOGI(TAG, "Forward trace ready");
}
