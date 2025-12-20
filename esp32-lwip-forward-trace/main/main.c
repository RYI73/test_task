#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

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

/* =======================================================
 * CONFIG
 * ===================================================== */

#define WIFI_STA_SSID "YOUR_STA_SSID"
#define WIFI_STA_PASS "YOUR_STA_PASS"

#define SPI_NETIF_MTU 1400

static const char *TAG = "SPI_FWD";

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

    /* =================================================
     * ТУТ ТИ ВІДПРАВЛЯЄШ IP-ПАКЕТ ПО SPI
     *
     * p->payload  -> IPv4 header
     * p->tot_len  -> повна довжина IP пакета
     *
     * !!! НЕ БЛОКУЙ !!!
     * !!! НЕ pbuf_free() !!!
     * ================================================= */

    // spi_send(p->payload, p->tot_len);

    return ERR_OK;
}

/* ---- netif init ---- */
static err_t spi_netif_init(struct netif *netif)
{
    netif->name[0] = 's';
    netif->name[1] = 'p';

    netif->output     = etharp_output;
    netif->linkoutput = spi_linkoutput;

    netif->mtu   = SPI_NETIF_MTU;
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;

    ESP_LOGI(TAG, "SPI netif initialized");

    return ERR_OK;
}

/* ---- create SPI netif ---- */
static void spi_netif_create(void)
{
    ip4_addr_t ip, mask, gw;

    IP4_ADDR(&ip,   10, 10, 0, 1);
    IP4_ADDR(&mask, 255,255,255,0);
    IP4_ADDR(&gw,   0, 0, 0, 0);

    netif_add(&spi_netif,
              &ip,
              &mask,
              &gw,
              NULL,
              spi_netif_init,
              tcpip_input);

    netif_set_up(&spi_netif);
    netif_set_link_up(&spi_netif);

    ESP_LOGI(TAG, "SPI netif added: %c%c%d",
             spi_netif.name[0],
             spi_netif.name[1],
             spi_netif.num);
}

/* =======================================================
 * WIFI
 * ===================================================== */

static void wifi_init(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_sta();

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
    ESP_ERROR_CHECK(esp_wifi_connect());

    ESP_LOGI(TAG, "WiFi STA started");
}

/* =======================================================
 * APP MAIN
 * ===================================================== */

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());

    /* lwIP tcpip thread */
    tcpip_init(NULL, NULL);

    /* Wi-Fi = source of packets */
    wifi_init();

    /* small delay to ensure lwIP is ready */
    vTaskDelay(pdMS_TO_TICKS(1000));

    /* SPI virtual netif = forwarding destination */
    spi_netif_create();

    ESP_LOGI(TAG, "System ready: WiFi -> SPI forwarding");
}
