#include <string.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/etharp.h"
#include "lwip/ip4.h"
#include "lwip/prot/ethernet.h"
#include "lwip/prot/ip.h"

#define WIFI_SSID "Linksys00283"
#define WIFI_PASS "@Valovyi_Ruslan1973"

static const char *TAG = "ESP32_LWIP_ROUTER";

static uint32_t cnt_all  = 0;
static uint32_t cnt_arp  = 0;
static uint32_t cnt_ip   = 0;
static uint32_t cnt_icmp = 0;
static uint32_t cnt_tcp  = 0;
static uint32_t cnt_udp  = 0;

/* ---- Fake MAC for ARP reply ---- */
static const uint8_t FAKE_MAC[6] = {0x02,0x00,0x00,0x00,0x00,0x02};
#define SPI_IPADDR_U32 0x0A000001  // 10.0.0.1

typedef struct {
    u16_t hwtype;
    u16_t proto;
    u8_t  hwlen;
    u8_t  protolen;
    u16_t opcode;
    u8_t  shwaddr[ETH_HWADDR_LEN];
    u8_t  sipaddr[4];
    u8_t  thwaddr[ETH_HWADDR_LEN];
    u8_t  tipaddr[4];
} etharp_hdr_t;

/* Dump first 64 bytes of the packet */
static void dump_bytes(const uint8_t *d, uint16_t len)
{
    uint16_t max = (len > 64) ? 64 : len;
    for (uint16_t i = 0; i < max; i++) {
        if ((i % 16) == 0) printf("\n%04X: ", i);
        printf("%02X ", d[i]);
    }
    printf("\n");
}

/* ---- WiFi STA init ---- */
static void init_wifi_sta(void)
{
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

    ESP_LOGI(TAG, "WiFi STA started");
}

/* ---- SPI netif ---- */
static struct netif spi_netif;

/* Dummy low-level output for SPI netif */
static err_t spi_netif_output(struct netif *netif, struct pbuf *p)
{
    // Тут ви будете надсилати pbuf через SPI на RPi
    (void)netif; (void)p;
    return ERR_OK;
}

/* Dummy link-level init for SPI netif */
static err_t spi_netif_init_cb(struct netif *netif)
{
    netif->hwaddr_len = 6;
    memcpy(netif->hwaddr, FAKE_MAC, 6);
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
    netif->output = etharp_output;
    netif->linkoutput = spi_netif_output;
    return ERR_OK;
}

/* Wrapper to match netif_input_fn signature */
static err_t spi_netif_input_cb(struct pbuf *p, struct netif *inp)
{
    if (!p || p->len < sizeof(struct eth_hdr)) return ERR_OK;

    struct eth_hdr *eth = (struct eth_hdr *)p->payload;
    uint16_t etype = lwip_htons(eth->type);

    cnt_all++;

    if (etype == ETHTYPE_ARP) {
        cnt_arp++;
        dump_bytes((uint8_t*)p->payload, p->len);

        etharp_hdr_t *arp = (etharp_hdr_t *)((uint8_t*)eth + SIZEOF_ETH_HDR);

        uint32_t tip =
            ((uint32_t)arp->tipaddr[0] << 24) |
            ((uint32_t)arp->tipaddr[1] << 16) |
            ((uint32_t)arp->tipaddr[2] << 8) |
            ((uint32_t)arp->tipaddr[3]);

        ESP_LOGI(TAG, "ARP packet received (WiFi)");
        ESP_LOGI(TAG, "Opcode: %s",
                 lwip_htons(arp->opcode) == ARP_REQUEST ? "REQUEST" : "REPLY");
        ESP_LOGI(TAG,
                 "Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X",
                 arp->shwaddr[0], arp->shwaddr[1], arp->shwaddr[2],
                 arp->shwaddr[3], arp->shwaddr[4], arp->shwaddr[5]);
        ESP_LOGI(TAG,
                 "Sender IP: %u.%u.%u.%u",
                 arp->sipaddr[0], arp->sipaddr[1],
                 arp->sipaddr[2], arp->sipaddr[3]);
        ESP_LOGI(TAG,
                 "Target IP: %u.%u.%u.%u",
                 arp->tipaddr[0], arp->tipaddr[1],
                 arp->tipaddr[2], arp->tipaddr[3]);

        /* ARP reply logic for 10.0.0.1 */
        if (lwip_htons(arp->opcode) == ARP_REQUEST && tip == SPI_IPADDR_U32) {
            ESP_LOGW(TAG, "ARP WHO-HAS 10.0.0.1 detected -> reply MAC 02:00:00:00:00:02");
            // Ваша логіка формування ARP reply сюди
        }
    }

    if (etype == ETHTYPE_IP) {
        cnt_ip++;
        struct ip_hdr *ip = (struct ip_hdr *)((uint8_t *)p->payload + sizeof(struct eth_hdr));
        uint8_t proto = IPH_PROTO(ip);

        if (proto == IP_PROTO_ICMP) cnt_icmp++;
        else if (proto == IP_PROTO_TCP) cnt_tcp++;
        else if (proto == IP_PROTO_UDP) cnt_udp++;

        dump_bytes((uint8_t*)p->payload, p->len);
    }

    /* Forward packet to SPI netif or WiFi */
    // Тут можна викликати netif->input для пересилки
    return ERR_OK;
}

/* ---- SPI netif init ---- */
static void spi_netif_init(void)
{
    ip4_addr_t ip, netmask, gw;
    IP4_ADDR(&ip, 10,0,0,2);
    IP4_ADDR(&netmask, 255,255,255,0);
    IP4_ADDR(&gw, 10,0,0,1);

    netif_add(&spi_netif, &ip, &netmask, &gw, NULL, spi_netif_init_cb, spi_netif_input_cb);
    netif_set_default(&spi_netif);
    netif_set_up(&spi_netif);

    ESP_LOGI(TAG, "SPI netif initialized at 10.0.0.2");
}

/* ---- Application entry point ---- */
void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    init_wifi_sta();

    vTaskDelay(pdMS_TO_TICKS(1500));

    spi_netif_init();

    while (1) {
        ESP_LOGI(TAG,
                 "Packets: ALL=%lu ARP=%lu IP=%lu ICMP=%lu TCP=%lu UDP=%lu",
                 cnt_all, cnt_arp, cnt_ip, cnt_icmp, cnt_tcp, cnt_udp);
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}
