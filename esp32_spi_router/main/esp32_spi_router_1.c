#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/etharp.h"
#include "lwip/ip4.h"
#include "lwip/prot/ethernet.h"
#include "lwip/prot/ip.h"
#include "lwip/icmp.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/ip4_addr.h"

#define SPI_IPADDR 0x0A000002  // 10.0.0.2
#define FAKE_MAC "\x02\x00\x00\x00\x00\x02"

#define WIFI_SSID "Linksys00283"
#define WIFI_PASS "@Valovyi_Ruslan1973"
#define FAKE_MAC "\x02\x00\x00\x00\x00\x02"
#define SPI_IPADDR 0x0A000002  // 10.0.0.2

static const char *TAG = "ESP32_LWIP_ROUTER";

static uint32_t cnt_all  = 0;
static uint32_t cnt_arp  = 0;
static uint32_t cnt_ip   = 0;
static uint32_t cnt_icmp = 0;
static uint32_t cnt_tcp  = 0;
static uint32_t cnt_udp  = 0;

// ---- Функція для дампу пакетів ----
static void dump_bytes(const uint8_t *d, uint16_t len)
{
    uint16_t max = (len > 64) ? 64 : len;
    for (uint16_t i = 0; i < max; i++) {
        if ((i % 16) == 0) printf("\n%04X: ", i);
        printf("%02X ", d[i]);
    }
    printf("\n");
}

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

// ---- Обробка Ethernet пакету ----
static void process_pbuf(struct pbuf *p)
{
    if (!p || p->len < sizeof(struct eth_hdr)) return;

    struct eth_hdr *eth = (struct eth_hdr *)p->payload;

    if (lwip_htons(eth->type) == ETHTYPE_ARP) {
        etharp_hdr_t *arp = (etharp_hdr_t *)((uint8_t*)eth + SIZEOF_ETH_HDR);

        // Check if ARP request is for SPI_IPADDR
        uint32_t tip_ip = ( ((uint32_t)arp->tipaddr[0] << 24) |
                            ((uint32_t)arp->tipaddr[1] << 16) |
                            ((uint32_t)arp->tipaddr[2] << 8)  |
                            ((uint32_t)arp->tipaddr[3]) );

        if ((tip_ip == SPI_IPADDR) && (lwip_htons(arp->opcode) == ARP_REQUEST)) {

            ESP_LOGI(TAG, "ARP request for SPI_IPADDR received, sending reply");

            // Swap Ethernet MACs
            uint8_t tmp_mac[ETH_HWADDR_LEN];
            memcpy(tmp_mac, eth->src.addr, ETH_HWADDR_LEN);
            memcpy(eth->src.addr, FAKE_MAC, ETH_HWADDR_LEN);
            memcpy(eth->dest.addr, tmp_mac, ETH_HWADDR_LEN);

            // ARP opcode
            arp->opcode = lwip_htons(ARP_REPLY);

            // Swap ARP MACs
            memcpy(arp->thwaddr, arp->shwaddr, ETH_HWADDR_LEN); // target MAC = requester MAC
            memcpy(arp->shwaddr, FAKE_MAC, ETH_HWADDR_LEN);     // source MAC = our MAC

            // Swap ARP IPs
            for (int i=0;i<4;i++) arp->tipaddr[i] = arp->sipaddr[i]; // target IP = requester IP
            arp->sipaddr[0] = 10; arp->sipaddr[1] = 0; arp->sipaddr[2] = 0; arp->sipaddr[3] = 2; // source IP = SPI_IPADDR

            dump_bytes(p->payload, p->len); // dump packet
        }
    }

    if (lwip_htons(eth->type) == ETHTYPE_IP) {
        struct ip_hdr *ip = (struct ip_hdr *)((uint8_t *)p->payload + sizeof(struct eth_hdr));
        uint8_t proto = IPH_PROTO(ip);

        if (proto == IP_PROTO_ICMP) {
            cnt_icmp++;
            ESP_LOGI(TAG, "ICMP packet");
        } else if (proto == IP_PROTO_TCP) {
            cnt_tcp++;
            ESP_LOGI(TAG, "TCP packet");
        } else if (proto == IP_PROTO_UDP) {
            cnt_udp++;
            ESP_LOGI(TAG, "UDP packet");
        }
        dump_bytes(p->payload, p->len);
    }
}

// ---- Імітація прийому пакетів з SPI netif ----
void spi_receive_task(void *arg)
{
    while (1) {
        // Тут реальні пакети будуть приходити через esp_netif_receive(spi_netif, buf, len, NULL)
        // Для тесту можна викликати process_pbuf(pbuf)
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

// ---- Ініціалізація WiFi STA ----
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

// ---- Основна функція ----
void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    init_wifi_sta();

    vTaskDelay(pdMS_TO_TICKS(1500));

    xTaskCreate(spi_receive_task, "spi_rx", 4096, NULL, 5, NULL);

    while (1) {
        ESP_LOGI(TAG,
                 "Packets: ALL=%lu ARP=%lu IP=%lu ICMP=%lu TCP=%lu UDP=%lu",
                 cnt_all, cnt_arp, cnt_ip, cnt_icmp, cnt_tcp, cnt_udp);
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}
