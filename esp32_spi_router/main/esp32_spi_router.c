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
#include "lwip/ip4_addr.h"
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

static err_t (*orig_input)(struct pbuf *p, struct netif *inp) = NULL;

#define SPI_IPADDR_U32 0x0A000002  // 10.0.0.2
#define SPI_NETMASK_U32 0xFFFFFF00 // 255.255.255.0
#define SPI_GW_U32 0x0A000001      // 10.0.0.1

static struct netif spi_netif;

/* Fake MAC we respond to ARP requests */
static const uint8_t FAKE_MAC[6] = {0x02,0x00,0x00,0x00,0x00,0x02};

/* ---- Dump first 64 bytes of a packet ---- */
static void dump_bytes(const uint8_t *d, uint16_t len)
{
    uint16_t max = (len > 64) ? 64 : len;
    for (uint16_t i = 0; i < max; i++) {
        if ((i % 16) == 0) printf("\n%04X: ", i);
        printf("%02X ", d[i]);
    }
    printf("\n");
}

/* ---- lwIP input hook ---- */
static err_t netif_input_cb(struct pbuf *p, struct netif *inp)
{
    cnt_all++;
    if (!p || p->len < sizeof(struct eth_hdr)) return orig_input(p, inp);

    struct eth_hdr *eth = (struct eth_hdr *)p->payload;
    uint16_t etype = lwip_htons(eth->type);

    dump_bytes(p->payload, p->len); // дамп перед ARP/IP

    /* ---- ARP processing ---- */
    if (etype == ETHTYPE_ARP) {
        cnt_arp++;

        struct etharp_hdr *arp = (struct etharp_hdr *)((uint8_t*)eth + SIZEOF_ETH_HDR);

        /* ---- LWIP fix: використання макросів IP ---- */
        ip4_addr_t tip_ip, sip_ip;
        IP4_ADDR(&tip_ip,
                 ip4_addr1(&arp->dipaddr),
                 ip4_addr2(&arp->dipaddr),
                 ip4_addr3(&arp->dipaddr),
                 ip4_addr4(&arp->dipaddr));
        IP4_ADDR(&sip_ip,
                 ip4_addr1(&arp->sipaddr),
                 ip4_addr2(&arp->sipaddr),
                 ip4_addr3(&arp->sipaddr),
                 ip4_addr4(&arp->sipaddr));

        ESP_LOGI(TAG, "ARP packet received (WiFi)");
        ESP_LOGI(TAG, "Opcode: %s",
                 lwip_htons(arp->opcode) == ARP_REQUEST ? "REQUEST" : "REPLY");
        ESP_LOGI(TAG,
                 "Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X",
                 arp->shwaddr.addr[0], arp->shwaddr.addr[1], arp->shwaddr.addr[2],
                 arp->shwaddr.addr[3], arp->shwaddr.addr[4], arp->shwaddr.addr[5]);
        ESP_LOGI(TAG,
                 "Sender IP: %u.%u.%u.%u",
                 ip4_addr1(&arp->sipaddr),
                 ip4_addr2(&arp->sipaddr),
                 ip4_addr3(&arp->sipaddr),
                 ip4_addr4(&arp->sipaddr));
        ESP_LOGI(TAG,
                 "Target IP: %u.%u.%u.%u",
                 ip4_addr1(&arp->dipaddr),
                 ip4_addr2(&arp->dipaddr),
                 ip4_addr3(&arp->dipaddr),
                 ip4_addr4(&arp->dipaddr));

        /* ---- respond only for 10.0.0.1 ---- */
        if (lwip_htons(arp->opcode) == ARP_REQUEST &&
            tip_ip.addr == SPI_GW_U32) {
            ESP_LOGW(TAG, "ARP WHO-HAS 10.0.0.1 detected -> reply MAC 02:00:00:00:00:02");

            struct pbuf *reply = pbuf_alloc(PBUF_RAW, sizeof(struct eth_hdr) + sizeof(struct etharp_hdr), PBUF_RAM);
            if (reply) {
                struct eth_hdr *reth = (struct eth_hdr *)reply->payload;
                memcpy(reth->dest.addr, eth->src.addr, 6);
                memcpy(reth->src.addr, FAKE_MAC, 6);
                reth->type = lwip_htons(ETHTYPE_ARP);

                struct etharp_hdr *rarp = (struct etharp_hdr *)((uint8_t*)reth + SIZEOF_ETH_HDR);
                rarp->opcode = lwip_htons(ARP_REPLY);
                memcpy(rarp->shwaddr.addr, FAKE_MAC, 6);
                IP4_ADDR(&rarp->sipaddr,
                         10,0,0,1);           // наш gw
                memcpy(rarp->dhwaddr.addr, arp->shwaddr.addr, 6);
                IP4_ADDR(&rarp->dipaddr,
                         ip4_addr1(&arp->sipaddr),
                         ip4_addr2(&arp->sipaddr),
                         ip4_addr3(&arp->sipaddr),
                         ip4_addr4(&arp->sipaddr));

                etharp_output(inp, reply, &arp->sipaddr);
                pbuf_free(reply);
            }
        }
    }

    /* ---- IP packet parsing ---- */
    if (etype == ETHTYPE_IP) {
        cnt_ip++;
        struct ip_hdr *ip = (struct ip_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
        uint8_t proto = IPH_PROTO(ip);

        if (proto == IP_PROTO_ICMP) { cnt_icmp++; ESP_LOGI(TAG,"ICMP packet"); }
        else if (proto == IP_PROTO_TCP) { cnt_tcp++; ESP_LOGI(TAG,"TCP packet"); }
        else if (proto == IP_PROTO_UDP) { cnt_udp++; ESP_LOGI(TAG,"UDP packet"); }

        dump_bytes(p->payload, p->len);
    }

    return orig_input(p, inp);
}

/* ---- SPI netif init ---- */
static err_t spi_netif_init_cb(struct netif *netif)
{
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
    netif->hwaddr_len = 6;
    memcpy(netif->hwaddr, FAKE_MAC, 6);
    netif->output = etharp_output;
    return ERR_OK;
}

static void spi_netif_init(void)
{
    ip4_addr_t ip, netmask, gw;
    IP4_ADDR(&ip, 10,0,0,2);
    IP4_ADDR(&netmask, 255,255,255,0);
    IP4_ADDR(&gw, 10,0,0,1);

    netif_add(&spi_netif, &ip, &netmask, &gw, NULL, spi_netif_init_cb, etharp_input);
    netif_set_up(&spi_netif);
    netif_set_link_up(&spi_netif);
    netif_set_default(&spi_netif); // <-- додано

    ESP_LOGI(TAG, "SPI netif initialized at 10.0.0.2");
}

/* ---- Hook lwIP input (WiFi) ---- */
static void hook_lwip_input(void)
{
    esp_netif_t *wifi_handle = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!wifi_handle) { ESP_LOGE(TAG,"WiFi netif not found"); return; }

    struct netif *lwip_wifi = (struct netif*) esp_netif_get_netif_data(wifi_handle);
    orig_input = lwip_wifi->input;
    lwip_wifi->input = netif_input_cb;

    ESP_LOGI(TAG,"lwIP WiFi input hooked");
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

    ESP_LOGI(TAG,"WiFi STA started");
}

/* ---- Application entry point ---- */
void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    init_wifi_sta();

    vTaskDelay(pdMS_TO_TICKS(1500));

    spi_netif_init();
    hook_lwip_input();

    while (1) {
        ESP_LOGI(TAG,
                 "Packets: ALL=%lu ARP=%lu IP=%lu ICMP=%lu TCP=%lu UDP=%lu",
                 cnt_all, cnt_arp, cnt_ip, cnt_icmp, cnt_tcp, cnt_udp);
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}
