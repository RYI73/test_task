/*******************************************************************************
 *   @file   src/esp32/network_helpers.c
 *   @brief  Implementation of network helper functions.
 *   @author Ruslan
********************************************************************************
 * Copyright 2025(c).
*******************************************************************************/

/******************************************************************************/
/***************************** Include Files **********************************/
/******************************************************************************/

#include <stddef.h>

#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_err.h"
#include "esp_event_base.h"

#include "freertos/event_groups.h"

#include "lwip/ip4.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/inet.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/tcpip.h"

#include "network_helpers.h"
#include "logs.h"
#include "defaults.h"
#include "error_code.h"

/***********************************************************************************************/
/* Internal functions                                                                          */
/***********************************************************************************************/
/***********************************************************************************************/
/**
 * @brief WiFi event handler
 *
 * Handles STA start, disconnect, and GOT IP events.
 *
 * @param arg          User argument (unused)
 * @param event_base   ESP event base
 * @param event_id     Event ID
 * @param event_data   Pointer to event-specific data
 */
static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    EventGroupHandle_t wifi_event_group = (EventGroupHandle_t)arg;

    if (event_base == WIFI_EVENT) {
        if (event_id == WIFI_EVENT_STA_START) {
            log_msg(LOG_INFO, "WiFi started, connecting...");
            esp_wifi_connect();
        } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
            log_msg(LOG_WARNING, "WiFi disconnected, retrying...");
            esp_wifi_connect();
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        log_msg(LOG_INFO, "WiFi GOT IP: " IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(wifi_event_group, WIFI_GOT_IP_BIT);
    }
}
/***********************************************************************************************/
/**
 * @brief Initialize a virtual lwIP network interface
 *
 * This function is called by lwIP when adding a new network interface.
 * It sets the interface name, MTU, and standard flags for a virtual interface.
 *
 * @param netif Pointer to the lwIP network interface structure to initialize.
 *
 * @return ERR_OK on success.
 *
 * @note The netif name is set to "vn" (virtual network).
 * @note MTU is set to DEFAULT_MTU.
 * @note Flags set include:
 *       - NETIF_FLAG_UP: interface is administratively up
 *       - NETIF_FLAG_LINK_UP: link is considered up
 *       - NETIF_FLAG_BROADCAST: supports broadcast
 *       - NETIF_FLAG_ETHARP: supports ARP (needed for IPv4)
 */
static err_t virtual_netif_netif_init(struct netif *netif)
{
    netif->name[0] = 'v';
    netif->name[1] = 'n';
    netif->mtu = DEFAULT_MTU;
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP |
                   NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;

    return ERR_OK;
}
/***********************************************************************************************/
/* External functions                                                                          */
/***********************************************************************************************/
int ipv4_forward(const u8 *buf, size_t len)
{
    int result = RESULT_OK;

    do {
        if (!buf || len < sizeof(struct ip_hdr)) {
            log_msg(LOG_WARNING, "Invalid buffer or too small length");
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        struct ip_hdr *iph = (struct ip_hdr *)buf;
        if (IPH_V(iph) != 4) {
            log_msg(LOG_WARNING, "Not IPv4 packet");
            result = RESULT_TYPE_UNKNOWN_ERROR;
            break;
        }

        u16 ip_hlen = IPH_HL_BYTES(iph);
        if (ip_hlen < sizeof(struct ip_hdr) || ip_hlen > len) {
            log_msg(LOG_WARNING, "Bad IP header length: %u", ip_hlen);
            result = RESULT_BROKEN_MSG_ERROR;
            break;
        }

        u16 l4_len = len - ip_hlen;
        u8 *l4 = (u8 *)buf + ip_hlen;

        struct pbuf *q = pbuf_alloc(PBUF_TRANSPORT, l4_len, PBUF_RAM);
        if (!q) {
            log_msg(LOG_WARNING, "pbuf_alloc failed for %u bytes", l4_len);
            result = RESULT_MEMORY_ERROR;
            break;
        }

        memcpy(q->payload, l4, l4_len);

        ip4_addr_t src, dst;
        ip4_addr_copy(src, iph->src);
        ip4_addr_copy(dst, iph->dest);

        err_t err = ip4_output_if(q, &src, &dst, IPH_TTL(iph), IPH_TOS(iph), IPH_PROTO(iph), netif_default);
        if (err != ERR_OK) {
            log_msg(LOG_WARNING, "ip4_output_if failed: %d", err);
            result = RESULT_IO_ERROR;
        }

        pbuf_free(q);

    } while (0);

    return result;
}
/***********************************************************************************************/
void log_l3_tcp(struct pbuf *p)
{
    if (!p || p->len < sizeof(struct ip_hdr)) return;

    struct ip_hdr *iph = (struct ip_hdr *)p->payload;
    if (IPH_V(iph) != 4) return;

    u32 src = ip4_addr_get_u32(&iph->src);
    u32 dst = ip4_addr_get_u32(&iph->dest);

    log_msg(LOG_INFO, "IP proto=%d %d.%d.%d.%d -> %d.%d.%d.%d len=%d",
        IPH_PROTO(iph),
        src & 0xff, (src>>8)&0xff, (src>>16)&0xff, (src>>24)&0xff,
        dst & 0xff, (dst>>8)&0xff, (dst>>16)&0xff, (dst>>24)&0xff,
        p->tot_len
    );

    if (IPH_PROTO(iph) == IP_PROTO_TCP) {
        u16 ip_hlen = IPH_HL_BYTES(iph);
        if (p->len < ip_hlen + sizeof(struct tcp_hdr)) return;

        struct tcp_hdr *tcph = (struct tcp_hdr *)((u8 *)iph + ip_hlen);
        u8 f = TCPH_FLAGS(tcph);

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
int wifi_init(void *ptr_event_group)
{
    int result = RESULT_OK;
    EventGroupHandle_t *wifi_event_group = (EventGroupHandle_t *)ptr_event_group;

    do {
        if (!wifi_event_group) {
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        if (esp_netif_init() != ESP_OK) {
            log_msg(LOG_ERR, "esp_netif_init failed");
            result = RESULT_INTERNAL_ERROR;
            break;
        }

        if (esp_event_loop_create_default() != ESP_OK) {
            log_msg(LOG_ERR, "esp_event_loop_create_default failed");
            result = RESULT_INTERNAL_ERROR;
            break;
        }

        *wifi_event_group = xEventGroupCreate();
        if (!*wifi_event_group) {
            log_msg(LOG_ERR, "Failed to create WiFi event group");
            result = RESULT_MEMORY_ERROR;
            break;
        }

        if (!esp_netif_create_default_wifi_sta()) {
            log_msg(LOG_ERR, "Failed to create default WiFi STA interface");
            result = RESULT_INTERNAL_ERROR;
            break;
        }

        if (esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                       &wifi_event_handler, *wifi_event_group) != ESP_OK ||
            esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                       &wifi_event_handler, *wifi_event_group) != ESP_OK) {
            log_msg(LOG_ERR, "Failed to register WiFi event handlers");
            result = RESULT_INTERNAL_ERROR;
            break;
        }

        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        if (esp_wifi_init(&cfg) != ESP_OK) {
            log_msg(LOG_ERR, "WiFi init failed");
            result = RESULT_INTERNAL_ERROR;
            break;
        }

        wifi_config_t sta_cfg = {
            .sta = {
                .ssid = WIFI_SSID,
                .password = WIFI_PASS,
            }
        };

        if (esp_wifi_set_mode(WIFI_MODE_STA) != ESP_OK ||
            esp_wifi_set_config(WIFI_IF_STA, &sta_cfg) != ESP_OK ||
            esp_wifi_start() != ESP_OK ||
            esp_wifi_set_ps(WIFI_PS_NONE) != ESP_OK) {
            log_msg(LOG_ERR, "Failed to configure/start WiFi");
            result = RESULT_INTERNAL_ERROR;
            break;
        }

    } while (0);

    return result;
}
/***********************************************************************************************/
int virtual_netif_init(struct netif *netif, netif_output_fn output_func)
{
    int result = RESULT_OK;

    do {
        if (!netif || !output_func) {
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        ip4_addr_t ip, netmask, gw;
        IP4_ADDR(&ip,      10,0,0,1);
        IP4_ADDR(&netmask, 255,255,255,0);
        IP4_ADDR(&gw,      0,0,0,0);

        if (!netif_add(netif, &ip, &netmask, &gw,
                       NULL,
                       virtual_netif_netif_init,
                       tcpip_input)) {
            result = RESULT_INTERNAL_ERROR;
            break;
        }

        netif->output = output_func;
        netif->linkoutput = NULL;

        netif_set_up(netif);
        netif_set_link_up(netif);

    } while (0);

    return result;
}
/***********************************************************************************************/
