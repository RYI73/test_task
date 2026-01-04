#pragma once

#include "types.h"

/***********************************************************************************************/
/**
 * @brief Forward IPv4 packet received over SPI
 *
 * Extracts L4 payload and forwards it via default netif.
 *
 * @param buf   Pointer to IP packet
 * @param len   Length of buffer in bytes
 * @return RESULT_OK on success, or error code
 */
int ipv4_forward(const u8 *buf, size_t len);

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
void log_l3_tcp(struct pbuf *p);

/**
 * @brief Initialize WiFi subsystem in STA mode.
 *
 * This function initializes ESP-IDF networking and WiFi stack, creates
 * a WiFi event group, registers WiFi and IP event handlers, and starts
 * the WiFi station interface.
 *
 * The event group handle is created internally and returned to the caller
 * via the provided pointer. The event group is later used to signal WiFi
 * connection and IP acquisition events.
 *
 * @param[in,out] ptr_event_group
 * Pointer to a variable of type EventGroupHandle_t where the created
 * WiFi event group handle will be stored. Must not be NULL.
 *
 * @return RESULT_OK on success,
 *         RESULT_MEMORY_ERROR if event group allocation fails,
 *         RESULT_INTERNAL_ERROR on any ESP-IDF initialization error.
 */
int wifi_init(void* ptr_event_group);

/**
 * @brief Initialize virtual network interface
 *
 * @param netif          Pointer to netif structure
 * @param output_func    Function pointer for link output (implemented in main.c)
 *
 * @return RESULT_OK on success, or appropriate error code
 */
int virtual_netif_init(struct netif *netif, netif_output_fn output_func);
/***********************************************************************************************/
