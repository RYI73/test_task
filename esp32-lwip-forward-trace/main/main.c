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
#include <stdint.h>

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

#include "lwip/netif.h"
#include "lwip/ip4.h"
#include "lwip/pbuf.h"
#include "lwip/err.h"

#include "logs.h"
#include "defaults.h"
#include "error_code.h"
#include "spi_helpers.h"
#include "network_helpers.h"
#include "gpio_helpers.h"
#include "types.h"

/***********************************************************************************************/
static EventGroupHandle_t wifi_event_group = NULL;
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
/* Internal functions                                                                          */
/***********************************************************************************************/
/**
 * @brief Initialize the Non-Volatile Storage (NVS) flash
 *
 * This function initializes the ESP32 NVS partition used for WiFi and system settings.
 * If the NVS partition has no free pages or a new version is found, it erases
 * the flash and reinitializes it.
 *
 * @return RESULT_OK on successful initialization,
 *         RESULT_INTERNAL_ERROR on failure (including erase failure).
 *
 * @note Logs warnings if NVS needs erasing, and logs errors on failure.
 */
static int nvs_init(void)
{
    int result = RESULT_OK;
    esp_err_t ret = nvs_flash_init();

    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        log_msg(LOG_WARNING, "NVS flash init: no free pages or new version, erasing...");
        ret = nvs_flash_erase();
        if (ret != ESP_OK) {
            log_msg(LOG_ERR, "Failed to erase NVS flash: %d", ret);
            result = RESULT_INTERNAL_ERROR;
            return result;
        }

        ret = nvs_flash_init();
    }

    if (ret != ESP_OK) {
        log_msg(LOG_ERR, "NVS flash init failed: %d", ret);
        result = RESULT_INTERNAL_ERROR;
    } else {
        log_msg(LOG_INFO, "NVS flash initialized successfully");
    }

    return result;
}
/***********************************************************************************************/
/**
 * @brief Virtual network interface output function
 *
 * This function is called by lwIP when sending a packet through the virtual network interface.
 * It logs IPv4/TCP details and enqueues the packet to be sent over SPI.
 *
 * @param netif  Pointer to the lwIP network interface (unused)
 * @param p      Pointer to the pbuf containing the packet
 * @param ipaddr Pointer to the destination IP address (unused)
 *
 * @return ERR_OK always
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
 * @brief SPI RX task
 *
 * This FreeRTOS task waits for SPI packets from the master, forwards IPv4 packets to lwIP,
 * and sends outgoing packets from the SPI TX queue back to the master.
 *
 * @param arg Pointer to the SPI file descriptor (int *)
 *
 * @note Runs indefinitely in a while(1) loop.
 * @note The SPI receive function is expected to return with packet length via the `length` pointer.
 */
static void spi_rx_task(void *arg)
{
    int *spi_fd_ptr = (int *)arg;
    int spi_fd = *spi_fd_ptr;

    static u8 buf[PKT_LEN*2] __attribute__((aligned(4)));
    u16 length = 0;
    queue_pkt_t tx_pkt = {0};

    while (1) {
        /* Wait for SPI transaction done event via semaphore */
        if (isOk(spi_receive(spi_fd, 0, buf, &length))) {
            log_msg(LOG_INFO, "Received valid SPI packet (%d bytes)", length);
            ipv4_forward(buf, length);
        }

        if (xQueueReceive(spi_tx_queue, &tx_pkt, 0)) {
            spi_send_packet(spi_fd, 0, tx_pkt.data, tx_pkt.len);
        }
    }
}
/***********************************************************************************************/
/* Main application function                                                                   */
/***********************************************************************************************/
void app_main(void)
{
    int spi_fd = -1;
    BaseType_t task_ret = 0;
    int result = RESULT_OK;

    do {
        result = nvs_init();
        if (!isOk(result)) {
            log_msg(LOG_ERR, "NVS Flash initialization error: %u", result);
            break;
        }
        log_msg(LOG_INFO, "NVS Flash initialized successfully");

        result = gpio_init(NULL, 0, NULL);
        if (!isOk(result)) {
            log_msg(LOG_ERR, "GPIO initialization error: %u", result);
            break;
        }
        log_msg(LOG_INFO, "GPIO initialized successfully");

        spi_tx_queue = xQueueCreate(SPI_TX_QUEUE_LEN, sizeof(queue_pkt_t));
        if (spi_tx_queue == NULL) {
            log_msg(LOG_ERR, "Unable to create queue 'spi_tx_queue'");
            result = RESULT_INTERNAL_ERROR;
            break;
        }

        result = spi_init(NULL, &spi_fd);
        if (!isOk(result)) {
            log_msg(LOG_ERR, "Spi initialization error: %u", result);
            break;
        }
        log_msg(LOG_INFO, "SPI initialized successfully");

        result = wifi_init(&wifi_event_group);
        if (!isOk(result)) {
            log_msg(LOG_ERR, "WiFi initialization error: %u", result);
            break;
        }
        log_msg(LOG_INFO, "WiFi initialized successfully");

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

        result = virtual_netif_init(&vnetif, virtual_netif_output);
        if (!isOk(result)) {
            log_msg(LOG_ERR, "Virtual netif initialization error: %u", result);
            break;
        }
        log_msg(LOG_INFO, "lwIP router + virtual sink ready");

        if (netif_default) {
            const ip4_addr_t *ip = netif_ip4_addr(netif_default);
            log_msg(LOG_INFO, "default netif: %c%c%d ip=%s",
                     netif_default->name[0], netif_default->name[1], netif_default->num,
                     ip ? ip4addr_ntoa(ip) : "none");
        }
        else {
            log_msg(LOG_ERR, "Default network interface not available, cannot start networking");
            result = RESULT_INTERNAL_ERROR;
            break;
        }

        task_ret = xTaskCreate(
            spi_rx_task,                   /* Task function */
            "spi_rx_task",                 /* Task name */
            SPI_RX_TASK_STACK_SIZE,        /* Stack size */
            (void *)&spi_fd,               /* Task argument: pointer to SPI FD */
            SPI_RX_TASK_PRIORITY,          /* Task priority */
            NULL                           /* Task handle not used */
        );

        if (task_ret != pdPASS) {
            log_msg(LOG_ERR, "Failed to create spi_rx_task");
            result = RESULT_INTERNAL_ERROR;
            break;
        }

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
