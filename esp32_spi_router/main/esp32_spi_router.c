#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "lwip/sockets.h"
#include "driver/spi_slave.h"
#include "driver/gpio.h"
#include "esp_netif.h"

// ===== Wi-Fi config =====
#define WIFI_SSID "YOUR_WIFI_SSID"
#define WIFI_PASS "YOUR_WIFI_PASSWORD"
#define SERVER_PORT 5000

// ===== SPI pins =====
#define PIN_NUM_MISO 19
#define PIN_NUM_MOSI 23
#define PIN_NUM_SCLK 18
#define PIN_NUM_CS   5

// ===== Queue packet =====
typedef struct {
    uint8_t data[256];
    size_t len;
} packet_t;

QueueHandle_t wifi_to_spi_queue;
QueueHandle_t spi_to_wifi_queue;

static const char *TAG = "ESP32-CAM-MESH";
static int client_sock = -1; // TCP клієнт

// ===== Wi-Fi init =====
static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI(TAG, "Disconnected, retrying...");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
    }
}

void wifi_init_sta() {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(
        esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                           &wifi_event_handler, NULL, &instance_any_id)
    );
    ESP_ERROR_CHECK(
        esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                           &wifi_event_handler, NULL, &instance_got_ip)
    );

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "Wi-Fi init done");
}

// ===== SPI init (slave) =====
void spi_init() {
    spi_bus_config_t buscfg = {
        .mosi_io_num = PIN_NUM_MOSI,
        .miso_io_num = PIN_NUM_MISO,
        .sclk_io_num = PIN_NUM_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 256,
    };

    spi_slave_interface_config_t slvcfg = {
        .mode = 0,
        .spics_io_num = PIN_NUM_CS,
        .queue_size = 3,
        .flags = 0,
        .post_setup_cb = NULL,
        .post_trans_cb = NULL,
    };

    ESP_ERROR_CHECK(spi_slave_initialize(SPI2_HOST, &buscfg, &slvcfg, 1));
}

// ===== SPI RX Task =====
void spi_rx_task(void *arg) {
    uint8_t rxbuf[256];
    spi_slave_transaction_t t;
    packet_t pkt;

    while(1) {
        memset(&t, 0, sizeof(t));
        t.length = 8 * sizeof(rxbuf); // в бітах
        t.tx_buffer = NULL;
        t.rx_buffer = rxbuf;

        if (spi_slave_transmit(SPI2_HOST, &t, portMAX_DELAY) == ESP_OK) {
            pkt.len = sizeof(rxbuf);
            memcpy(pkt.data, rxbuf, pkt.len);
            xQueueSend(spi_to_wifi_queue, &pkt, portMAX_DELAY);
            ESP_LOGI(TAG, "SPI RX: %02X %02X %02X ...", rxbuf[0], rxbuf[1], rxbuf[2]);
        }
    }
}

// ===== SPI TX Task =====
void spi_tx_task(void *arg) {
    packet_t pkt;
    spi_slave_transaction_t t;

    while(1) {
        if (xQueueReceive(wifi_to_spi_queue, &pkt, portMAX_DELAY) == pdPASS) {
            memset(&t, 0, sizeof(t));
            t.length = 8 * pkt.len;
            t.tx_buffer = pkt.data;
            t.rx_buffer = NULL;
            if (spi_slave_transmit(SPI2_HOST, &t, portMAX_DELAY) == ESP_OK) {
                ESP_LOGI(TAG, "SPI TX sent %d bytes", pkt.len);
            }
        }
    }
}

// ===== Wi-Fi Server Task =====
#if 1
void wifi_server_task(void *arg) {
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        ESP_LOGE(TAG, "Unable to create listen socket");
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Bind failed");
        close(listen_sock);
        vTaskDelete(NULL);
        return;
    }

    if (listen(listen_sock, 1) < 0) {
        ESP_LOGE(TAG, "Listen failed");
        close(listen_sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "TCP server listening on port %d", SERVER_PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            ESP_LOGE(TAG, "Accept failed");
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            continue;
        }

        ESP_LOGI(TAG, "Client connected");

        packet_t pkt;
        int len;
        while ((len = recv(client_sock, pkt.data, sizeof(pkt.data), 0)) > 0) {
            pkt.len = len;
            xQueueSend(wifi_to_spi_queue, &pkt, portMAX_DELAY);
        }

        ESP_LOGI(TAG, "Client disconnected");
        close(client_sock);
    }

    // Якщо колись потрібно завершити сервер
    close(listen_sock);
}
#else
void wifi_server_task(void *arg) {
    while(1) {
        int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_sock < 0) {
            ESP_LOGE(TAG, "Unable to create socket");
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            continue;
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(SERVER_PORT);
        server_addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            ESP_LOGE(TAG, "Bind failed");
            close(listen_sock);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            continue;
        }

        if (listen(listen_sock, 1) < 0) {
            ESP_LOGE(TAG, "Listen failed");
            close(listen_sock);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            continue;
        }

        ESP_LOGI(TAG, "TCP server listening on port %d", SERVER_PORT);

        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            ESP_LOGE(TAG, "Accept failed");
            close(listen_sock);
            continue;
        }

        ESP_LOGI(TAG, "Client connected");

        packet_t pkt;
        int len;
        while((len = recv(client_sock, pkt.data, sizeof(pkt.data), 0)) > 0) {
            pkt.len = len;
            xQueueSend(wifi_to_spi_queue, &pkt, portMAX_DELAY);
        }

        ESP_LOGI(TAG, "Client disconnected");
        close(client_sock);
        client_sock = -1;
        close(listen_sock);
    }
}
#endif

// ===== Wi-Fi TX Task =====
void wifi_tx_task(void *arg) {
    packet_t pkt;

    while(1) {
        if (xQueueReceive(spi_to_wifi_queue, &pkt, portMAX_DELAY) == pdPASS) {
            if (client_sock >= 0) {
                send(client_sock, pkt.data, pkt.len, 0);
                ESP_LOGI(TAG, "Sent %d bytes to client", pkt.len);
            }
        }
    }
}

// ===== Main =====
void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    wifi_init_sta();
    spi_init();

    wifi_to_spi_queue = xQueueCreate(5, sizeof(packet_t));
    spi_to_wifi_queue = xQueueCreate(5, sizeof(packet_t));

    xTaskCreate(spi_rx_task, "SPI_RX", 4096, NULL, 10, NULL);
    xTaskCreate(spi_tx_task, "SPI_TX", 4096, NULL, 10, NULL);
    xTaskCreate(wifi_server_task, "WiFi_Server", 4096, NULL, 5, NULL);
    xTaskCreate(wifi_tx_task, "WiFi_TX", 4096, NULL, 5, NULL);

    ESP_LOGI(TAG, "ESP32-CAM TCP-SPI bridge started");
}
