#pragma once

/***********************************************************************************************/
#define MAX_DUMP_BUFFER_SIZE                    (128)
/***********************************************************************************************/
#define SOCKET_READ_TIMEOUT_MS                  (2000)
/***********************************************************************************************/
/** Localhost IPv4 address (string form) */
#define LOCALHOST_ADDR                          "127.0.0.1"
/** INADDR_ANY IPv4 address (string form) */
#define ANY_ADDR                                "0.0.0.0"
/** TUN IPv4 address (string form) */
#define TUN_ADDR                                "10.0.0.1"
/** Server IPv4 address (string form) */
#define SERVER_ADDR                             "10.0.0.2"
/** Server TCP port */
#define SERVER_PORT                             (12345)
/** Message sent to server */
#define CLIENT_MESSAGE                          "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur vel sapien eget sapien gravida ornare."
#define WRONG_MESSAGE                           "Wrong message for testing."
#define CLIENT_ARRAY                                                                                  \
{                                                                                                     \
    0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,   \
    0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,   \
    0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,   \
    0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF    \
}
#define WRONG_ARRAY                                                                                   \
{                                                                                                     \
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,   \
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,   \
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,   \
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF    \
}
/** Maximum size of packet */
#define PACKET_SIZE                             (256)
/** Maximum number of concurrent clients */
#define MAX_CLIENTS                             (5)
/** poll() timeout in milliseconds */
#define CONNECT_TIMEOUT_MS                      (500)
#define POLL_TIMEOUT_MS                         (500)
#define WAIT_IP_TIMEOUT_MS                      (60000)

/** SPI protocol config */
#define SPI_MAGIC                               (0x49504657)      /**< Magic constant ('IPFW') for SPI framing */
#define SPI_PROTO_VERSION                       (1)

/** WiFi SSID config */
//#define WIFI_SSID                               "YOUR_WIFI_SSID"
//#define WIFI_PASS                               "YOUR_PASSWORD"
#define WIFI_SSID                               "D-Link"
#define WIFI_PASS                               "12345678"

/** Maximum size of packet */
#define DEFAULT_MTU                             (1500)

/***********************************************************************************************/
/*  Raspberry Pi defines                                                                              */
/***********************************************************************************************/
/** SPI device settings */
#define SPI_DEVICE                              "/dev/spidev0.0"
#define SPI_MODE                                (0)
#define SPI_BITS                                (8)
#define SPI_SPEED                               (1000000)         /**< SPI speed in Hz */
#define MAX_PKT_SIZE                            (1500)            /**< Maximum packet size for SPI transfer */
#define PKT_LEN                                 (256)

/** TUN device settings */
#define TUN_DEVICE                              "/dev/net/tun"
#define INTERFACE_NAME_TUN0                     "tun0"

/** GPIO handshake definitions */
#define GPIO_READY_SYSFS                        "/sys/class/gpio/gpio537/value"
#define GPIO_EXPORT                             "/sys/class/gpio/export"
#define GPIO_BASE                               "/sys/class/gpio/%s/base"
#define GPIO_CLASS                              "/sys/class/gpio"
#define GPIO_HANDSHAKE_SPI                      (25)              /**< GPIO25 used as SPI handshake line */

#define PROC_PATH                               "/proc"
#define DEV_NULL_PATH                           "/dev/null"

/***********************************************************************************************/
/*  ESP32 defines                                                                              */
/***********************************************************************************************/
/** SPI device settings */
#define SPI_HOST                                SPI2_HOST
#define PKT_LEN                                 (256)
#define WIFI_GOT_IP_BIT                         BIT0

/* SPI GPIOs */
#define GPIO_SPI_READY                          GPIO_NUM_16
#define GPIO_MOSI                               (13)
#define GPIO_MISO                               (12)
#define GPIO_SCLK                               (14)
#define GPIO_CS                                 (15)

#define SPI_TX_QUEUE_LEN                        (8)

#define SPI_RX_TASK_STACK_SIZE                  (4096)
#define SPI_RX_TASK_PRIORITY                    (3)
/***********************************************************************************************/

