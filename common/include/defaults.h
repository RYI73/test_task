#pragma once

/***********************************************************************************************/
#define INTERFACE_NAME_TUN0                     "tun0"
/***********************************************************************************************/
#define DEVICE_TUN                              "/dev/net/tun"
#define PROC_PATH                               "/proc"
#define DEV_NULL_PATH                           "/dev/null"
/***********************************************************************************************/
#define MAX_DUMP_BUFFER_SIZE                    (128)
/***********************************************************************************************/
#define SOCKET_READ_TIMEOUT_MS                  (500)
/***********************************************************************************************/
/** Localhost IPv4 address (string form) */
#define LOCALHOST_ADDR                          "127.0.0.1"
/** INADDR_ANY IPv4 address (string form) */
#define ANY_ADDR                                "0.0.0.0"
/** TUN IPv4 address (string form) */
#define TUN_ADDR                                "10.0.0.1"
/** Server IPv4 address (string form) */
//#define SERVER_ADDR                             "192.168.1.122"
#define SERVER_ADDR                             "10.0.0.2"
/** Server TCP port */
#define SERVER_PORT                             (12345)
/** Message sent to server */
#define CLIENT_MESSAGE                          "HELLO"
/** Maximum size of packet */
#define PACKET_SIZE                             (1024)
/** Maximum number of concurrent clients */
#define MAX_CLIENTS                             (5)
/** poll() timeout in milliseconds */
#define POLL_TIMEOUT_MS                         (500)
/***********************************************************************************************/
/** Expected message from client */
#define EXPECTED_STRING                         "HELLO"
/** Reply sent on successful match */
#define OK_REPLY                                "OK"
/** Reply sent on mismatch */
#define ERR_REPLY                               "ERROR"
/***********************************************************************************************/
/** SPI device settings */
#define SPI_DEVICE                              "/dev/spidev0.0"
#define SPI_MODE                                0
#define SPI_BITS                                8
#define SPI_SPEED                               1000000         /**< SPI speed in Hz */
#define MAX_PKT_SIZE                            1500            /**< Maximum packet size for SPI transfer */
#define SPI_MAGIC                               0x49504657      /**< Magic constant ('IPFW') for SPI framing */
#define SPI_PROTO_VERSION                       1
#define PKT_LEN                                 128

/** GPIO handshake definitions */
#define GPIO_READY_SYSFS                        "/sys/class/gpio/gpio537/value"
#define GPIO_EXPORT                             "/sys/class/gpio/export"
#define GPIO_BASE                               "/sys/class/gpio/%s/base"
#define GPIO_CLASS                              "/sys/class/gpio"
#define GPIO_HANDSHAKE_SPI                      25              /**< GPIO25 used as SPI handshake line */
/***********************************************************************************************/

