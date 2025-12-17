#pragma once

/***********************************************************************************************/
// TODO move to json config
#define INTERFACE_NAME                          "eth0"
#define INTERFACE_NAME_TUN0                     "tun0"
#define INTERFACE_NAME_TUN1                     "tun1"
/***********************************************************************************************/
#define DEVICE_TUN                              "/dev/net/tun"
#define PROC_PATH                               "/proc"
#define DEV_NULL_PATH                           "/dev/null"
/***********************************************************************************************/
#define MAX_DUMP_BUFFER_SIZE                    (128)
/***********************************************************************************************/
#define SOCKET_READ_TIMEOUT_MS                  (500)
/***********************************************************************************************/
/** Server IPv4 address (string form) */
#define SERVER_ADDR "127.0.0.1"

/** Server TCP port */
#define SERVER_PORT 12345

/** Message sent to server */
#define CLIENT_MESSAGE "HELLO"

/** Maximum size of receive buffer */
#define RECV_BUF_SIZE 256
/***********************************************************************************************/
