#pragma once

#include "types.h"

/**
 * @brief Create a TCP server socket and bind it to a local IP and port.
 *
 * This function creates a TCP socket, optionally binds it to a specific local IP
 * address and port, sets the SO_REUSEADDR option, and starts listening for incoming
 * connections with the specified backlog.
 *
 * @param[out] ssock Pointer to an integer where the created socket descriptor will be stored.
 * @param[in]  server_ip String with the local IP address to bind, or NULL/empty for INADDR_ANY.
 * @param[in]  server_port Local port number to bind the socket to.
 * @param[in]  backlog Maximum number of pending connections in the listen queue.
 *
 * @return RESULT_OK (0) on success, otherwise a negative error code:
 *         - RESULT_NOT_INITED_ERROR: Function not properly initialized.
 *         - RESULT_ARGUMENT_ERROR: Invalid arguments provided.
 *         - RESULT_SOCKET_CREATE_ERROR: Socket creation failed.
 *         - RESULT_SOCKET_BIND_ERROR: Binding the socket failed.
 *         - RESULT_LISTEN_ERROR: Listen failed.
 *         - RESULT_INET_PTON_ERROR: Conversion of IP address string failed.
 *
 * @note After successful creation, use accept() to handle incoming client connections.
 *       The socket should be closed with close() or socket_close() when no longer needed.
 *
 * @warning This function does not handle multiple client connections; that should be
 *          implemented separately (e.g., with select(), poll(), or threads).
 */
int socket_tcp_server_create(int *ssock, const char *server_ip, u16 server_port, int backlog);

/**
 * @brief Closes the specified socket.
 *
 * Attempts to close the provided socket file descriptor and logs the result.
 *
 * @param[in] sock Socket file descriptor to close.
 * @return RESULT_OK on success, RESULT_SOCKET_CLOSE_ERROR on failure, or RESULT_ARGUMENT_ERROR if sock is invalid.
 */
int socket_close(int sock);

/**
 * @brief Sends a raw message through a socket.
 *
 * Sends the data buffer of the specified size through the given socket.
 * If sending fails, the socket is closed and an error is returned.
 *
 * @param[in] sock     Socket descriptor.
 * @param[in] buff     Pointer to the message data.
 * @param[in] sz       Size of the message in bytes.
 * @return RESULT_OK on success, or RESULT_SOCKET_SEND_ERROR on failure.
 */
int socket_send_data(int sock, void* buff, ssize_t sz);

/**
 * @brief Add IP address to TUN interface
 *
 * @param ifname Interface name
 * @param ip_str IP address string
 * @return 0 on success, -1 on error
 */
int tun_add_ip(const char *ifname, const char *ip_str);

/**
 * @brief Check if TUN interface has specific IP address
 *
 * @param ifname Interface name
 * @param ip_str IP address string (e.g., "10.0.0.2")
 * @return 1 if IP is configured, 0 otherwise
 */
int tun_has_ip(const char *ifname, const char *ip_str);

/**
 * @brief Reads data from a socket with a timeout.
 *
 * Uses `poll()` to wait for data on the given socket for a specified time,
 * and reads into the provided buffer if available.
 *
 * @param[in]    sock        Socket descriptor.
 * @param[out]   buff        Buffer to store received data.
 * @param[inout] sz          Pointer of size of the buffer in bytes.
 * @param[in]    timeout_ms  Poll timeout in milliseconds.
 * @return RESULT_OK if data was received, or RESULT_NODATA if timeout or failure occurred.
 */
int socket_read_data(int sock, void *buff, ssize_t *sz, int timeout_ms);

int socket_tcp_client_create(int *ssock, const char *local_ip, u16 local_port, const char *server_ip, u16 server_port);

/**
 * @brief Allocate a TUN interface
 *
 * @param devname Desired interface name (e.g., "tun0")
 * @return File descriptor for TUN interface, or -1 on failure
 */
int tun_alloc(char *devname);

/**
 * @brief Set TUN interface UP
 *
 * @param ifname Interface name
 * @return 0 on success, -1 on failure
 */
int tun_set_up(const char *ifname);

/**
 * @brief Read a packet from TUN interface
 *
 * @param tun_fd File descriptor of TUN
 * @param buf Buffer to store packet
 * @return Number of bytes read, or -1 on error
 */
ssize_t read_tun_packet(int tun_fd, uint8_t *buf);

/**
 * @brief Write a packet to TUN interface
 *
 * @param tun_fd File descriptor of TUN
 * @param buf Packet data
 * @param len Length of packet
 * @return Number of bytes written, or -1 on error
 */
ssize_t write_tun_packet(int tun_fd, uint8_t *buf, size_t len);

/***********************************************************************************************/
