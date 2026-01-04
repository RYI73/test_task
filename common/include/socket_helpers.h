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

/**
 * @brief Create and connect a non-blocking TCP client socket.
 *
 * Creates a TCP socket, optionally binds it to a local IP/port,
 * switches the socket to non-blocking mode and connects to the
 * specified server with timeout control.
 *
 * @param[out] ssock        Pointer to store connected socket descriptor
 * @param[in]  local_ip     Optional local IPv4 address to bind
 *                          (NULL or empty string to skip bind)
 * @param[in]  local_port   Local TCP port for bind (used if local_ip is set)
 * @param[in]  server_ip    Remote server IPv4 address
 * @param[in]  server_port  Remote server TCP port
 *
 * @return
 *  - RESULT_OK on successful connection
 *  - RESULT_ARGUMENT_ERROR on invalid arguments
 *  - RESULT_SOCKET_CREATE_ERROR if socket() fails
 *  - RESULT_INET_PTON_ERROR if IP address conversion fails
 *  - RESULT_SOCKET_BIND_ERROR if bind() fails
 *  - RESULT_SOCKET_CONNECT_TIMEOUT on connection timeout
 *  - RESULT_SOCKET_CONNECT_ERROR on connection failure
 */
int socket_tcp_client_create(int *ssock, const char *local_ip, u16 local_port, const char *server_ip, u16 server_port);

/**
 * @brief Initialize TUN interface and assign IP address.
 *
 * Allocates a TUN device, brings it up and ensures that the specified
 * IP address is assigned to the interface.
 *
 * @param[in]  device  Name of the TUN device (e.g. "tun0")
 * @param[in]  tun_ip  IP address to assign to the TUN interface
 * @param[out] tun_fd  Pointer to store TUN device file descriptor
 *
 * @return
 *  - RESULT_OK on success
 *  - RESULT_NOT_INITED if TUN exists but has no IP assigned
 *  - Other RESULT_* codes returned by helper functions
 */
int tup_init(const char *device, const char *tun_ip, int *tun_fd);

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
