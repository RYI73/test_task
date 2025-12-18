#pragma once

#include "types.h"

/***********************************************************************************************/
enum inet_pack_type_e {
    INET_PACKTYPE_TCP,
    INET_PACKTYPE_UDP,
    INET_PACKTYPE_IP,
    INET_PACKTYPE_ARP,
    INET_PACKTYPE_UNKNOWN,
    INET_PACKTYPE_BAD
};
/***********************************************************************************************/
/**
 * @brief Parses a raw network packet and logs its key contents.
 *
 * This function inspects the Ethernet header to determine the packet type.
 * If it is an IPv4 packet, it further parses IP, TCP, or UDP headers.
 * ARP packets are also identified and logged.
 *
 * @param[in] buffer Pointer to the raw packet buffer.
 */
//void parse_packet(const unsigned char *buffer);
int parse_packet(const u8 *buffer, size_t len);

/**
 * @brief Create a raw AF_PACKET socket and bind it to a given interface in promiscuous mode.
 *
 * This function creates a raw packet socket (AF_PACKET/SOCK_RAW, ETH_P_ALL),
 * enables promiscuous mode on the specified interface, and binds the socket
 * to that interface. It returns the socket fd via @p ssock on success.
 *
 * Typical usage:
 * @code
 *   int fd;
 *   int rc = socket_raw_create(&fd, "eth0");
 *   if (isOk(rc)) {
 *       // use fd with recvfrom()/sendto() for L2 frames
 *   }
 * @endcode
 *
 * @param[out] ssock      Pointer to an int that receives the created socket fd.
 * @param[in]  if_name    Null-terminated interface name (e.g., "eth0", "tun0").
 *
 * @return RESULT_OK on success, or one of the RESULT_* error codes on failure.
 *
 * @retval RESULT_OK                     Success; *ssock contains a valid fd.
 * @retval RESULT_ARGUMENT_ERROR         @p ssock is NULL.
 * @retval RESULT_SOCKET_CREATE_ERROR    socket() failed.
 * @retval RESULT_SOCKET_IOCTL_ERROR     ioctl(SIOCGIFINDEX) failed.
 * @retval RESULT_SOCKET_BIND_ERROR      setsockopt(PACKET_ADD_MEMBERSHIP) or bind() failed.
 * @retval RESULT_NOT_INITED_ERROR       Generic failure before initialization completed.
 *
 * @note Requires CAP_NET_RAW/CAP_NET_ADMIN privileges to open AF_PACKET
 *       sockets and enable promiscuous mode.
 * @note The socket is set to promiscuous mode via PACKET_ADD_MEMBERSHIP.
 * @warning Caller is responsible for closing the socket with socket_close()
 *          on error paths if @c isOk(result) is false.
 */
int socket_raw_create(int *ssock, char *if_name);

/**
 * @brief Create a connected UDP/IPv4 socket with optional local bind.
 *
 * Creates a UDP socket, optionally binds it to @p local_ip:@p local_port,
 * then connect()s to @p dst_ip:@p dst_port so the caller can use send()/recv()
 * without specifying the destination each time.
 *
 * @param[out] ssock       Output: created socket file descriptor on success.
 * @param[in]  local_ip    Local IPv4 address to bind (dotted), or NULL/empty for INADDR_ANY.
 * @param[in]  local_port  Local UDP port to bind (0 = ephemeral).
 * @param[in]  dst_ip      Destination IPv4 address (dotted). Must be non-NULL/non-empty.
 * @param[in]  dst_port    Destination UDP port (> 0).
 *
 * @return RESULT_OK on success, or one of RESULT_* error codes on failure.
 *
 * @retval RESULT_OK                    Success; *ssock contains valid fd.
 * @retval RESULT_ARGUMENT_ERROR        Bad arguments (dst_ip NULL/empty or dst_port == 0).
 * @retval RESULT_SOCKET_CREATE_ERROR   socket() failed.
 * @retval RESULT_SOCKET_BIND_ERROR     setsockopt(SO_REUSEADDR) or bind() failed.
 * @retval RESULT_INET_PTON_ERROR       inet_pton() failed for local_ip or dst_ip.
 * @retval RESULT_SOCKET_CONNECT_ERROR  connect() failed.
 * @retval RESULT_NOT_INITED_ERROR      Generic failure before initialization completed.
 *
 * @note connect() on UDP is non-blocking and only fixes the default peer.
 * @warning Caller must close the socket (socket_close()/close()) on success.
 */
int socket_udp_create(int *ssock, const char *local_ip, u16 local_port, const char *dst_ip, u16 dst_port);

/**
 * @brief Create a TCP client socket and connect it to a remote server.
 *
 * This function creates a TCP socket, optionally binds it to a local IP
 * address and port, and connects it to the specified remote server IP
 * and port.
 *
 * @param[out] ssock Pointer to an integer where the created socket descriptor
 *                   will be stored on success.
 * @param[in]  local_ip Optional local IP address to bind the socket to.
 *                      Can be NULL or empty string to skip bind().
 * @param[in]  local_port Local port number to bind to (used only if local_ip is set).
 * @param[in]  server_ip Remote server IPv4 address (string).
 * @param[in]  server_port Remote server TCP port.
 *
 * @return RESULT_OK on success, otherwise a negative error code:
 *         - RESULT_NOT_INITED_ERROR: Function not properly initialized.
 *         - RESULT_ARGUMENT_ERROR: Invalid arguments.
 *         - RESULT_SOCKET_CREATE_ERROR: Socket creation failed.
 *         - RESULT_SOCKET_BIND_ERROR: Local bind failed.
 *         - RESULT_SOCKET_CONNECT_ERROR: Connection to server failed.
 *         - RESULT_INET_PTON_ERROR: IP address conversion failed.
 *
 * @note On success, the socket is in connected state and ready for send()/recv().
 *       The caller is responsible for closing the socket using close() or
 *       socket_close().
 */
int socket_tcp_client_create(int *ssock, const char *local_ip, u16 local_port, const char *server_ip, u16 server_port);

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

int socket_udp_create_rx(int *ssock, const char *local_ip, u16 local_port);

/**
 * @brief Open a TUN device (IP L3) and return its file descriptor.
 *
 * Opens @c DEVICE_TUN (usually "/dev/net/tun"), attaches to the given
 * interface name @p ifname with flags IFF_TUN|IFF_NO_PI to read/write
 * pure IP packets (no 4-byte tun_pi header). Optionally sets O_NONBLOCK.
 *
 * @param[out] ssock     Output: TUN file descriptor on success.
 * @param[in]  ifname    TUN device name to attach (e.g., "tun0"). Must be non-NULL/non-empty.
 * @param[in]  nonblock  If non-zero, set the returned fd to O_NONBLOCK.
 *
 * @return RESULT_OK on success, or one of RESULT_* error codes on failure.
 *
 * @retval RESULT_OK                   Success; *ssock contains valid fd.
 * @retval RESULT_ARGUMENT_ERROR       Bad arguments (ifname NULL/empty).
 * @retval RESULT_OPEN_DEVICE_ERROR    open(DEVICE_TUN) failed.
 * @retval RESULT_SOCKET_IOCTL_ERROR   ioctl(TUNSETIFF) failed.
 * @retval RESULT_FCNTL_ERROR          fcntl() failed while setting flags.
 * @retval RESULT_NOT_INITED_ERROR     Generic failure before initialization completed.
 *
 * @note The interface must exist administratively (created via `ip tuntap add ... mode tun`),
 *       and be configured/up (`ip addr add`, `ip link set up`) by the caller.
 * @warning Caller must close the fd with socket_close()/close() on success.
 */
int socket_tun_open_ip(int *ssock, const char *ifname, int nonblock);

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
 * @brief Read a UDP datagram from a connected socket with a poll-based timeout.
 *
 * This helper waits for readability on a UDP socket using poll(2) and then
 * reads a single datagram. For a *connected* UDP socket, recv(2) is used,
 * so only packets from the bound peer are returned.
 *
 * @pre  The socket must be a valid connected UDP socket (AF_INET/AF_INET6).
 * @pre  @p buff != NULL, @p sz != NULL, and *@p sz > 0 (capacity in bytes).
 *
 * @param sock        File descriptor of the connected UDP socket.
 * @param buff        Destination buffer to store the received payload.
 * @param sz          In: buffer capacity (bytes). Out: number of bytes read.
 * @param timeout_ms  Timeout for poll(2) in milliseconds.
 *                    -1 = infinite, 0 = non-blocking check, >0 = finite wait.
 *
 * @return RESULT_OK on success (data received).
 * @retval RESULT_NODATA            No data available before timeout (poll() timed out),
 *                                  or recv() would block.
 * @retval RESULT_ARGUMENT_ERROR    Invalid arguments (NULL pointers or non-positive capacity).
 * @retval RESULT_POLL_ERROR        poll() failed (see errno).
 * @retval RESULT_SOCKET_IO_ERROR   poll() reported error events (POLLERR/POLLHUP/POLLNVAL).
 * @retval RESULT_SOCKET_READ_ERROR recv() failed (see errno).
 * @retval RESULT_EOF               Peer closed / zero-length condition (rare for UDP).
 *
 * @note For unconnected UDP sockets, prefer recvfrom(2) with a sockaddr_in/6,
 *       not sockaddr_ll (which is for PF_PACKET).
 * @note This function is signal-interruptible: if poll() or recv() return -1 with
 *       errno == EINTR, the caller may retry according to its policy.
 * @warning Do not pass a PF_PACKET address structure (sockaddr_ll) to recvfrom()
 *          when using AF_INET/AF_INET6 sockets.
 * @thread_safety The function itself is thread-safe w.r.t. independent sockets.
 *                Do not call concurrently on the same socket from multiple threads.
 */
int socket_udp_read(int sock, void *buff, u16 *sz, int timeout_ms);

/**
 * @brief Get the MAC (hardware) address of a network interface.
 *
 * @param ifname   Name of the network interface (e.g., "eth0").
 * @param mac_out  Pointer to a buffer (at least 6 bytes) to receive the MAC address.
 *
 * @return 0 on success, -1 on failure (errno is set).
 */
int get_mac_address(const char *ifname, u8 *mac_out);

/**
 * @brief Check whether a raw Ethernet packet is addressed to this host,
 *        and not sent by this host (to avoid processing own packets).
 *
 * @param packet Pointer to the Ethernet frame (starting with dst/src MAC).
 * @param this_mac Pointer to this host's MAC address (6 bytes).
 *
 * @return true if the destination MAC matches this_mac or is broadcast,
 *         and the source MAC is not equal to this_mac.
 */
bool is_packet_our(const u8 *packet, const u8 *this_mac);

int socket_read_tun(int sock, void *buff, u16 *sz, int timeout_ms);
int socket_send_tun(int sock, const void *buff, size_t sz);
int parse_ipv4_udp(const uint8_t *buf, size_t len, char *str);
int socket_lo_up();

/***********************************************************************************************/
