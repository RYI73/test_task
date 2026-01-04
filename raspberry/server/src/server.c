/**
 * @file poll_server_multi.c
 * @brief Simple TCP server using poll() supporting up to 5 simultaneous clients.
 *
 * The server listens on a predefined port, accepts up to MAX_CLIENTS connections,
 * compares received messages with a predefined string, and replies with "OK" or
 * "ERROR". All errors are logged to syslog.
 *
 * @author Ruslan
 * @date 2025-12-24
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <syslog.h>

#include "defaults.h"
#include "protocol.h"
#include "logs.h"
#include "socket_helpers.h"
#include "helpers.h"

static u16 sequence = 0x20;
static server_stats_t g_stats = {0};

/***********************************************************************************************/
/* Internal functions                                                                          */
/***********************************************************************************************/
/**
 * @brief Find a free slot in pollfd array for a new client.
 *
 * This function searches the `pfds` array for a free slot (fd < 0) starting from index 1,
 * as index 0 is reserved for the listening socket.
 *
 * @param pfds  Pointer to an array of pollfd structures.
 * @param slot  Output parameter, set to the index of the first free slot if found, or -1 if none.
 *
 * @return RESULT_OK if a free slot was found,
 *         RESULT_DATA_NOT_FOUND if no free slot is available.
 */
static int find_free_slot(struct pollfd *pfds, int *slot)
{
    int i = 0;
    *slot = -1;
    int result = RESULT_DATA_NOT_FOUND;

    for (i = 1; i <= MAX_CLIENTS; i++) {
        if (pfds[i].fd < 0) {
            *slot = i;
            result = RESULT_OK;
            break;
        }
    }

    return result;
}
/***********************************************************************************************/
/**
 * @brief Accept a new client connection and assign to pollfd array.
 *
 * @param listen_fd Listening socket
 * @param pfds Pollfd array
 */
static void accept_new_client(int listen_fd, struct pollfd *pfds)
{
    int slot = -1;
    int result = RESULT_OK;

    do {
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            log_msg(LOG_ERR, "Server accept failed: %s", strerror(errno));
            break;
        }

        result = find_free_slot(pfds, &slot);
        if (!isOk(result)) {
            log_msg(LOG_WARNING, "Maximum clients reached");
            socket_close(client_fd);
            break;
        }

        pfds[slot].fd = client_fd;
        pfds[slot].events = POLLIN;
    } while(0);
}
/***********************************************************************************************/
static void stats_init(void)
{
    g_stats.requests.total_requests = 0;
    g_stats.requests.broken_requests = 0;

    g_stats.bytes.total_bytes = 0;

    g_stats.latency.total_latency_ns = 0;
    g_stats.latency.max_latency_ms = 0;
    g_stats.latency.min_latency_ms = UINT32_MAX;

    g_stats.runtime.start_time_ns = now_ns();
}

/***********************************************************************************************/
static void stats_update(u64 request_bytes, u32 latency_ms, bool broken)
{
    g_stats.requests.total_requests += 1;
    if (broken) {
        g_stats.requests.broken_requests += 1;
    }

    g_stats.bytes.total_bytes += request_bytes;

    g_stats.latency.total_latency_ns += (u64)latency_ms * 1000000ULL;
    if (latency_ms > g_stats.latency.max_latency_ms) {
        g_stats.latency.max_latency_ms = latency_ms;
    }
    if (latency_ms < g_stats.latency.min_latency_ms) {
        g_stats.latency.min_latency_ms = latency_ms;
    }
}
/***********************************************************************************************/
static void stats_compute(u32 *avg_latency_ms, u64 *throughput_kbps)
{
    u64 now = now_ns();
    u32 elapsed_s = (u32)((now - g_stats.runtime.start_time_ns) / 1000000000ULL);
    if (elapsed_s == 0) {
        elapsed_s = 1;
    }

    *avg_latency_ms = g_stats.requests.total_requests ?
                      (u32)((g_stats.latency.total_latency_ns / 1000000ULL) / g_stats.requests.total_requests)
                      : 0;

    *throughput_kbps = (g_stats.bytes.total_bytes * 8ULL) / elapsed_s / 1000ULL;
}
/***********************************************************************************************/
/**
 * @brief Handle a single client socket: read, validate, prepare reply, and send.
 *
 * @param client_fd Client socket file descriptor
 */
static void handle_client(int client_fd)
{
    int result = RESULT_OK;
    int res_pack = RESULT_OK;
    size_t len_in = 0;
    size_t len_out = 0;
    u32 latency_ms = 0;
    packet_t request = {0};
    packet_t reply   = {0};
    ssize_t received = sizeof(request.buffer);
    u8  type = PACKET_TYPE_ANSWER_DATA;

    u64 start_ns = now_ns();

    do {
        memset(request.buffer, 0, sizeof(request.buffer));
        memset(reply.buffer, 0, sizeof(reply.buffer));
        len_out = 0;

        result = socket_read_data(client_fd, request.buffer, &received, SOCKET_READ_TIMEOUT_MS);
        if (!isOk(result) || received == 0) {
            log_msg(LOG_ERR, "Server recv failed");
            result = RESULT_SOCKET_ERROR;
            break;
        }

        res_pack = protocol_packet_validate(&request);
        if (isOk(res_pack)) {
            switch (request.packet.header.type) {
                case PACKET_TYPE_STRING: {
                    log_msg(LOG_DEBUG, "Received STRING: '%.32s%s'", request.packet.data,
                            strlen(request.packet.data) > 32 ? "..." : "");
                    len_in = strlen(request.packet.data);
                    if (len_in < strlen(CLIENT_MESSAGE) || memcmp(request.packet.data, CLIENT_MESSAGE, len_in) != 0) {
                        res_pack = RESULT_BROKEN_MSG_ERROR;
                    }
                    break;
                }

                case PACKET_TYPE_ARRAY: {
                    char str[32];
                    const u8 array_good_bin[] = CLIENT_ARRAY;
                    bytes_to_hexstr(request.packet.data, request.packet.header.len, str, sizeof(str));
                    log_msg(LOG_DEBUG, "Received ARRAY: %.32s", str);
                    if (memcmp(request.packet.data, array_good_bin, sizeof(array_good_bin)) != 0) {
                        res_pack = RESULT_BROKEN_MSG_ERROR;
                    }
                    break;
                }

                case PACKET_TYPE_GET_STATS: {
                    len_out = sizeof(server_stats_t);
                    stats_compute(&g_stats.latency.avg_latency, &g_stats.throughput);
                    memcpy(reply.packet.data, &g_stats, len_out);
                    type = PACKET_TYPE_ANSWER_STATS;

                    break;
                }

                case PACKET_TYPE_CLR_STATS: {
                    stats_init();
                    break;
                }

                default: {
                    res_pack = RESULT_TYPE_UNKNOWN_ERROR;
                    log_msg(LOG_DEBUG, "Unknown packet type: %u", request.packet.header.type);
                    break;
                }
            }
        } else {
            log_msg(LOG_WARNING, "Received broken packet");
        }

        /* Prepare and send reply */
        reply.packet.header.type = type;
        reply.packet.header.answer_sequence = request.packet.header.sequence;
        reply.packet.header.answer_result = res_pack;
        protocol_packet_prepare(&reply, sequence++, len_out);

        result = socket_send_data(client_fd, reply.buffer, PACKET_HEADER_SIZE + len_out);
        if (!isOk(result)) {
            log_msg(LOG_ERR, "Server send failed");
            result = RESULT_SOCKET_ERROR;
        }

    } while(0);

    u64 end_ns = now_ns();
    latency_ms = (u32)((end_ns - start_ns) / 1000000ULL);

    stats_update(received, latency_ms, !isOk(res_pack));

    /* Close client socket in any case */
    socket_close(client_fd);
}
/***********************************************************************************************/
/**
 * @brief Close all client sockets
 *
 * @param pfds Pollfd array
 */
static void close_all_clients(struct pollfd *pfds)
{
    for (int i = 1; i <= MAX_CLIENTS; i++) {
        if (pfds[i].fd >= 0) {
            socket_close(pfds[i].fd);
            pfds[i].fd = -1;
        }
    }
}

/***********************************************************************************************/
/* Main application function                                                                   */
/***********************************************************************************************/
int main(void)
{
    volatile bool is_running = true;
    int listen_fd = -1;
    struct pollfd pfds[MAX_CLIENTS + 1];
    int result = RESULT_OK;

    /* SIGNAL handler */
    void sighandler(int sig)
    {
        UNUSED(sig);
        is_running = false;
    }
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    do {
        /* Initialize syslog */
        openlog("poll_server", LOG_PID | LOG_CONS, LOG_DAEMON);

        /* Create TCP server */
        result = socket_tcp_server_create(&listen_fd, ANY_ADDR, SERVER_PORT, MAX_CLIENTS);
        if (!isOk(result)) {
            log_msg(LOG_ERR, "Failed to create server socket: %u", result);
            break;
        }

        log_msg(LOG_INFO, "Server listening on fd %d port %d", listen_fd, SERVER_PORT);

        /* Initialize pollfd array */
        pfds[0].fd = listen_fd;
        pfds[0].events = POLLIN;

        for (int i = 1; i <= MAX_CLIENTS; i++) {
            pfds[i].fd = -1;
        }

        stats_init();

        /* Main poll loop */
        while (is_running) {
            int ret = poll(pfds, MAX_CLIENTS + 1, POLL_TIMEOUT_MS);

            if (ret < 0) {
                if (errno == EINTR) {
                    continue;
                }
                log_msg(LOG_ERR, "Poll error: %s", strerror(errno));
                break;
            } else if (ret == 0) {
                continue;
            }

            /* Accept new connections */
            if (pfds[0].revents & POLLIN) {
                accept_new_client(listen_fd, pfds);
            }

            /* Handle clients */
            for (int i = 1; i <= MAX_CLIENTS; i++) {
                if (pfds[i].fd < 0) {
                    continue;
                }

                if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    socket_close(pfds[i].fd);
                    pfds[i].fd = -1;
                    continue;
                }

                if (pfds[i].revents & POLLIN) {
                    handle_client(pfds[i].fd);
                    pfds[i].fd = -1;
                }
            }
        }

    } while (0);

    close_all_clients(pfds);

    socket_close(listen_fd);

    log_msg(LOG_INFO, "Server stopped");

    closelog();

    if (isOk(result)) {
        return EXIT_SUCCESS;
    } else {
        fprintf(stderr, "Server exited with error: %u\n", result);
        return EXIT_FAILURE;
    }
}
/***********************************************************************************************/
