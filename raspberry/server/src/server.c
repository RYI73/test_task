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
#include "protocol.h"

static u16 sequence = 0x20;

/**
 * @brief Global flag controlling main loop execution.
 *
 * Set to 0 by SIGINT handler to allow graceful shutdown.
 */
static volatile sig_atomic_t running = 1;

/**
 * @brief SIGINT signal handler.
 *
 * This handler only sets a flag so that the main loop
 * can terminate cleanly.
 *
 * @param sig Signal number (unused).
 */
static void sigint_handler(int sig)
{
    (void)sig;
    running = 0;
}

/**
 * @brief Find a free slot in pollfd array for a new client.
 *
 * Index 0 is reserved for the listening socket.
 *
 * @param pfds Array of pollfd structures.
 * @return Index of a free slot, or -1 if none available.
 */
static int find_free_slot(struct pollfd *pfds)
{
    for (int i = 1; i <= MAX_CLIENTS; i++) {
        if (pfds[i].fd < 0)
            return i;
    }
    return -1;
}

/**
 * @brief Program entry point.
 *
 * Initializes syslog, installs signal handlers, creates and binds
 * the listening socket, and enters the main poll-based event loop.
 *
 * @return Exit status code.
 */
int main(void)
{
    int listen_fd = -1;
    struct pollfd pfds[MAX_CLIENTS + 1];
    int result = RESULT_OK;
    int res_pack = RESULT_OK;
    size_t len = 0;
    packet_t request = {0};
    packet_t replay = {0};

    do {
        /* Initialize syslog */
        openlog("poll_server", LOG_PID | LOG_CONS, LOG_DAEMON);

        /* Install SIGINT handler */
        struct sigaction sa = { .sa_handler = sigint_handler };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, NULL);

        result = socket_tcp_server_create(&listen_fd, ANY_ADDR, SERVER_PORT, MAX_CLIENTS);
        if (!isOk(result)) {
            break;
        }
        log_msg(LOG_INFO, "Opened socket fd %d", listen_fd);

        /* Initialize pollfd array */
        pfds[0].fd     = listen_fd;
        pfds[0].events = POLLIN;

        for (int i = 1; i <= MAX_CLIENTS; i++)
            pfds[i].fd = -1;

        log_msg(LOG_INFO, "Server started on port %d", SERVER_PORT);

        /* Main event loop */
        while (running) {
            int ret = poll(pfds, MAX_CLIENTS + 1, POLL_TIMEOUT_MS);

            if (ret == 0) {
                /* Timeout occurred, loop again */
                continue;
            }

            if (ret < 0) {
                if (errno == EINTR)
                    continue;
                log_msg(LOG_ERR, "❌ Server poll failed: %s", strerror(errno));
                break;
            }
            printf("Server poll OK\n");

            /* Handle new incoming connections */
            if (pfds[0].revents & POLLIN) {
                int client_fd = accept(listen_fd, NULL, NULL);
                if (client_fd < 0) {
                    log_msg(LOG_ERR, "❌ Server accept failed: %s", strerror(errno));
                } else {
                    int slot = find_free_slot(pfds);
                    if (slot < 0) {
                        log_msg(LOG_WARNING, "Maximum clients reached");
                        socket_close(client_fd);
                    } else {
                        pfds[slot].fd     = client_fd;
                        pfds[slot].events = POLLIN;
                    }
                }
            }

            printf("Cickle for all clients OK\n");

            /* Handle client sockets */
            for (int i = 1; i <= MAX_CLIENTS; i++) {
                if (pfds[i].fd < 0)
                    continue;

                printf("Client %d fd %d\n", i, pfds[i].fd);
                printf("revents %X\n", pfds[i].revents);
                if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    socket_close(pfds[i].fd);
                    pfds[i].fd = -1;
                    continue;
                }

                if (pfds[i].revents & POLLIN) {
                    printf("revents POLLIN\n");
                    memset(request.buffer, 0, sizeof(request.buffer));
                    memset(replay.buffer, 0, sizeof(request.buffer));
//                    ssize_t n = recv(pfds[i].fd, request.buffer, sizeof(request.buffer), 0);
                    /* Receive reply */
                    ssize_t received = sizeof(request.buffer);
                    result = socket_read_data(pfds[i].fd, request.buffer, &received, SOCKET_READ_TIMEOUT_MS);
                    if (!isOk(result) || received == 0) {
                        log_msg(LOG_ERR, "❌ Server recv failed");
                        socket_close(pfds[i].fd);
                        pfds[i].fd = -1;
                        continue;
                    }

                    char str[32];
                    const char array_good_bin[] = CLIENT_ARRAY;
                    res_pack = RESULT_OK;
                    /* Validate reply */
                    res_pack = protocol_packet_validate(&request);
                    if (isOk(res_pack)) {
                        switch (request.packet.header.type) {
                        case PACKET_TYPE_STRING:
                            log_msg(LOG_DEBUG, "Server received: '%.32s%s'", request.packet.data, strlen(request.packet.data) > 32 ? "..." : "");
                            len = strlen(request.packet.data);
                            if (strlen(request.packet.data) < strlen(CLIENT_MESSAGE) || memcmp(request.packet.data, CLIENT_MESSAGE, len) != 0) {
                                res_pack = RESULT_BROKEN_MSG_ERROR;
                            }
                            break;
                        case PACKET_TYPE_ARRAY:
                            bytes_to_hexstr(request.packet.data, request.packet.header.len, str, sizeof(str));
                            log_msg(LOG_DEBUG, "Server received: %.32s", str);
                            if (memcmp(request.packet.data, array_good_bin, sizeof(array_good_bin)) != 0) {
                                res_pack = RESULT_BROKEN_MSG_ERROR;
                            }
                            break;
                        default:
                            res_pack = RESULT_TYPE_UNKNOWN_ERROR;
                            log_msg(LOG_DEBUG, "Server received unknown type of packed: %u", request.packet.header.type);
                            break;
                        }

                    }
                    else {
                        log_msg(LOG_WARNING, "Server received broken packet");
                    }

                    /* Prepare packet to server */
                    replay.packet.header.type = PACKET_TYPE_ANSWER;
                    replay.packet.header.answer_sequence = request.packet.header.sequence;
                    replay.packet.header.answer_result = res_pack;
                    protocol_packet_prepare(&replay, sequence++, 0);

                    /* Send message to server */
                    result = socket_send_data(pfds[i].fd, (void*)replay.buffer, PACKET_HEADER_SIZE);
                    if (!isOk(result)) {
                        log_msg(LOG_ERR, "❌ Server send failed");
                    }

                    socket_close(pfds[i].fd);
                    pfds[i].fd = -1;
                }
            }
        }

    } while(0);


    for (int i = 1; i <= MAX_CLIENTS; i++) {
        if (pfds[i].fd >= 0) {
            socket_close(pfds[i].fd);
        }
    }

    if (listen_fd >= 0) {
        socket_close(listen_fd);
    }

    log_msg(LOG_INFO, "Server stopped");

    closelog();

    if (isOk(result)) {
        return EXIT_SUCCESS;
    }
    else {
        return EXIT_FAILURE;
    }
}
