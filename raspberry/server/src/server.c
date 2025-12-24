/**
 * @file poll_server_multi.c
 * @brief Simple TCP server using poll() supporting up to 5 simultaneous clients.
 *
 * The server listens on a predefined port, accepts up to MAX_CLIENTS connections,
 * compares received messages with a predefined string, and replies with "OK" or
 * "ERROR". All errors are logged to syslog.
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
                log_msg(LOG_ERR, "poll failed: %s", strerror(errno));
                break;
            }

            /* Handle new incoming connections */
            if (pfds[0].revents & POLLIN) {
                int client_fd = accept(listen_fd, NULL, NULL);
                if (client_fd < 0) {
                    log_msg(LOG_ERR, "accept failed: %s", strerror(errno));
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

            /* Handle client sockets */
            for (int i = 1; i <= MAX_CLIENTS; i++) {
                if (pfds[i].fd < 0)
                    continue;

                if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    socket_close(pfds[i].fd);
                    pfds[i].fd = -1;
                    continue;
                }

                if (pfds[i].revents & POLLIN) {
                    packet_t replay = {0};
                    ssize_t n = recv(pfds[i].fd, replay.buffer, sizeof(replay.buffer) - 1, 0);

                    if (n <= 0) {
                        if (n < 0) {
                            log_msg(LOG_ERR, "recv failed: %s", strerror(errno));
                        }
                        socket_close(pfds[i].fd);
                        pfds[i].fd = -1;
                        continue;
                    }

                    /* Validate reply */
                    if (isOk(validate_replay(&replay))) {
                        log_msg(LOG_DEBUG, "Server received: '%s'", replay.packet.data);
                        if (strcmp(buf, EXPECTED_STRING) == 0)
                            send(pfds[i].fd, OK_REPLY, strlen(OK_REPLY), 0);
                        else
                            send(pfds[i].fd, ERR_REPLY, strlen(ERR_REPLY), 0);
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
