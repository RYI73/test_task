/**
 * @file poll_server_multi.c
 * @brief Simple TCP server using poll() supporting up to 5 simultaneous clients.
 *
 * The server listens on a predefined port, accepts up to MAX_CLIENTS connections,
 * compares received messages with a predefined string, and replies with "OK" or
 * "ERROR". All errors are logged to syslog.
 */

#define _GNU_SOURCE
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

/** TCP port to listen on */
#define SERVER_PORT      12345

/** Maximum number of concurrent clients */
#define MAX_CLIENTS      5

/** poll() timeout in milliseconds */
#define POLL_TIMEOUT_MS  500

/** Expected message from client */
#define EXPECTED_STRING  "HELLO"

/** Reply sent on successful match */
#define OK_REPLY         "OK"

/** Reply sent on mismatch */
#define ERR_REPLY        "ERROR"

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
    struct sockaddr_in addr;
    struct pollfd pfds[MAX_CLIENTS + 1];

    /* Initialize syslog */
    openlog("poll_server", LOG_PID | LOG_CONS, LOG_DAEMON);

    /* Install SIGINT handler */
    struct sigaction sa = { .sa_handler = sigint_handler };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    /* Create listening socket */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        syslog(LOG_ERR, "socket failed: %s", strerror(errno));
        goto cleanup;
    }

    /* Allow address reuse */
    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        syslog(LOG_ERR, "setsockopt failed: %s", strerror(errno));
        goto cleanup;
    }

    /* Bind socket */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(SERVER_PORT);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "bind failed: %s", strerror(errno));
        goto cleanup;
    }

    /* Start listening */
    if (listen(listen_fd, MAX_CLIENTS) < 0) {
        syslog(LOG_ERR, "listen failed: %s", strerror(errno));
        goto cleanup;
    }

    /* Initialize pollfd array */
    pfds[0].fd     = listen_fd;
    pfds[0].events = POLLIN;

    for (int i = 1; i <= MAX_CLIENTS; i++)
        pfds[i].fd = -1;

    syslog(LOG_INFO, "Server started on port %d", SERVER_PORT);

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
            syslog(LOG_ERR, "poll failed: %s", strerror(errno));
            break;
        }

        /* Handle new incoming connections */
        if (pfds[0].revents & POLLIN) {
            int client_fd = accept(listen_fd, NULL, NULL);
            if (client_fd < 0) {
                syslog(LOG_ERR, "accept failed: %s", strerror(errno));
            } else {
                int slot = find_free_slot(pfds);
                if (slot < 0) {
                    syslog(LOG_WARNING, "Maximum clients reached");
                    close(client_fd);
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
                close(pfds[i].fd);
                pfds[i].fd = -1;
                continue;
            }

            if (pfds[i].revents & POLLIN) {
                char buf[256];
                ssize_t n = recv(pfds[i].fd, buf, sizeof(buf) - 1, 0);

                if (n <= 0) {
                    if (n < 0)
                        syslog(LOG_ERR, "recv failed: %s", strerror(errno));
                    close(pfds[i].fd);
                    pfds[i].fd = -1;
                    continue;
                }

                buf[n] = '\0';

                syslog(LOG_DEBUG, "Server received: '%s'", buf);
                if (strcmp(buf, EXPECTED_STRING) == 0)
                    send(pfds[i].fd, OK_REPLY, strlen(OK_REPLY), 0);
                else
                    send(pfds[i].fd, ERR_REPLY, strlen(ERR_REPLY), 0);

                close(pfds[i].fd);
                pfds[i].fd = -1;
            }
        }
    }

cleanup:
    /* Cleanup all open file descriptors */
    for (int i = 0; i <= MAX_CLIENTS; i++) {
        if (pfds[i].fd >= 0)
            close(pfds[i].fd);
    }

    syslog(LOG_INFO, "Server stopped");
    closelog();
    return 0;
}
