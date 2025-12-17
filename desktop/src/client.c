/**
 * @file poll_client.c
 * @brief Simple TCP client for poll-based test server.
 *
 * The client connects to a server on a predefined host and port,
 * sends a predefined message, receives a response, and prints it.
 * All errors are logged to syslog.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>

/** Server IPv4 address (string form) */
#define SERVER_ADDR "127.0.0.1"

/** Server TCP port */
#define SERVER_PORT 12345

/** Message sent to server */
#define CLIENT_MESSAGE "HELLO"

/** Maximum size of receive buffer */
#define RECV_BUF_SIZE 256

/**
 * @brief Program entry point.
 *
 * Initializes syslog, creates a TCP socket, connects to the server,
 * sends a predefined message, receives the reply, and prints it to stdout.
 *
 * @return Exit status code.
 */
int main(void)
{
    int sockfd = -1;
    struct sockaddr_in server_addr;
    char recv_buf[RECV_BUF_SIZE];

    /* Initialize syslog */
    openlog("poll_client", LOG_PID | LOG_CONS, LOG_DAEMON);

    /* Create TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        syslog(LOG_ERR, "socket failed: %s", strerror(errno));
        goto cleanup;
    }

    /* Prepare server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_ADDR, &server_addr.sin_addr) != 1) {
        syslog(LOG_ERR, "inet_pton failed for %s", SERVER_ADDR);
        goto cleanup;
    }

    /* Connect to server */
    if (connect(sockfd, (struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0) {
        syslog(LOG_ERR, "connect failed: %s", strerror(errno));
        goto cleanup;
    }

    /* Send message to server */
    ssize_t sent = send(sockfd, CLIENT_MESSAGE,
                        strlen(CLIENT_MESSAGE), 0);
    if (sent < 0) {
        syslog(LOG_ERR, "send failed: %s", strerror(errno));
        goto cleanup;
    }

    /* Receive reply */
    ssize_t received = recv(sockfd, recv_buf,
                            sizeof(recv_buf) - 1, 0);
    if (received < 0) {
        syslog(LOG_ERR, "recv failed: %s", strerror(errno));
        goto cleanup;
    }

    recv_buf[received] = '\0';

    /* Print server response */
    printf("Server reply: %s", recv_buf);

cleanup:
    if (sockfd >= 0)
        close(sockfd);

    closelog();
    return 0;
}
