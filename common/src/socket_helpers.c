/*******************************************************************************
 *   @file   src/socket_helpers.c
 *   @brief  Implementation of socket helper functions.
 *   @author Ruslan
********************************************************************************
 * Copyright 2025(c).
*******************************************************************************/

/******************************************************************************/
/***************************** Include Files **********************************/
/******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <poll.h>
#include <net/ethernet.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "helpers.h"

#include "logs.h"
#include "types.h"
#include "defines.h"
#include "error_code.h"
#include "socket_helpers.h"

/***********************************************************************************************/
/* Internal functions                                                                          */
/***********************************************************************************************/
static int tun_alloc(char *if_name, int *tun_fd)
{
    struct ifreq ifr = {0};
    int fd = -1;
    const char *dev_name = TUN_DEVICE;
    int result = RESULT_NOT_INITED;

    do {
        if (if_name == NULL || tun_fd == NULL) {
            log_msg(LOG_ERR, "Arguments error");
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        fd = open(dev_name, O_RDWR);
        if (fd < 0) {
            log_msg(LOG_ERR, "Unable to open device %s: '%s'", dev_name, strerror(errno));
            result = RESULT_FILE_OPEN_ERROR;
            break;
        }

        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

        if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
            log_msg(LOG_ERR, "ioctl error of device %s: '%s'", dev_name, strerror(errno));
            result = RESULT_FILE_IOCTL_ERROR;
            break;
        }

        result = RESULT_OK;
        log_msg(LOG_INFO, "TUN interface %s created\n", ifr.ifr_name);

    } while(0);

    if (!isOk(result)) {
        fd_close(fd);
        fd = -1;
    }

    *tun_fd = fd;

    return result;
}
/***********************************************************************************************/
static int tun_set_up(const char *ifname)
{
    struct ifreq ifr = {0};
    int sock = -1;
    int result = RESULT_NOT_INITED;

    do {
        if (ifname == NULL) {
            log_msg(LOG_ERR, "Arguments error");
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            log_msg(LOG_ERR, "Socket creation failed, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_CREATE_ERROR;
            break;
        }

        strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

        if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
            log_msg(LOG_ERR, "SIOCGIFFLAGS error: '%s'", strerror(errno));
            result = RESULT_SOCKET_IOCTL_ERROR;
            break;
        }

        if (!(ifr.ifr_flags & IFF_UP)) {
            ifr.ifr_flags |= IFF_UP;
            if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
                log_msg(LOG_ERR, "SIOCSIFFLAGS with IFF_UP flag error: '%s'", strerror(errno));
                result = RESULT_SOCKET_IOCTL_ERROR;
                break;
            }
        }

        result = RESULT_OK;
        log_msg(LOG_INFO, "Interface %s set UP", ifname);

    } while(0);

    socket_close(sock);

    return result;
}
/***********************************************************************************************/
static int tun_has_ip(const char *ifname, const char *ip_str)
{
    struct ifreq ifr = {0};
    struct sockaddr_in *addr;
    int result = RESULT_NOT_INITED;
    int sock = -1;

    do {
        if (ifname == NULL || ip_str == NULL) {
            log_msg(LOG_ERR, "Arguments error");
           result = RESULT_ARGUMENT_ERROR;
            break;
        }

        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            log_msg(LOG_ERR, "Socket creation failed, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_CREATE_ERROR;
            break;
        }

        strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

        if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
            break; /**< Specified IP not set yet */
        }

        addr = (struct sockaddr_in *)&ifr.ifr_addr;

        if (strcmp(inet_ntoa(addr->sin_addr), ip_str) != 0) {
            break; /**< Specified IP not set yet */
        }

        result = RESULT_OK;

    } while(0);

    socket_close(sock);

    return result;
}
/***********************************************************************************************/
static int tun_add_ip(const char *ifname, const char *ip_str)
{
    struct ifreq ifr = {0};
    struct sockaddr_in addr = {0};
    int sock = -1;
    int result = RESULT_NOT_INITED;

    do {
        if (ifname == NULL || ip_str == NULL) {
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            log_msg(LOG_ERR, "Socket creation failed, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_CREATE_ERROR;
            break;
        }

        strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

        addr.sin_family = AF_INET;
        inet_pton(AF_INET, ip_str, &addr.sin_addr);
        memcpy(&ifr.ifr_addr, &addr, sizeof(addr));

        if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
            log_msg(LOG_ERR, "SIOCSIFADDR error = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_IOCTL_ERROR;
            break;
        }

        log_msg(LOG_INFO, "IP %s added to %s\n", ip_str, ifname);

        result = RESULT_OK;

    } while(0);

    socket_close(sock);

    return result;
}
/***********************************************************************************************/
/* External functions                                                                          */
/***********************************************************************************************/
int socket_tcp_server_create(int *ssock, const char *server_ip, u16 server_port, int backlog)
{
    int result = RESULT_NOT_INITED_ERROR;
    int sock = -1;
    int yes = 1;

    do {
        if (!server_port) {
            errno = EINVAL;
            log_msg(LOG_ERR, "Arguments error");
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            log_msg(LOG_ERR, "Socket creation failed, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_CREATE_ERROR;
            break;
        }

        // Allow fast reuse
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
            log_msg(LOG_ERR, "setsockopt(SO_REUSEADDR) failed, errno = %d [%s]", errno, strerror(errno));
            // not fatal
        }

        /* Bind socket */
        struct sockaddr_in local;
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_port   = htons(server_port);

        if (server_ip && server_ip[0] != '0') {
            if (inet_pton(AF_INET, server_ip, &local.sin_addr) != 1) {
                log_msg(LOG_ERR, "inet_pton(server_ip) failed, errno = %d [%s]", errno, strerror(errno));
                result = RESULT_INET_PTON_ERROR;
                break;
            }
        } else {
            local.sin_addr.s_addr = INADDR_ANY;
        }

        if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
            log_msg(LOG_ERR, "Bind failed, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_BIND_ERROR;
            break;
        }

        /* Start listening */
        if (listen(sock, backlog) < 0) {
            log_msg(LOG_ERR, "Listen failed, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_LISTEN_ERROR;
            break;
        }

        log_msg(LOG_DEBUG, "TCP server socket created on %s:%u", server_ip ? server_ip : "0.0.0.0", server_port);
        *ssock = sock;
        result = RESULT_OK;

    } while(0);

    if (!isOk(result)) {
        socket_close(sock);
    }

    return result;
}
/***********************************************************************************************/
int socket_tcp_client_create(int *ssock, const char *local_ip, u16 local_port, const char *server_ip, u16 server_port)
{
    int result = RESULT_NOT_INITED_ERROR;
    int sock = -1;
    int yes = 1;

    do {
        if (!ssock || !server_ip || !server_port) {
            errno = EINVAL;
            log_msg(LOG_ERR, "Arguments error");
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            log_msg(LOG_ERR, "Socket creation failed, errno=%d [%s]",
                    errno, strerror(errno));
            result = RESULT_SOCKET_CREATE_ERROR;
            break;
        }

        /* Allow fast reuse */
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                       &yes, sizeof(yes)) < 0) {
            log_msg(LOG_ERR, "setsockopt(SO_REUSEADDR) failed, errno=%d [%s]",
                    errno, strerror(errno));
            /* not fatal */
        }

        /* Optional local bind */
        if (local_ip && local_ip[0]) {
            struct sockaddr_in local = {0};

            local.sin_family = AF_INET;
            local.sin_port   = htons(local_port);

            if (inet_pton(AF_INET, local_ip, &local.sin_addr) != 1) {
                log_msg(LOG_ERR, "inet_pton(local_ip) failed, errno=%d [%s]",
                        errno, strerror(errno));
                result = RESULT_INET_PTON_ERROR;
                break;
            }

            if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
                log_msg(LOG_ERR, "Bind failed, errno=%d [%s]",
                        errno, strerror(errno));
                result = RESULT_SOCKET_BIND_ERROR;
                break;
            }
        }

        /* Server address */
        struct sockaddr_in server = {0};

        server.sin_family = AF_INET;
        server.sin_port   = htons(server_port);

        if (inet_pton(AF_INET, server_ip, &server.sin_addr) != 1) {
            log_msg(LOG_ERR, "inet_pton(server_ip) failed, errno=%d [%s]",
                    errno, strerror(errno));
            result = RESULT_INET_PTON_ERROR;
            break;
        }

        /* --- Make socket unlocked --- */
        int flags = fcntl(sock, F_GETFL, 0);
        if (flags < 0) {
            result = RESULT_SOCKET_CONNECT_ERROR;
            break;
        }

        if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
            result = RESULT_SOCKET_CONNECT_ERROR;
            break;
        }

        int rc = connect(sock, (struct sockaddr*)&server, sizeof(server));
        if (rc < 0) {
            if (errno != EINPROGRESS) {
                log_msg(LOG_ERR, "Connect failed, errno=%d [%s]",
                        errno, strerror(errno));
                result = RESULT_SOCKET_CONNECT_ERROR;
                break;
            }

            struct pollfd pfd = {
                .fd = sock,
                .events = POLLOUT
            };

            rc = poll(&pfd, 1, CONNECT_TIMEOUT_MS);
            if (rc == 0) {
                log_msg(LOG_ERR, "Connect timeout");
                result = RESULT_SOCKET_CONNECT_TIMEOUT;
                break;
            }
            if (rc < 0) {
                log_msg(LOG_ERR, "poll error: %s", strerror(errno));
                result = RESULT_SOCKET_CONNECT_ERROR;
                break;
            }

            int so_error = 0;
            socklen_t slen = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &slen);
            if (so_error != 0) {
                errno = so_error;
                log_msg(LOG_ERR, "Connect failed, errno=%d [%s]",
                        errno, strerror(errno));
                result = RESULT_SOCKET_CONNECT_ERROR;
                break;
            }
        }

        fcntl(sock, F_SETFL, flags);

        log_msg(LOG_DEBUG, "TCP client connected to %s:%u",
                server_ip, server_port);

        *ssock = sock;
        result = RESULT_OK;

    } while (0);

    if (!isOk(result)) {
        socket_close(sock);
    }

    return result;
}
/***********************************************************************************************/
int socket_close(int sock)
{
    int result = RESULT_ARGUMENT_ERROR;
    if (sock >= 0) {
        setsockopt(sock, SOL_SOCKET, SO_LINGER, &(struct linger){1, 0}, sizeof(struct linger));
        if (close(sock) < 0) {
            log_msg(LOG_ERR, "Can't close socket %d, errno = %d [%s]", sock, errno, strerror(errno));
            result = RESULT_SOCKET_CLOSE_ERROR;
        }
        else {
            result = RESULT_OK;
        }
    }
    return result;
}
/***********************************************************************************************/
int fd_close(int fd)
{
    int result = RESULT_ARGUMENT_ERROR;
    if (fd >= 0) {
        if (close(fd) < 0) {
            log_msg(LOG_ERR, "Can't close fd %d, errno = %d [%s]", fd, errno, strerror(errno));
            result = RESULT_FILE_CLOSE_ERROR;
        }
        else {
            result = RESULT_OK;
        }
    }
    return result;
}
/***********************************************************************************************/
int socket_send_data(int sock, void* buff, ssize_t sz)
{
    const uint8_t *p = buff;
    size_t left = sz;
    int64_t deadline = 0;
    int64_t remaining = 0;
    int pr = -1;
    int result = RESULT_OK;

    do {
        if (!buff || !sz) {
            log_msg(LOG_ERR, "Arguments error");
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        int flags = fcntl(sock, F_GETFL, 0);
        if (flags < 0) {
            result = RESULT_SOCKET_SEND_ERROR;
            break;
        }

        if (!(flags & O_NONBLOCK)) {
            if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
                result = RESULT_SOCKET_SEND_ERROR;
                break;
            }
        }

        deadline = now_ms() + POLL_TIMEOUT_MS;

        while (left > 0) {

            ssize_t n = write(sock, p, left);
            if (n > 0) {
                p += n;
                left -= n;
                continue;
            }

            if (n == 0) {
                log_msg(LOG_ERR, "socket closed by peer");
                result = RESULT_SOCKET_SEND_ERROR;
                break;
            }

            if (errno == EINTR) {
                continue;
            }

            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                log_msg(LOG_ERR, "write failed: %s", strerror(errno));
                result = RESULT_SOCKET_SEND_ERROR;
                break;
            }

            remaining = deadline - now_ms();
            if (remaining <= 0) {
                log_msg(LOG_ERR, "socket send timeout");
                result = RESULT_SOCKET_SEND_TIMEOUT;
                break;
            }

            struct pollfd pfd = {
                .fd = sock,
                .events = POLLOUT
            };

            pr = poll(&pfd, 1, (int)remaining);
            if (pr < 0) {
                if (errno == EINTR) {
                    continue;
                }
                log_msg(LOG_ERR, "poll error: %s", strerror(errno));
                result = RESULT_SOCKET_SEND_ERROR;
                break;
            }

            if (pr == 0) {
                log_msg(LOG_ERR, "socket send timeout");
                result = RESULT_SOCKET_SEND_TIMEOUT;
                break;
            }

            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                log_msg(LOG_ERR, "socket error revents=0x%x", pfd.revents);
                result = RESULT_SOCKET_SEND_ERROR;
                break;
            }
        }
    } while(0);

    return result;
}
/***********************************************************************************************/
int socket_read_data(int sock, void *buff, ssize_t *sz, int timeout_ms)
{
    static struct pollfd pollfds[1];
    int result = RESULT_NODATA;

    do {
        if (!buff || !sz) {
            log_msg(LOG_ERR, "Arguments error");
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        pollfds[0].fd = sock;
        pollfds[0].events = POLLIN | POLLPRI;

        int poll_result = poll(pollfds, 1, timeout_ms);
        if (poll_result > 0) {
            if (pollfds[0].revents & POLLIN) {
                struct sockaddr_ll sll;
                socklen_t sll_len = sizeof(sll);
                *sz = recvfrom(sock, buff, *sz, 0, (struct sockaddr*)&sll, &sll_len);

                if (sll.sll_pkttype != PACKET_OUTGOING && *sz > 0) {
                    result = RESULT_OK;
                }
            }
        }
    } while(0);

    return result;
}
/***********************************************************************************************/
int tup_init(const char *device, const char *tun_ip, int *tun_fd)
{
    int result = RESULT_OK;
    int fd = -1;

    do {
        if (!device || !tun_ip || !tun_fd) {
            log_msg(LOG_ERR, "Arguments error");
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        result = tun_alloc((char *)device, &fd);
        if (!isOk(result)) {
            break;
        }

        result = tun_set_up(device);
        if (!isOk(result)) {
            break;
        }

        result = tun_has_ip(device, tun_ip);
        if (isOk(result) || result == RESULT_NOT_INITED) {
            result = tun_add_ip(device, tun_ip);
            if (!isOk(result)) {
                break;
            }
        }

    } while(0);

    *tun_fd = fd;

    return result;
}
/***********************************************************************************************/
ssize_t read_tun_packet(int tun_fd, uint8_t *buf)
{
    static int nonblock_set = 0;
    ssize_t n = -1;

    do {
        if (!buf) {
            log_msg(LOG_ERR, "Arguments error");
            break;
        }

        if (!nonblock_set) {
            int flags = fcntl(tun_fd, F_GETFL, 0);
            fcntl(tun_fd, F_SETFL, flags | O_NONBLOCK);
            nonblock_set = 1;
        }

        n = read(tun_fd, buf, MAX_PKT_SIZE);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                log_msg(LOG_ERR, "TUN read error: %s", strerror(errno));
            }
            n = 0;
            break;
        }
    } while(0);

    return n;
}
/***********************************************************************************************/
ssize_t write_tun_packet(int tun_fd, uint8_t *buf, size_t len)
{
    ssize_t n = -1;
    do {
        if (!buf) {
            log_msg(LOG_ERR, "Arguments error");
            break;
        }

        n = write(tun_fd, buf, len);
        if (n < 0) {
            log_msg(LOG_ERR, "TUN write error: %s", strerror(errno));
        }
    } while(0);

    return n;
}
/***********************************************************************************************/
