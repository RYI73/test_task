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
int parse_packet(const u8 *buffer, size_t len)
{
    int result = INET_PACKTYPE_BAD;

    do {
        if (len < sizeof(struct ethhdr)) {
            print_string("Packet too short for Ethernet\n");
            break;
        }

        const struct ethhdr *eth = (const struct ethhdr *)buffer;
        u16 eth_type = ntohs(eth->h_proto);

    //    char dst_mac[18], src_mac[18];
    //    snprintf(dst_mac, sizeof(dst_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
    //             eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
    //             eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    //    snprintf(src_mac, sizeof(src_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
    //             eth->h_source[0], eth->h_source[1], eth->h_source[2],
    //             eth->h_source[3], eth->h_source[4], eth->h_source[5]);

    //    printf("EtherType: 0x%04X", eth_type);
    //    printf("dst_mac %s", dst_mac);
    //    printf("src_mac %s", src_mac);

    //    printf("Packet sz %zu", len);
        if (eth_type == ETH_P_IP) {
            if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
                print_string("Packet too short for IPv4 header\n");
                break;
            }

            const struct iphdr *ip = (const struct iphdr *)(buffer + sizeof(struct ethhdr));
//            char src_ip_str[INET_ADDRSTRLEN];
//            char dst_ip_str[INET_ADDRSTRLEN];
//            inet_ntop(AF_INET, &ip->saddr, src_ip_str, sizeof(src_ip_str));
//            inet_ntop(AF_INET, &ip->daddr, dst_ip_str, sizeof(dst_ip_str));
//            printf("IPv4 %s -> %s\n", src_ip_str, dst_ip_str);

            if (ip->protocol == IPPROTO_TCP) {
//                const struct tcphdr *tcp = (const struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);
//                printf("TCP %u -> %u\n", ntohs(tcp->source), ntohs(tcp->dest));
                result = INET_PACKTYPE_TCP;
                break;
            } else if (ip->protocol == IPPROTO_UDP) {
//                const struct udphdr *udp = (const struct udphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);
//                printf("UDP %u -> %u\n", ntohs(udp->source), ntohs(udp->dest));
                result = INET_PACKTYPE_UDP;
                break;
            } else {
//                printf("IP proto %u\n", ip->protocol);
                result = INET_PACKTYPE_IP;
                break;
            }

        } else if (eth_type == ETH_P_ARP) {
//            printf("ARP packet\n");
            result = INET_PACKTYPE_ARP;
            break;
        } else {
//            printf("Unknown EtherType 0x%04X\n", eth_type);
            result = INET_PACKTYPE_UNKNOWN;
            break;
        }
    } while(0);

    return result;
}
/***********************************************************************************************/
int socket_raw_create(int *ssock, char *if_name)
{
    int result = RESULT_NOT_INITED_ERROR;
    int sock = -1;

    do {
        if (!ssock) {
            log_msg(LOG_ERR, "Arguments error");
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock < 0) {
            log_msg(LOG_ERR, "Socket creation failed, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_CREATE_ERROR;
            break;
        }
//        if (is_rx) {
//            int one = 1;
//            setsockopt(sock, SOL_PACKET, PACKET_ORIGDEV, &one, sizeof(one));
//        }

        log_msg(LOG_DEBUG, "Socket %d created", sock);

        struct ifreq ifr = {0};
        strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
        ioctl(sock, SIOCGIFINDEX, &ifr);
        if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
            log_msg(LOG_ERR, "Error in obtaining the network interface index, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_IOCTL_ERROR;
            break;
        }

        struct packet_mreq mr = {0};
        mr.mr_ifindex = ifr.ifr_ifindex;
        mr.mr_type = PACKET_MR_PROMISC;

        if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
            log_msg(LOG_ERR, "setsockopt (PROMISC) failed, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_BIND_ERROR;
            break;
        }

        struct sockaddr_ll sll = {
            .sll_family = AF_PACKET,
            .sll_ifindex = ifr.ifr_ifindex,
            .sll_protocol = htons(ETH_P_ALL)
        };

        if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            log_msg(LOG_ERR, "Bind failed, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_BIND_ERROR;
            break;
        }
        log_msg(LOG_DEBUG, "Bind done");

//        listen(sock , 3);
        *ssock = sock;
        result = RESULT_OK;
    } while(0);

    if (!isOk(result)) {
        socket_close(sock);
    }

    return result;
}
/***********************************************************************************************/
int socket_lo_up()
{
    int result = RESULT_NOT_INITED_ERROR;

    do {
        int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (sock < 0) {
            log_msg(LOG_ERR, "Socket netlink creation failed, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_CREATE_ERROR;
            break;
        }

        struct {
            struct nlmsghdr nh;
            struct ifinfomsg ifi;
            char buf[256];
        } req;

        memset(&req, 0, sizeof(req));

        // Netlink header
        req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
        req.nh.nlmsg_type = RTM_NEWLINK;
        req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

        // Interface info (lo = ifindex 1 on Linux)
        req.ifi.ifi_family = AF_UNSPEC;
        req.ifi.ifi_index = 1;     // lo interface index
        req.ifi.ifi_change = 0xffffffff;
        req.ifi.ifi_flags |= IFF_UP;

        // Destination address (kernel)
        struct sockaddr_nl nl = {0};
        nl.nl_family = AF_NETLINK;

        struct iovec iov = {
            .iov_base = &req,
            .iov_len  = req.nh.nlmsg_len
        };

        struct msghdr msg = {
            .msg_name = &nl,
            .msg_namelen = sizeof(nl),
            .msg_iov = &iov,
            .msg_iovlen = 1,
        };

        if (sendmsg(sock, &msg, 0) < 0) {
            log_msg(LOG_ERR, "Failed to send netlink message, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_SEND_ERROR;
            break;
        }

        close(sock);
        result = RESULT_OK;

    } while(0);

    return result;
}
/***********************************************************************************************/
int socket_udp_create_rx(int *ssock, const char *local_ip, u16 local_port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return RESULT_SOCKET_CREATE_ERROR;

    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_port   = htons(local_port);
    local.sin_addr.s_addr = (local_ip && local_ip[0]) ?
        inet_addr(local_ip) : htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
        socket_close(sock);
        return RESULT_SOCKET_BIND_ERROR;
    }

    *ssock = sock;
    return RESULT_OK;
}
/***********************************************************************************************/
int socket_udp_create(int *ssock, const char *local_ip, u16 local_port, const char *dst_ip, u16 dst_port)
{
    int result = RESULT_NOT_INITED_ERROR;
    int sock = -1;
    int yes = 1;

    do {
        if (!dst_ip || !dst_port) {
            errno = EINVAL;
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

        // Optional: allow fast rebind after restart
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
            log_msg(LOG_ERR, "setsockopt(SO_REUSEADDR) failed, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_BIND_ERROR;
            break;
            // not fatal
        }

        // Optional local bind
        if (local_ip && local_ip[0]) {
            struct sockaddr_in local;
            memset(&local, 0, sizeof(local));
            local.sin_family = AF_INET;
            local.sin_port   = htons(local_port);
            if (inet_pton(AF_INET, local_ip, &local.sin_addr) != 1) {
                log_msg(LOG_ERR, "inet_pton(local_ip), errno = %d [%s]", errno, strerror(errno));
                result = RESULT_INET_PTON_ERROR;
                break;
            }
            if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
                log_msg(LOG_ERR, "Bind failed, errno = %d [%s]", errno, strerror(errno));
                result = RESULT_SOCKET_BIND_ERROR;
                break;
            }
        }

        // Connect to destination (binds default peer for send()/recv())
        struct sockaddr_in peer;
        memset(&peer, 0, sizeof(peer));
        peer.sin_family = AF_INET;
        peer.sin_port   = htons(dst_port);
        if (inet_pton(AF_INET, dst_ip, &peer.sin_addr) != 1) {
            log_msg(LOG_ERR, "inet_pton(dst_ip), errno = %d [%s]", errno, strerror(errno));
            result = RESULT_INET_PTON_ERROR;
            break;
        }
        if (connect(sock, (struct sockaddr*)&peer, sizeof(peer)) < 0) {
            log_msg(LOG_ERR, "Connect failed, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_CONNECT_ERROR;
            break;
        }
        log_msg(LOG_DEBUG, "UDP socket created");

        *ssock = sock;
        result = RESULT_OK;

    } while(0);

    if (!isOk(result)) {
        socket_close(sock);
    }

    return result;
}
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

        if (server_ip && server_ip[0]) {
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

        if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
            log_msg(LOG_ERR, "Connect failed, errno=%d [%s]",
                    errno, strerror(errno));
            result = RESULT_SOCKET_CONNECT_ERROR;
            break;
        }

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
int socket_tun_open_ip(int *ssock, const char *ifname, int nonblock)
{
    int result = RESULT_NOT_INITED_ERROR;
    int sock = -1;

    do {
        if (!ifname || !*ifname) {
            errno = EINVAL;
            log_msg(LOG_ERR, "Arguments error");
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        sock = open(DEVICE_TUN, O_RDWR | O_CLOEXEC);
        if (sock < 0) {
            log_msg(LOG_ERR, "Open deevice %s failed, errno = %d [%s]", DEVICE_TUN, errno, strerror(errno));
            result = RESULT_OPEN_DEVICE_ERROR;
            break;
        }

        struct ifreq ifr = {0};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

        if (ioctl(sock, TUNSETIFF, (void *)&ifr) < 0) {
            log_msg(LOG_ERR, "Error in set of tun IFF, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_IOCTL_ERROR;
            break;
        }

        if (nonblock) {
            int fl;
            do {
                fl = fcntl(sock, F_GETFL, 0);
            } while (fl < 0 && errno == EINTR);
            if (fl < 0) {
                log_msg(LOG_ERR, "Error in fcntl(F_GETFL), errno = %d [%s]", errno, strerror(errno));
                result = RESULT_FCNTL_ERROR;
                break;
            }
            if (fcntl(sock, F_SETFL, fl | O_NONBLOCK) < 0) {
                log_msg(LOG_ERR, "Error in fcntl(F_SETFL,O_NONBLOCK), errno = %d [%s]", errno, strerror(errno));
                result = RESULT_FCNTL_ERROR;
                break;
            }
        }
        log_msg(LOG_DEBUG, "TUN opened successfuly");

        *ssock = sock;
        result = RESULT_OK;

    } while(0);

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
        if (close(sock) < 0) {
            log_msg(LOG_ERR, "Can't close socket %d, errno = %d [%s]", sock, errno, strerror(errno));
            result = RESULT_SOCKET_CLOSE_ERROR;
        }
        else {
            log_msg(LOG_INFO, "Closed socket %d", sock);
            result = RESULT_OK;
        }
    }
    return result;
}
/***********************************************************************************************/
int socket_send_data(int sock, void* buff, ssize_t sz)
{
    int result = RESULT_OK;
    do {
        int res = write(sock, buff, sz);
        if (res < 0) {
            log_msg(LOG_ERR, "Can't send message, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_SEND_ERROR;
            break;
        }
    } while(0);

    return result;
}
/***********************************************************************************************/
int socket_read_data(int sock, void *buff, ssize_t *sz, int timeout_ms)
{
    int result = RESULT_NODATA;

    static struct pollfd pollfds[1];

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
    return result;
}
/***********************************************************************************************/
int socket_udp_read(int sock, void *buff, u16 *sz, int timeout_ms)
{
    if (!buff || !sz || *sz <= 0) {
        errno = EINVAL;
        return RESULT_ARGUMENT_ERROR;
    }

    struct pollfd pfd = {
        .fd = sock,
        .events = POLLIN
    };

    int n = poll(&pfd, 1, timeout_ms);
    if (n < 0) {
        log_msg(LOG_ERR, "poll() failed, errno=%d [%s]", errno, strerror(errno));
        return RESULT_POLL_ERROR;
    }
    if (n == 0) {
        return RESULT_NODATA; // timeout
    }

    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        log_msg(LOG_ERR, "poll() error revents=0x%x", pfd.revents);
        return RESULT_SOCKET_IO_ERROR;
    }

    if (pfd.revents & POLLIN) {
        // для connected UDP краще просто recv()
        ssize_t cap = *sz;
        ssize_t r = recv(sock, buff, cap, 0);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return RESULT_NODATA;
            log_msg(LOG_ERR, "recv() failed, errno=%d [%s]", errno, strerror(errno));
            return RESULT_SOCKET_READ_ERROR;
        }
        if (r == 0) {
            return RESULT_NODATA; // для UDP рідко, але позначимо
        }
        *sz = (u16)r;
        return RESULT_OK;
    }

    return RESULT_NODATA;
}
/***********************************************************************************************/
int socket_read_tun(int sock, void *buff, u16 *sz, int timeout_ms)
{
    if (!buff || !sz || *sz <= 0) {
        print_string("❌ argument error: buff %p sz %p *sz %d\n", buff, sz, *sz);
        return RESULT_ARGUMENT_ERROR;
    }

    struct pollfd p = { .fd = sock, .events = POLLIN };
    int pr;
    do {
        pr = poll(&p, 1, timeout_ms);
    } while (pr < 0 && errno == EINTR);

    if (pr == 0) {
        return RESULT_TIMEOUT;
    }
    else if (pr < 0) {
        print_string("❌ read_tun: poll() failed, errno=%d [%s]\n", errno, strerror(errno));
        log_msg(LOG_ERR, "poll() failed, errno=%d [%s]", errno, strerror(errno));
        return RESULT_POLL_ERROR;
    }

    if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        print_string("❌ read_tun: RESULT_SOCKET_ERROR\n");
        return RESULT_SOCKET_ERROR;
    }

    ssize_t cap = *sz;
    ssize_t n;
    do {
        n = read(sock, buff, cap);
    } while (n < 0 && errno == EINTR);

    if (n > 0) {
        *sz = (u16)n;
        return RESULT_OK;
    }
    if (n == 0) {
        print_string("❌ read_tun: RESULT_NOT_INITED_ERROR\n");
        return RESULT_NOT_INITED_ERROR;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        print_string("❌ read_tun: RESULT_NODATA\n");
        return RESULT_NODATA;
    }

    print_string("❌ read() failed, errno=%d [%s]\n", errno, strerror(errno));
    log_msg(LOG_ERR, "read() failed, errno=%d [%s]", errno, strerror(errno));
    return RESULT_SOCKET_READ_ERROR;
}
/***********************************************************************************************/
int socket_send_tun(int sock, const void *buff, size_t sz)
{
    if (!buff || sz == 0) return RESULT_ARGUMENT_ERROR;

    struct pollfd p = { .fd = sock, .events = POLLOUT };
    int pr;
    do { pr = poll(&p, 1, 2000); } while (pr < 0 && errno == EINTR);
    if (pr == 0)               return RESULT_TIMEOUT;
    if (pr < 0)                return RESULT_POLL_ERROR;
    if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) return RESULT_SOCKET_ERROR;

    ssize_t n;
    do {
        n = write(sock, buff, sz);
    } while (n < 0 && errno == EINTR);

    if (n == (ssize_t)sz) {
        return RESULT_OK;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return RESULT_NODATA;
    }

    // For TUN, a short record is atypical; we interpret it as an error.
    log_msg(LOG_ERR, "write() failed/short: want=%zu got=%zd, errno=%d [%s]",
           sz, n, errno, strerror(errno));
    print_string("write() failed/short: want=%zu got=%zd, errno=%d [%s]\n", sz, n, errno, strerror(errno));
    return RESULT_SOCKET_SEND_ERROR;
}
/***********************************************************************************************/
int get_mac_address(const char *ifname, u8 *mac_out)
{
    int result = RESULT_OK;
    int fd = -1;

    do {
        if (!ifname || !mac_out) {
            log_msg(LOG_ERR, "Arguments error");
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            log_msg(LOG_ERR, "Socket creation failed, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_CREATE_ERROR;
            break;
        }

        struct ifreq ifr = {0};
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';

        if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
            log_msg(LOG_ERR, "Error in obtaining the network interface index, errno = %d [%s]", errno, strerror(errno));
            result = RESULT_SOCKET_IOCTL_ERROR;
            break;
        }

        memcpy(mac_out, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    } while(0);

    if (fd >= 0) {
        close(fd);
    }

    return result;
}
/***********************************************************************************************/
bool is_packet_our(const u8 *packet, const u8 *this_mac)
{
    bool result = false;

    const u8 *dst_mac = packet;
    const u8 *src_mac = packet + ETH_ALEN;

    // Ignore self-generated packets
    if (memcmp(src_mac, this_mac, ETH_ALEN) == 0) {
//        print_dump(node->data, len, "DropOwn");
        result = true;
    }

    // Unicast to this host?
    if (memcmp(dst_mac, this_mac, ETH_ALEN) == 0) {
        result = true;
    }

    // Debug: ignore Cisco Realtek Layer 2 Protocols from MAC: 24 D7 9C E4 9E 61
//    const u8 cisco_mac[] = {0x61, 0x9E, 0xE4, 0x9C, 0xD7, 0x24};
    const u8 cisco_mac[] = {0x24, 0xD7, 0x9C, 0xE4, 0x9E, 0x61};
    if (memcmp(src_mac, cisco_mac, ETH_ALEN) == 0) {
        result = true;
    }

    return result;
}
/***********************************************************************************************/
#include <arpa/inet.h>

int parse_ipv4_udp(const uint8_t *buf, size_t len, char *str)
{
    if (!buf || len < 20) {
        fprintf(stderr, "Buffer too small for IPv4 header\n");
        return -1;
    }

    uint8_t ver = buf[0] >> 4;
    uint8_t ihl = buf[0] & 0x0F;          // in 32-bit words
    size_t ip_hlen = (size_t)ihl * 4;

    if (ver != 4) {
        fprintf(stderr, "Not IPv4 (version=%u)\n", ver);
        return -1;
    }
    if (ihl < 5 || ip_hlen > len) {
        fprintf(stderr, "Invalid IPv4 header length\n");
        return -1;
    }

    // Total length (bytes 2-3, network byte order)
    uint16_t ip_total_len = (uint16_t)((buf[2] << 8) | buf[3]);
    if (ip_total_len < ip_hlen || ip_total_len > len) {
        // allow outer len to be larger (packet capture padding), but not smaller
        if (ip_total_len < ip_hlen || ip_total_len > len) {
            fprintf(stderr, "Invalid IPv4 total length\n");
            return -1;
        }
    }

    uint8_t proto = buf[9];
    if (proto != 17) {
        fprintf(stderr, "Not UDP (protocol=%u)\n", proto);
        return -1;
    }

    // Source/Destination IPv4 addresses (bytes 12-15, 16-19)
    struct in_addr src_addr, dst_addr;
    memcpy(&src_addr, buf + 12, 4);
    memcpy(&dst_addr, buf + 16, 4);

    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &src_addr, src_str, sizeof(src_str)) ||
        !inet_ntop(AF_INET, &dst_addr, dst_str, sizeof(dst_str))) {
        perror("inet_ntop");
        return -1;
    }

    // UDP header starts right after IP header
    if (len < ip_hlen + 8) {
        fprintf(stderr, "Buffer too small for UDP header\n");
        return -1;
    }
    const uint8_t *udp = buf + ip_hlen;

    uint16_t src_port = (uint16_t)((udp[0] << 8) | udp[1]);
    uint16_t dst_port = (uint16_t)((udp[2] << 8) | udp[3]);
    uint16_t udp_len  = (uint16_t)((udp[4] << 8) | udp[5]);

    // Sanity checks for UDP length
    size_t ip_payload_len = ip_total_len ? (size_t)ip_total_len - ip_hlen : len - ip_hlen;
    if (udp_len < 8 || udp_len > ip_payload_len) {
        fprintf(stderr, "Invalid UDP length\n");
        return -1;
    }

    if (str && dst_port==8000) {
        sprintf(str, "IPv4 src=%s, dst=%s | UDP sport=%u, dport=%u\n",
               src_str, dst_str, (unsigned)src_port, (unsigned)dst_port);
    }
    return 0;
}
/***********************************************************************************************/
