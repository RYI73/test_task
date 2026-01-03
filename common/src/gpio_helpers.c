/*******************************************************************************
 *   @file   src/gpio_helpers.c
 *   @brief  Implementation of GPIO helper functions.
 *   @author Ruslan
********************************************************************************
 * Copyright 2026(c).
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
#include <dirent.h>

#include "helpers.h"

#include "logs.h"
#include "types.h"
#include "defines.h"
#include "error_code.h"
#include "socket_helpers.h"

/***********************************************************************************************/
int export_gpio(int gpio)
{
    int fd = open(GPIO_EXPORT, O_WRONLY);
    if (fd < 0) {
        perror("open export");
        return -1;
    }

    char buf[16];
    int len = snprintf(buf, sizeof(buf), "%d", gpio);

    if (write(fd, buf, len) < 0) {
        if (errno != EBUSY)   // already exported — не помилка
            perror("write export");
    }

    close(fd);
    return 0;
}
/***********************************************************************************************/
int read_gpiochip_base(void)
{
    DIR *dir = opendir(GPIO_CLASS);
    if (!dir) {
        perror("opendir");
        return -1;
    }

    struct dirent *ent;
    char path[256];
    char buf[32];

    while ((ent = readdir(dir)) != NULL) {
        if (strncmp(ent->d_name, "gpiochip", 8) == 0) {
            snprintf(path, sizeof(path),
                     GPIO_BASE, ent->d_name);

            int fd = open(path, O_RDONLY);
            if (fd < 0)
                continue;

            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);

            if (n > 0) {
                buf[n] = '\0';
                closedir(dir);
                return atoi(buf);
            }
        }
    }

    closedir(dir);
    return -1;
}
/***********************************************************************************************/
