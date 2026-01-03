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
/* Internal functions                                                                          */
/***********************************************************************************************/
/**
 * @brief Export a GPIO via sysfs
 *
 * @param gpio Global Linux GPIO number
 * @return 0 on success, -1 on error
 */
static int export_gpio(int gpio)
{
    int fd = -1;
    char buf[16];
    int len = 0;
    int result = RESULT_OK;

    do {
        fd = open(GPIO_EXPORT, O_WRONLY);
        if (fd < 0) {
            log_msg(LOG_ERR, "Unable to open %s: %s", GPIO_EXPORT, strerror(errno));
            result = RESULT_FILE_OPEN_ERROR;
            break;
        }

        len = snprintf(buf, sizeof(buf), "%d", gpio);

        if (write(fd, buf, len) < 0) {
            if (errno != EBUSY) {  // EBUSY: already exported — not error.
                log_msg(LOG_ERR, "Write export failed: %s", strerror(errno));
                result = RESULT_FILE_WRITE_ERROR;
                break;
            }
        }

    } while(0);

    fd_close(fd);

    return result;
}
/***********************************************************************************************/
/**
 * @brief Read GPIO chip base number
 *
 * @return Base GPIO number, or -1 on error
 */
static int read_gpiochip_base(int *number)
{
    int fd = -1;
    int gpio_number = -1;
    DIR *dir = NULL;
    struct dirent *ent;
    char path[256];
    char buf[32];
    int result = RESULT_NODATA;

    do {
        dir = opendir(GPIO_CLASS);
        if (!dir) {
            log_msg(LOG_ERR, "Unable to open DIR %s: '%s'", GPIO_CLASS, strerror(errno));
            result = RESULT_FILE_OPEN_ERROR;
            break;
        }

        while ((ent = readdir(dir)) != NULL) {
            if (strncmp(ent->d_name, "gpiochip", 8) == 0) {
                snprintf(path, sizeof(path), GPIO_BASE, ent->d_name);

                fd = open(path, O_RDONLY);
                if (fd < 0) {
                    continue;
                }

                ssize_t n = read(fd, buf, sizeof(buf) - 1);
                fd_close(fd);

                if (n > 0) {
                    buf[n] = '\0';
                    gpio_number = atoi(buf);
                    result = RESULT_OK;
                    break;
                }
            }
        }

    } while(0);

    if (dir != NULL) {
        closedir(dir);
    }

    *number = gpio_number;

    return result;
}
/***********************************************************************************************/
/* External functions                                                                          */
/***********************************************************************************************/
int gpio_init(const char *device, int offset, int *gpio_fd)
{
    int result = RESULT_NOT_INITED;
    int fd = -1;
    int base = -1;
    int gpio = -1;

    do {
        fd = open(device, O_RDONLY);
        if (fd < 0) {
            log_msg(LOG_ERR, "Unable to open device '%s': %s", device, strerror(errno));
            result = RESULT_FILE_OPEN_ERROR;
            break;
        }

        // Export GPIO
        result = read_gpiochip_base(&base);
        if (!isOk(result)) {
            log_msg(LOG_ERR, "Failed to read gpiochip base");
            break;
        }

        gpio = base + offset;

        log_msg(LOG_INFO, "gpiochip base = %d\n", base);
        log_msg(LOG_INFO, "Exporting GPIO %d (offset %d)\n", gpio, offset);

        result = export_gpio(gpio);

    } while(0);

    *gpio_fd = fd;

    return result;
}
/***********************************************************************************************/
