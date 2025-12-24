/*******************************************************************************
 *   @file   src/helpers.c
 *   @brief  Implementation of helper functions.
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
#include <ctype.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <math.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>

#include "helpers.h"
#include "defines.h"
#include "defaults.h"
#include "error_code.h"
#include "protocol.h"

static pthread_mutex_t lock;

/***********************************************************************************************/
__attribute__((format(printf, 1, 2)))
void print_string(const char* message, ...) {
    va_list args;
    LOCK(lock);
    va_start(args, message);
    vprintf(message, args);
    va_end(args);
    UNLOCK(lock);
}
/***********************************************************************************************/
void print_dump(u8 *buff, u32 sz, char *pref)
{
    LOCK(lock);
    char str[64];
    if (pref != NULL) {
        snprintf(str, sizeof(str), "[%s] ", pref);
    }
    if (sz > MAX_DUMP_BUFFER_SIZE) {
//        printf("Real dump buffer size %zu reduced to %zu bytes\n", sz, MAX_DUMP_BUFFER_SIZE);
//        sz = MAX_DUMP_BUFFER_SIZE;
    }
    printf("%sDump (%u bytes):\r\n", pref==NULL?"":str, sz);
    char symbols[16] = {0};
    u32 symCntr = 0;
    for (u32 j=0; j<sz; j++) {
        if (j % 16 == 0) {
            printf("%06Xh: ", j);
        }
        printf("%02X ", buff[j]);
        symbols[symCntr++] = buff[j];
        u32 p = j+1;
        if (p % 16 == 0 || p == sz) {
            if (p == sz && p % 16 != 0) {
                for (u32 i=0; i<16 - p % 16; i++) {
                    printf("   ");
                }
            }
            printf("| ");
            for (u32 i=0; i<symCntr; i++) {
                printf("%c", (isalpha((int)symbols[i]) || isdigit((int)symbols[i])) ? symbols[i] : '.');
            }
            symCntr = 0;
            printf("\n");
        }
    }
    printf("\n");
    UNLOCK(lock);
}
/***********************************************************************************************/
char *strupr(char *str)
{
    char *s = str;
    while (*s) {
        *s = toupper((unsigned char)*s);
        s++;
    }
    return str;
}
/***********************************************************************************************/
void posix_putch(void *data, char ch, bool is_last)
{
    LOCK(lock);
    FILE *fp = data;
    fputc(ch, fp);
    if (is_last)
        fflush(fp);
    UNLOCK(lock);
}
/***********************************************************************************************/
void set_raw_mode(int enable)
{
    static struct termios oldt, newt;

    if (enable) {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO | ISIG); // Turn off canonical mode and echo and ISIG turn off Ctrl-C, Ctrl-Z
        newt.c_cc[VMIN] = 1;  // waiting at least 1 byte
        newt.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    } else {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    }
}
/***********************************************************************************************/
void handle_sigint(int sig)
{
    UNUSED(sig);
}
/***********************************************************************************************/
/* Table for polynomial 0x8005 (reversed: 0xA001) */
static const uint16_t crc16_table[256] = {
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};

#define CRC16_STEP(crc_, byte_) \
    do { \
        uint8_t __idx = (uint8_t)((crc_) ^ (uint8_t)(byte_)); \
        (crc_) = (uint16_t)(((crc_) >> 8) ^ crc16_table[__idx]); \
    } while (0)

u16 crc16(const u8 * __restrict data, u32 length)
{
    if (!data || length == 0) return 0xFFFFu;  // same as running over empty input

    const u8 *p = data;
    const u8 *end = data + length;
    u16 crc = 0xFFFFu;

    // Align to 8 bytes (optional micro-optimization)
    while ((((uintptr_t)p) & 7u) && p < end) {
        CRC16_STEP(crc, *p++);
    }

    // Big unrolled blocks: 32 bytes per iteration
    while ((size_t)(end - p) >= 32) {
        __builtin_prefetch(p + 128, 0, 0);

        CRC16_STEP(crc, p[ 0]); CRC16_STEP(crc, p[ 1]);
        CRC16_STEP(crc, p[ 2]); CRC16_STEP(crc, p[ 3]);
        CRC16_STEP(crc, p[ 4]); CRC16_STEP(crc, p[ 5]);
        CRC16_STEP(crc, p[ 6]); CRC16_STEP(crc, p[ 7]);

        CRC16_STEP(crc, p[ 8]); CRC16_STEP(crc, p[ 9]);
        CRC16_STEP(crc, p[10]); CRC16_STEP(crc, p[11]);
        CRC16_STEP(crc, p[12]); CRC16_STEP(crc, p[13]);
        CRC16_STEP(crc, p[14]); CRC16_STEP(crc, p[15]);

        CRC16_STEP(crc, p[16]); CRC16_STEP(crc, p[17]);
        CRC16_STEP(crc, p[18]); CRC16_STEP(crc, p[19]);
        CRC16_STEP(crc, p[20]); CRC16_STEP(crc, p[21]);
        CRC16_STEP(crc, p[22]); CRC16_STEP(crc, p[23]);

        CRC16_STEP(crc, p[24]); CRC16_STEP(crc, p[25]);
        CRC16_STEP(crc, p[26]); CRC16_STEP(crc, p[27]);
        CRC16_STEP(crc, p[28]); CRC16_STEP(crc, p[29]);
        CRC16_STEP(crc, p[30]); CRC16_STEP(crc, p[31]);

        p += 32;
    }

    // Medium blocks: 8 bytes per iteration
    while ((size_t)(end - p) >= 8) {
        CRC16_STEP(crc, p[0]); CRC16_STEP(crc, p[1]);
        CRC16_STEP(crc, p[2]); CRC16_STEP(crc, p[3]);
        CRC16_STEP(crc, p[4]); CRC16_STEP(crc, p[5]);
        CRC16_STEP(crc, p[6]); CRC16_STEP(crc, p[7]);
        p += 8;
    }

    // Tail
    while (p < end) {
        CRC16_STEP(crc, *p++);
    }

    return crc;
}
/***********************************************************************************************/
int hexstr_to_bytes(const char *str, uint8_t *out, size_t max_out, size_t *count)
{
    int result = RESULT_OK;
    *count = 0;

    while (*str) {
        while (*str == ' ' || *str == '\t')
            str++;

        if (*str == '\0')
            break;

        if (!isxdigit((unsigned char)str[0]) ||
            !isxdigit((unsigned char)str[1])) {
            return RESULT_ARGUMENT_ERROR;
        }

        if (*count >= max_out) {
            return RESULT_FULL_BUFFER_ERROR;
        }

        uint8_t byte = 0;
        for (int i = 0; i < 2; i++) {
            byte <<= 4;
            char c = *str++;

            if (c >= '0' && c <= '9') byte |= (c - '0');
            else if (c >= 'A' && c <= 'F') byte |= (c - 'A' + 10);
            else if (c >= 'a' && c <= 'f') byte |= (c - 'a' + 10);
        }

        out[(*count)++] = byte;
    }

    return result;
}
/***********************************************************************************************/
int bytes_to_hexstr(const uint8_t *data, size_t len, char *out, size_t out_size)
{
    int result = RESULT_OK;

    if (!data || !out || out_size == 0)
        return RESULT_ARGUMENT_ERROR;

    static const char hex[] = "0123456789ABCDEF";

    size_t pos = 0;

    for (size_t i = 0; i < len; i++) {

        if (pos + 2 >= out_size)
            break;

        out[pos++] = hex[(data[i] >> 4) & 0x0F];
        out[pos++] = hex[data[i] & 0x0F];

        /* пробіл тільки якщо влазить */
        if (i != len - 1) {
            if (pos + 1 >= out_size)
                break;
            out[pos++] = ' ';
        }
    }

    out[pos] = '\0';

    return result;
}
/***********************************************************************************************/
