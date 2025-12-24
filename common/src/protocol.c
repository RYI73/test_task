/*******************************************************************************
 *   @file   src/protocol.c
 *   @brief  Implementation of protocol functions.
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

#include "helpers.h"
#include "defines.h"
#include "defaults.h"
#include "error_code.h"
#include "protocol.h"

/***********************************************************************************************/
int protocol_packet_prepare(packet_t *packet, u16 seq, size_t len)
{
    int result = RESULT_OK;

    packet->packet.header.prefix = PACK_PREFIX;
    packet->packet.header.len = len;
    packet->packet.header.sequence = seq;
    packet->packet.header.crc = crc16(packet->buffer + PACKET_HEADER_CRC_OFFSET, len + PACKET_HEADER_CRC_SIZE);

    return result;
}
/***********************************************************************************************/
int protocol_packet_validate(packet_t *packet)
{
    int result = RESULT_OK;

    do {
        if (packet->packet.header.prefix != PACK_PREFIX) {
            result = RESULT_BAD_PREFIX_ERROR;
            break;
        }
        if (packet->packet.header.crc != crc16(packet->buffer + PACKET_HEADER_CRC_OFFSET, packet->packet.header.len + PACKET_HEADER_CRC_SIZE)) {
            result = RESULT_BAD_CRC_ERROR;
            break;
        }
    } while(0);

    if (!isOk(result)) {
        print_string("❌ broken package. error %u\n", result);
    }

    return result;
}
/***********************************************************************************************/
