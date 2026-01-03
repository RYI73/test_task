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
#include <stdint.h>
#include <stddef.h>

#include "logs.h"
#include "defines.h"
#include "protocol.h"
#include "helpers.h"
#include "error_code.h"

/***********************************************************************************************/
int protocol_packet_prepare(packet_t *packet, u16 seq, size_t len)
{
    int result = RESULT_OK;

    packet->packet.header.prefix   = PACK_PREFIX;
    packet->packet.header.len      = len;
    packet->packet.header.sequence = seq;
    packet->packet.header.crc      = crc16(packet->buffer + PACKET_HEADER_CRC_OFFSET,
                                           len + PACKET_HEADER_CRC_SIZE);

    return result;
}
/***********************************************************************************************/
int protocol_packet_validate(packet_t *packet)
{
    int result = RESULT_OK;
    static u16 last_sequence = 0;
    u16 seq = packet->packet.header.sequence;

    do {
        if (packet->packet.header.prefix != PACK_PREFIX) {
            log_msg(LOG_ERR, "❌ Error: bad prefix. Expected 0x%04X, got 0x%04X",
                    PACK_PREFIX, packet->packet.header.prefix);
            result = RESULT_BAD_PREFIX_ERROR;
            break;
        }
        if (packet->packet.header.crc != crc16(packet->buffer + PACKET_HEADER_CRC_OFFSET, packet->packet.header.len + PACKET_HEADER_CRC_SIZE)) {
            log_msg(LOG_ERR, "❌ Error: bad CRC. Expected 0x%04X, got 0x%04X",
                    crc16(packet->buffer + PACKET_HEADER_CRC_OFFSET,
                          packet->packet.header.len + PACKET_HEADER_CRC_SIZE),
                    packet->packet.header.crc);
            result = RESULT_BAD_CRC_ERROR;
            break;
        }

        if (seq <= last_sequence) {
            log_msg(LOG_ERR, "❌ Error: duplicate packet sequence %u", seq);
            result = RESULT_SEQUENCE_ERROR;
            break;
        }

        u16 skipped = 0;
        if (seq > last_sequence) {
            skipped = seq - last_sequence - 1;
        } else { // wrap-around
            skipped = (UINT16_MAX - last_sequence) + seq;
        }

        if (skipped > 0) {
            log_msg(LOG_WARNING, "⚠️ Skipped %u packet(s) between last (%u) and current (%u)",
                    skipped, last_sequence, seq);
        }

        last_sequence = seq;

    } while(0);

    return result;
}
/***********************************************************************************************/
