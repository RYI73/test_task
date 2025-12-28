#pragma once

#include <stddef.h>

#include "defaults.h"
#include "types.h"

/***********************************************************************************************/
#define PACK_PREFIX        (0x5A2A)
/***********************************************************************************************/
enum packet_type_e {
    PACKET_TYPE_STRING,
    PACKET_TYPE_ARRAY,
    PACKET_TYPE_ANSWER
};
/***********************************************************************************************/
typedef struct {
    struct {
        u16 prefix;
        u16 crc;
        u16 sequence;
        u16 len;
        u16  answer_sequence;
        u16  answer_result;
        u8  type;
        u8  unused[3];
    } header;
    u8 data[];
} pack_t;
/***********************************************************************************************/
typedef union {
    u8 buffer[PACKET_SIZE];
    pack_t packet;
} packet_t;
/***********************************************************************************************/
#define PACKET_HEADER_CRC_OFFSET    (offsetof(packet_t, packet.header.sequence))
#define PACKET_HEADER_SIZE          (sizeof(((packet_t*)0)->packet.header))
#define PACKET_DATA_SIZE            (PACKET_SIZE - PACKET_HEADER_SIZE)
#define PACKET_HEADER_CRC_SIZE      (PACKET_HEADER_SIZE - PACKET_HEADER_CRC_OFFSET)
/***********************************************************************************************/
/**
 * @brief Prepare a request packet with header and CRC
 *
 * This function fills the packet header fields including prefix, length,
 * sequence number, and computes the CRC over the payload.
 *
 * @param packet Pointer to the packet to prepare
 * @param seq Sequence number for this packet
 * @param len Length of the payload
 * @return RESULT_OK on success
 */
int protocol_packet_prepare(packet_t *packet, u16 seq, size_t len);

/**
 * @brief Validate a replay/response packet from server
 *
 * This function checks if the packet prefix and CRC are correct.
 * It also prints the result returned by the server.
 *
 * @param packet Pointer to the received packet
 * @return RESULT_OK if packet is valid,
 *         RESULT_BAD_PREFIX_ERROR if prefix mismatch,
 *         RESULT_BAD_CRC_ERROR if CRC mismatch
 */
int protocol_packet_validate(packet_t *packet);
/***********************************************************************************************/
