#pragma once

#include <stddef.h>

#include "defaults.h"
#include "types.h"

/***********************************************************************************************/
#define PACK_PREFIX        (0x5A2A)
/***********************************************************************************************/
enum packet_type_e {
    PACKET_TYPE_STRING,
    PACKET_TYPE_ARRAY
};
/***********************************************************************************************/
typedef struct {
    struct {
        u16 prefix;
        u16 crc;
        u16 sequence;
        u32 len;
        u8  type;
        u8  result;
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
