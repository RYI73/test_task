#pragma once

#include "defaults.h"
#include "types.h"

/***********************************************************************************************/
typedef struct {
    struct {
        u32 sequence;
        u32 len;
        u16 crc;
        u8  type;
        s8  result;
    } header;
    u8 data[];
} pack_t;
/***********************************************************************************************/
typedef union {
    u8 buffer[PACKET_SIZE];
    pack_t packet;
} packet_t;
/***********************************************************************************************/
enum packet_type_e {
    PACKET_TYPE_STRING,
    PACKET_TYPE_ARRAY
};
/***********************************************************************************************/
