#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>
#include "error_code.h"

/***********************************************************************************************/
static inline
bool isOk(int result) { return result == RESULT_OK; }
/***********************************************************************************************/
#define COUNTOF(array) (sizeof(array)/sizeof(*(array)))
#define LOCK(__m)  pthread_mutex_lock(&__m)
#define TRYLOCK(__m)  pthread_mutex_trylock(&__m)
#define LOCKSPIN(__m)  pthread_spin_lock(&__m)
#define TRYLOCKSPIN(__m)  pthread_spin_trylock(&__m)
#define UNLOCK_CV(__c, __m)               \
    ({                                    \
    pthread_cond_signal(&__c);            \
    pthread_mutex_unlock(&__m);           \
    })
#define UNLOCK(__m) pthread_mutex_unlock(&__m)
#define UNLOCKSPIN(__m) pthread_spin_unlock(&__m)
#define UNUSED(x) (void)(x)
#define ARRAY_SIZE(x) ((sizeof(x)/sizeof(*x)))
#define IS_DIGIT(b) ((u8)(b) >= (u8)'0' && (u8)(b) <= (u8)'9')
/***********************************************************************************************/
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
typedef int64_t  s64;
typedef int32_t  s32;
typedef int16_t  s16;
typedef int8_t   s8;
/***********************************************************************************************/
