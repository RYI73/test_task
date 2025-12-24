/*******************************************************************************
 *   @file   include/helpers.h
 *   @brief  Header of helper functions.
********************************************************************************
 * Copyright 2025(c).
*******************************************************************************/

#pragma once

#include "types.h"

/***********************************************************************************************/
/**
 * @brief Prints a hexadecimal and ASCII dump of a memory buffer.
 *
 * This function takes a pointer to a buffer and its size, and prints a formatted
 * hex dump to standard output. Each line contains 16 bytes in hexadecimal format,
 * followed by the corresponding printable ASCII characters (non-printable characters
 * are replaced with a dot `.`).
 *
 * The output format looks like:
 * ```
 * 000000h: 48 65 6C 6C 6F 20 77 6F 72 6C 64 21 0A         | Hello world!.
 * ```
 *
 * @param buff Pointer to the input buffer (`u8 *`), which contains the data to dump.
 * @param sz The number of bytes in the buffer to print.
 *
 * @note Printable characters are determined using `isalpha()` and `isdigit()`.
 *       Non-printable or control characters are displayed as `.`.
 *
 * @see printf(), isalpha(), isdigit()
 */
void print_dump(u8 *buff, u32 sz, char *pref);
void print_string(const char* message, ...);

/**
 * @brief Signal handler for SIGINT (Ctrl-C).
 *
 * This function is invoked automatically when the process receives
 * the SIGINT signal, which is typically triggered by pressing Ctrl-C
 * in the terminal. It can be used to clean up resources, print messages,
 * or safely terminate the program instead of abruptly exiting.
 *
 * @param sig The signal number received (expected to be SIGINT).
 *
 * @note This function should not perform complex operations (like malloc, printf, or file I/O)
 *       unless you are certain they are async-signal-safe. For basic use cases like logging
 *       or setting a flag, this is typically safe.
 *
 * @see signal(), sigaction(), SIGINT
 */
void handle_sigint(int sig);

/**
 * @brief Enables or disables raw input mode for the terminal.
 *
 * This function modifies the terminal attributes for STDIN to enable or disable
 * raw mode. In raw mode, canonical input, echo, and signal generation (e.g., Ctrl-C, Ctrl-Z)
 * are disabled, allowing real-time character processing (useful for games, shell tools, etc.).
 *
 * On the first call, it saves the current terminal settings. On subsequent calls,
 * it restores or reapplies them depending on the `enable` flag.
 *
 * @param enable If non-zero, raw mode is enabled. If zero, the terminal settings are restored.
 *
 * @note This function modifies global terminal state for the current process.
 *       It should be used carefully in programs that interact with the terminal or shell.
 *
 * @see termios, tcgetattr(), tcsetattr(), ICANON, ECHO, ISIG
 */
void set_raw_mode(int enable);

/**
 * @brief Calculate CRC-16 (Modbus/IBM, poly 0x8005) using lookup table.
 *
 * @param data Pointer to the input data buffer.
 * @param length Number of bytes in the buffer.
 * @return 16-bit CRC result.
 */
u16 crc16(const u8 *data, u32 length);

/**
 * @brief Converts all characters in a string to uppercase.
 *
 * This function iterates through each character in the given null-terminated
 * string `str`, converting any lowercase alphabetical characters to their
 * uppercase equivalents using the standard C `toupper()` function.
 *
 * The conversion is performed in place — the input string is modified directly.
 *
 * @param str Pointer to a modifiable null-terminated string.
 *            Must not be NULL. The string should not be a string literal.
 *
 * @return Returns the same pointer `str` after all characters have been converted to uppercase.
 *
 * @note If `str` is a string literal (e.g., "hello"), this results in undefined behavior.
 *       Make sure to pass a writable buffer, such as a `char[]` array.
 *
 * @see toupper()
 */
char *strupr(char *str);

/**
 * @brief Writes a character to a FILE stream and optionally flushes the stream.
 *
 * This function writes a single character `ch` to the specified output stream `fp`,
 * which is passed as a generic `void *data` pointer (expected to be a `FILE *`).
 * If `is_last` is set to true, the stream is flushed using `fflush()` after writing.
 *
 * This is useful in scenarios where buffered output needs to be committed
 * immediately after writing the final character (e.g., printing lines incrementally).
 *
 * @param data A pointer to the output stream (casted as `void *`, expected to be `FILE *`).
 * @param ch The character to write to the output.
 * @param is_last If true, the function flushes the stream after writing the character.
 *
 * @note Make sure that `data` is a valid and open `FILE *`. Passing NULL or an invalid pointer
 *       may cause undefined behavior.
 *
 * @see fputc(), fflush(), FILE
 */
void posix_putch(void *data, char ch, bool is_last);

/**
 * @brief Prepare a request packet with header and CRC
 *
 * This function fills the packet header fields including prefix, length,
 * sequence number, and computes the CRC over the payload.
 *
 * @param request Pointer to the packet to prepare
 * @param seq Sequence number for this packet
 * @param len Length of the payload
 * @return RESULT_OK on success
 */
int prepare_request(packet_t *request, u16 seq, size_t len);

/**
 * @brief Validate a replay/response packet from server
 *
 * This function checks if the packet prefix and CRC are correct.
 * It also prints the result returned by the server.
 *
 * @param replay Pointer to the received packet
 * @return RESULT_OK if packet is valid,
 *         RESULT_BAD_PREFIX_ERROR if prefix mismatch,
 *         RESULT_BAD_CRC_ERROR if CRC mismatch
 */
int validate_replay(packet_t *replay);

static inline u64 now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000000ull + (u64)ts.tv_nsec;
}

static inline u32 now_ms(void)
{
    return (u32)(now_ns() / 1000000);
}
/***********************************************************************************************/

