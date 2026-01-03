/*******************************************************************************
 *   @file   include/helpers.h
 *   @brief  Header of helper functions.
********************************************************************************
 * Copyright 2025(c).
*******************************************************************************/

#pragma once

#include "types.h"

/**
 * @brief Thread-safe printf wrapper.
 *
 * This function prints a formatted string to standard output (stdout)
 * in a thread-safe manner, using a mutex or similar lock mechanism.
 *
 * @param[in] message Format string (like in printf)
 * @param[in] ...     Variadic arguments to be formatted according to the format string
 *
 * @note Uses LOCK/UNLOCK macros to ensure thread safety.
 * @note Can be combined with GCC/Clang attribute:
 *       __attribute__((format(printf, 1, 2))) to enable compile-time format checking.
 *
 * @example
 * print_string("Hello %s, number=%d\n", "world", 42);
 */
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
 * @brief Compute CRC32 for data integrity check
 *
 * @param crc Initial CRC value
 * @param buf Pointer to data buffer
 * @param len Length of buffer in bytes
 * @return Computed CRC32 value
 */
uint32_t crc32(u32 crc, const uint8_t *buf, size_t len);

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
 * @brief Converts a hexadecimal string to a byte array.
 *
 * Parses a string containing hexadecimal digits and stores the result
 * as binary bytes in the provided output buffer.
 *
 * @param[in]  str      Input string containing hexadecimal characters
 * @param[out] out      Output buffer to store the bytes
 * @param[in]  max_out  Maximum number of bytes that can be written to out
 * @param[out] count    Number of bytes actually written to out
 *
 * @return 0 on success, non-zero on error (e.g., invalid characters or overflow)
 *
 * @note The input string may contain uppercase or lowercase hex digits.
 */
int hexstr_to_bytes(const char *str, uint8_t *out, size_t max_out, size_t *count);

/**
 * @brief Converts a byte array to a hexadecimal string.
 *
 * Converts the given byte array into a null-terminated string containing
 * hexadecimal digits.
 *
 * @param[in]  data      Input byte array
 * @param[in]  len       Number of bytes in the input array
 * @param[out] out       Output buffer to store the hex string
 * @param[in]  out_size  Size of the output buffer (including null terminator)
 *
 * @return 0 on success, non-zero if the output buffer is too small
 */
int bytes_to_hexstr(const uint8_t *data, size_t len, char *out, size_t out_size);

/**
 * @brief Returns current time in nanoseconds.
 *
 * Gets the current time using a monotonic clock and returns it as
 * the number of nanoseconds since an unspecified starting point.
 *
 * @return Current time in nanoseconds
 *
 * @note Uses CLOCK_MONOTONIC to avoid issues with system clock changes.
 */
static inline u64 now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000000ull + (u64)ts.tv_nsec;
}

/**
 * @brief Returns current time in milliseconds.
 *
 * Convenience function that returns the current monotonic time in
 * milliseconds by dividing now_ns() by 1,000,000.
 *
 * @return Current time in milliseconds
 */
static inline u32 now_ms(void)
{
    return (u32)(now_ns() / 1000000);
}
/***********************************************************************************************/

