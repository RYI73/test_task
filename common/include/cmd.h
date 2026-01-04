/*
 * File Name:         cmd.h
 * Description:       C Header File
*/

#pragma once

#define DOTS      "..............................................................................................."
#define STATUS_NAME_SIZE    64
#define UNUSED(x) (void)(x)

/***********************************************************************************************/
typedef struct commands {
    char *name;
    void (*parser_fn)(int cli_argc, const char **cli_argv);
    const char *description; // Description for the usage/help message
}commands_t;
/***********************************************************************************************/
/**
 * @brief Initialize CLI interface, print logo, and show usage.
 *
 * @param[in] prompt       Prompt string for CLI
 * @param[in] put_char     Callback function to output characters
 * @param[in] print_logo   Function to print logo/banner
 * @param[in] cb_data      User-defined callback data passed to put_char
 */
void cmd_init(const char *prompt,
              void (*put_char)(void *data, char ch, bool is_last),
              void (*print_logo)(void),
              void *cb_data);

/**
 * @brief Process a single input character from the user.
 *
 * Handles command entry, executes command when Enter is pressed,
 * and supports exit via Ctrl-D or "exit"/"quit".
 *
 * @param[in] ch Input character
 * @return 0 if processed, -1 if CLI should exit
 */
int cmd_process_symbol(char ch);

/**
 * @brief Empty command handler (does nothing).
 *
 * @param[in] cli_argc Number of arguments
 * @param[in] cli_argv Array of argument strings
 */
void cmd_empty(int cli_argc, const char **cli_argv);

/**
 * @brief Send a string message to the server via TCP.
 *
 * Supports options:
 *   - -s / --string : custom string to send
 *   - -w / --wrong  : send wrong string for testing
 *
 * @param[in] cli_argc Number of arguments
 * @param[in] cli_argv Array of argument strings
 */
void cmd_send_string(int cli_argc, const char **cli_argv);

/**
 * @brief Send a binary array to the server via TCP.
 *
 * Supports options:
 *   - -b / --binary : binary array in hex string format (e.g., "1A 23 FD")
 *   - -w / --wrong  : send predefined wrong binary for testing
 *
 * @param[in] cli_argc Number of arguments
 * @param[in] cli_argv Array of argument strings
 */
void cmd_send_binary(int cli_argc, const char **cli_argv);

/**
 * @brief Get statistics from server.
 *
 * @param[in] cli_argc Number of arguments
 * @param[in] cli_argv Array of argument strings
 */
void cmd_get_statisctics(int cli_argc, const char **cli_argv);

/**
 * @brief Clear statistics on server.
 *
 * @param[in] cli_argc Number of arguments
 * @param[in] cli_argv Array of argument strings
 */
void cmd_clr_statisctics(int cli_argc, const char **cli_argv);
/***********************************************************************************************/
