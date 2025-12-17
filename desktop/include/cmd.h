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
void cmd_init(const char *prompt,
              void (*put_char)(void *data, char ch, bool is_last),
              void (*print_logo)(void),
              void *cb_data);
int cmd_process_symbol(char ch);
void parser(int cli_argc, char **cli_argv);
void cmd_usage(void);

void cmd_empty(int cli_argc, const char **cli_argv);
void cmd_status_get(int cli_argc, const char **cli_argv);
void cmd_send_string(int cli_argc, const char **cli_argv);
/***********************************************************************************************/
