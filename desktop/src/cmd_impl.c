/******************************************************************************
 *   @file   cmd_impl.c
 *   @brief  Implementation of Command Functions.
 *   @author Ruslan
*******************************************************************************
 * Copyright 2025(c).
*******************************************************************************/

/******************************************************************************/
/***************************** Include Files **********************************/
/******************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "cli.h"
#include "cmd.h"
#include "defines.h"
#include "helpers.h"
#include "socket_helpers.h"
#include "logs.h"
#include "simple_options.h"
#include "protocol.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/***********************************************************************************************/
static struct cli cli;
static u16 sequence = 0;
/***********************************************************************************************/
commands_t commands[] = {
    {"status_get",      cmd_status_get,             "Get client status."},
    {"send_str",        cmd_send_string,            "Send string to server."},
    {"exit",            cmd_empty,                  "Exit from ark-modem (or press Ctrl-D)."}
};
/***********************************************************************************************/
void cmd_init(const char *prompt,
                       void (*put_char)(void *data, char ch, bool is_last),
                       void (*print_logo)(void),
                       void *cb_data)
{
    cli_init(&cli, prompt, put_char, cb_data);
    print_logo();
    cli_prompt(&cli);
}
/***********************************************************************************************/
int cmd_process_symbol(char ch)
{
    /**
     * If we have entered a command, try and process it
     */
    int result = 0;

    if (ch == 0x04) {
        print_string("\nExit ...\n");
        result = -1;
    }
    else if (cli_insert_char(&cli, ch)) {
        int cli_argc;
        char **cli_argv;
        char buff[1024] = {0};
        cli_argc = cli_get_argc(&cli, &cli_argv);
        if (cli_argc) {
            strncpy(buff, cli_argv[0], sizeof(buff)-1);
            strupr(buff);
            if (!strncmp(buff, "QUIT", strlen(buff)) || !strncmp(buff, "EXIT", strlen(buff))) {
                print_string("Exit ...\n");
                result = -1;
            }
            else if (!strncmp(buff, "HELP", strlen(buff))) {
                cmd_usage();
            }
            else {
                parser(cli_argc, cli_argv);
            }
        }
        if (!result) {
            cli_prompt(&cli);
        }
    }

    return result;
}
/***********************************************************************************************/
void cmd_usage(void)
{
    print_string("Available commands:\n");
    for (u32 i = 0; i < ARRAY_SIZE(commands); i++) {
        print_string("%-10s\t%s\n", commands[i].name, commands[i].description);
    }
}
/***********************************************************************************************/
static int eprintf(const char *str, ...)
{
    va_list ap;
    va_start(ap, str);
    vfprintf(stderr, str, ap);
    va_end(ap);
    return 0;
}
/***********************************************************************************************/
void parser(int cli_argc, char **cli_argv)
{
    bool is_cmd_found = false;
    for (u32 i = 0; i < ARRAY_SIZE(commands); i++) {
        if (!strncmp(commands[i].name, cli_argv[0], strlen(commands[i].name))) {
            commands[i].parser_fn(cli_argc, (const char **)cli_argv);
            is_cmd_found = true;
            break;
        }
    }

    if (!is_cmd_found) {
        print_string("Unknown command '%s'.\n", cli_argv[0]);
        cmd_usage();
    }
}
/***********************************************************************************************/
void cmd_empty(int cli_argc, const char **cli_argv)
{
    UNUSED(cli_argc);
    UNUSED(cli_argv);
}
/***********************************************************************************************/
void cmd_status_get(int cli_argc, const char **cli_argv)
{
    UNUSED(cli_argc);
    UNUSED(cli_argv);

    const char client_mode[] = "Client mode"DOTS;
    u8 is_connected = 0;

    print_string("%-.*s%s\n", STATUS_NAME_SIZE, client_mode, is_connected?"Connected":"Disconnected");
}
/***********************************************************************************************/
void cmd_send_string(int cli_argc, const char **cli_argv)
{
    const char *direct = CLIENT_MESSAGE;
    int sockfd = -1;
    size_t len = 0;
    packet_t request = {0};
    packet_t replay = {0};
    int result = RESULT_OK;

    struct option_entry entries[] = {
        {"string", 's', "Enter string for sending", OPTION_FLAG_string, .string = &direct},
        {NULL, 0, NULL, 0, .boolean=false},
    };
    int extra_args = opt_parse(cli_argc, cli_argv, entries);
    if (extra_args < 0) {
        opt_parse_usage(eprintf, cli_argv[0], entries);
    }
    else {
        do {
            result = socket_tcp_client_create(&sockfd, 0, 0, SERVER_ADDR, SERVER_PORT);
            if (!isOk(result)) {
                break;
            }

            len = PACKET_DATA_SIZE < strlen(direct) ? PACKET_DATA_SIZE : strlen(direct);

            /* Prepare packet to server */
            prepare_request(&request, sequence++, len);
            memcpy(request.packet.data, direct, len);
            request.packet.header.type = PACKET_TYPE_STRING;

            /* Send message to server */
            result = socket_send_data(sockfd, (void*)request.buffer, len + PACKET_HEADER_SIZE);
            if (!isOk(result)) {
                log_msg(LOG_ERR, "❌ send failed");
            }


            /* Receive reply */
            ssize_t received = sizeof(replay.buffer);
            result = socket_read_data(sockfd, replay.buffer, &received, SOCKET_READ_TIMEOUT_MS);
            if (!isOk(result) || received == 0) {
                log_msg(LOG_ERR, "❌ recv failed");
                break;
            }

            /* Validate reply */
            if (isOk(validate_replay(&replay))) {
                if (isOk(replay.packet.header.result)) {
                    print_string("Server responded: %s\n",  OK_REPLY);
                }
                else {
                    print_string("Server returned an error %u\n",  replay.packet.header.result);
                }
            }

        } while(0);

        if (!isOk(result)) {
            print_string("❌ Server not responding\n");
        }

    }


    socket_close(sockfd);
}
/***********************************************************************************************/
