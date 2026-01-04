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
static u16 sequence = 0x10;
static u64 last_throughput_kbps;
/***********************************************************************************************/
commands_t commands[] = {
    {"send_str",        cmd_send_string,            "Send string to server."},
    {"send_bin",        cmd_send_binary,            "Send binary array to server."},
    {"stats_get",       cmd_get_statisctics,        "Get statistics from server."},
    {"stats_clr",       cmd_clr_statisctics,        "Clear statistics on server."},
    {"exit",            cmd_empty,                  "Exit from testtask (or press Ctrl-D)."}
};
/***********************************************************************************************/
/* Internal functions                                                                          */
/***********************************************************************************************/
/**
 * @brief Print usage/help for available commands.
 */
static void cmd_usage(void)
{
    print_string("Available commands:\n");
    for (u32 i = 0; i < ARRAY_SIZE(commands); i++) {
        print_string("%-10s\t%s\n", commands[i].name, commands[i].description);
    }
}
/***********************************************************************************************/
/**
 * @brief Parse CLI arguments and dispatch to corresponding command function.
 *
 * @param[in] cli_argc Number of arguments
 * @param[in] cli_argv Array of argument strings
 */
static void parser(int cli_argc, char **cli_argv)
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
/**
 * @brief Print formatted string to stderr.
 *
 * @param[in] str Format string
 * @param[in] ... Arguments
 * @return Always returns 0
 */
static int eprintf(const char *str, ...)
{
    va_list ap;
    va_start(ap, str);
    vfprintf(stderr, str, ap);
    va_end(ap);
    return 0;
}
/***********************************************************************************************/
static void stats_compute(u32 len, u64 start_ns, u64 end_ns, u64 *throughput)
{
    u32 elapsed_s = (u32)((end_ns - start_ns) / 1000000ULL);
    if (elapsed_s == 0) {
        elapsed_s = 1;
    }

    *throughput = (len * 8ULL * 1000ULL) / elapsed_s / 1000ULL;
    print_string("throughput: %llu kbps\n", *throughput);

}
/***********************************************************************************************/
/**
 * @brief Perform a single request/reply transaction with the server.
 *
 * Opens TCP connection, sends request packet, waits for reply, validates reply,
 * and prints results.
 *
 * @param[in]  request Pointer to request packet
 * @param[out] replay  Pointer to buffer for server reply
 * @return RESULT_OK on success, error code otherwise
 */
static int cmd_transaction(packet_t *request, packet_t *replay)
{
    int sockfd = -1;
    ssize_t received = 0;
    int result = RESULT_OK;

    do {
        if (request == NULL || replay == NULL) {
            log_msg(LOG_ERR, "Arguments error");
            result = RESULT_ARGUMENT_ERROR;
            break;
        }

        result = socket_tcp_client_create(&sockfd, 0, 0, SERVER_ADDR, SERVER_PORT);
        if (!isOk(result)) {
            break;
        }

        /* Send message to server */
        result = socket_send_data(sockfd, (void*)request->buffer, request->packet.header.len + PACKET_HEADER_SIZE);
        if (!isOk(result)) {
            log_msg(LOG_ERR, "❌ Client send failed");
            break;
        }

        /* Receive reply */
        received = sizeof(replay->buffer);
        result = socket_read_data(sockfd, replay->buffer, &received, SOCKET_READ_TIMEOUT_MS);
        if (!isOk(result) || received == 0) {
            log_msg(LOG_ERR, "❌ Client recv failed");
            break;
        }

        /* Validate reply */
        int res = protocol_packet_validate(replay);
        if (isOk(res)) {
            if (replay->packet.header.type == PACKET_TYPE_ANSWER_DATA) {
                if (isOk(replay->packet.header.answer_result)) {
                    print_string("Server responded OK on packet %u\n",  replay->packet.header.answer_sequence);
                }
                else {
                    print_string("Server returned an error %u on packet %u\n",  replay->packet.header.answer_result, replay->packet.header.answer_sequence);
                }
            }
            else if (replay->packet.header.type == PACKET_TYPE_ANSWER_STATS) {
                server_stats_t *g_stats = (server_stats_t *)replay->packet.data;

                const char total_packets[] = "Total bytes"DOTS;
                const char broken_packets[] = "Broken bytes"DOTS;
                const char avg_latency[] = "Average latency"DOTS;
                const char min_latency[] = "Min latency"DOTS;
                const char max_latency[] = "Max latency"DOTS;
                const char throughput[] = "Throughput"DOTS;

                print_string("%-.*s\n", 11, EQUALS);
                print_string("Statistics:\n");
                print_string("%-.*s\n", 11, DASHES);
                print_string("%-.*s%u packets\n", STATUS_NAME_SIZE, total_packets, g_stats->requests.total_requests);
                print_string("%-.*s%u packets\n", STATUS_NAME_SIZE, broken_packets, g_stats->requests.broken_requests);
                print_string("%-.*s%u ms\n", STATUS_NAME_SIZE, avg_latency, g_stats->latency.avg_latency);
                print_string("%-.*s%u ms\n", STATUS_NAME_SIZE, min_latency, g_stats->latency.min_latency_ms);
                print_string("%-.*s%u ms\n", STATUS_NAME_SIZE, max_latency, g_stats->latency.max_latency_ms);
                print_string("%-.*s%u kbps\n", STATUS_NAME_SIZE, throughput, last_throughput_kbps);
                print_string("%-.*s\n", 64, EQUALS);

            }
            else {
                print_string("Server responded with unknown type: %u\n",  replay->packet.header.type);
            }
        }
        else {
            print_string("❌ broken package. error %u\n", res);
        }
    } while(0);

    socket_close(sockfd);

    if (!isOk(result) && result != RESULT_ARGUMENT_ERROR) {
        print_string("❌ Server unavailable\n");
    }

    return result;
}
/***********************************************************************************************/
/* External functions                                                                          */
/***********************************************************************************************/
void cmd_init(const char *prompt,
                       void (*put_char)(void *data, char ch, bool is_last),
                       void (*print_logo)(void),
                       void *cb_data)
{
    cli_init(&cli, prompt, put_char, cb_data);
    print_logo();
    cmd_usage();
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
void cmd_empty(int cli_argc, const char **cli_argv)
{
    UNUSED(cli_argc);
    UNUSED(cli_argv);
}
/***********************************************************************************************/
void cmd_send_string(int cli_argc, const char **cli_argv)
{
    const char *message = CLIENT_MESSAGE;
    bool wrong_string_mode = false;
    size_t len = 0;
    packet_t request = {0};
    packet_t replay = {0};
    s64 repeat_amount = 1;
    int cntr_err = 0;
    int cntr_x = 0;
    int result = RESULT_OK;

    struct option_entry entries[] = {
        {"string", 's', "Enter string for sending", OPTION_FLAG_string, .string = &message},
        {"wrong", 'w', "Send wrong string for testing (Enable: 1, true, t, on, yes)", OPTION_FLAG_bool, .boolean = &wrong_string_mode},
        {"repeat", 'r', "Specify amount of packet send repeat", OPTION_FLAG_int, .integer = &repeat_amount},
        {NULL, 0, NULL, 0, .boolean=false},
    };
    int extra_args = opt_parse(cli_argc, cli_argv, entries);
    if (extra_args < 0) {
        opt_parse_usage(eprintf, cli_argv[0], entries);
    }
    else {
        do {
            if (wrong_string_mode) {
                message = WRONG_MESSAGE;
            }

            len = PACKET_DATA_SIZE < strlen(message) ? PACKET_DATA_SIZE : strlen(message);

            u64 start_ns = now_ns();
            for (cntr_x = 0; cntr_x < repeat_amount; cntr_x++) {
                /* Prepare packet to server */
                memcpy(request.packet.data, message, len);
                request.packet.header.type = PACKET_TYPE_STRING;
                protocol_packet_prepare(&request, sequence++, len);

                result = cmd_transaction(&request, &replay);
                if (!isOk(result)) {
                    if (cntr_err++ > 10) {
                        break;
                    }
                }
            }
            u64 end_ns = now_ns();
            stats_compute(len * cntr_x, start_ns, end_ns, &last_throughput_kbps);

            if (!isOk(result)) {
                break;
            }
        } while(0);
    }
}
/***********************************************************************************************/
void cmd_send_binary(int cli_argc, const char **cli_argv)
{
    const uint8_t array_good_bin[] = CLIENT_ARRAY;
    const uint8_t array_wrong_bin[] = WRONG_ARRAY;
    const uint8_t *array_bin = array_good_bin;
    const char *binary_str = NULL;
    uint8_t array[64] = {0};
    bool wrong_bin_mode = false;
    size_t len = 0;
    s64 repeat_amount = 1;
    packet_t request = {0};
    packet_t replay = {0};
    int cntr_err = 0;
    int cntr_x = 0;
    int result = RESULT_OK;

    struct option_entry entries[] = {
        {"binary", 'b', "Enter binary in format: \"1A 23 FD 08 17 3C\"", OPTION_FLAG_string, .string = &binary_str},
        {"wrong", 'w', "Send wrong string for testing (Enable: 1, true, t, on, yes)", OPTION_FLAG_bool, .boolean = &wrong_bin_mode},
        {"repeat", 'r', "Specify amount of packet send repeat", OPTION_FLAG_int, .integer = &repeat_amount},
        {NULL, 0, NULL, 0, .boolean=false},
    };
    int extra_args = opt_parse(cli_argc, cli_argv, entries);
    if (extra_args < 0) {
        opt_parse_usage(eprintf, cli_argv[0], entries);
    }
    else {
        do {
            len = sizeof(array_good_bin);
            if (binary_str != NULL && isOk(hexstr_to_bytes(binary_str, array, sizeof(array), &len))) {
                array_bin = array;
            }
            else if (wrong_bin_mode) {
                array_bin = array_wrong_bin;
                len = sizeof(array_wrong_bin);
            }

            u64 start_ns = now_ns();
            for (cntr_x = 0; cntr_x < repeat_amount; cntr_x++) {
                /* Prepare packet to server */
                memcpy(request.packet.data, array_bin, len);
                request.packet.header.type = PACKET_TYPE_ARRAY;
                protocol_packet_prepare(&request, sequence++, len);

                result = cmd_transaction(&request, &replay);
                if (!isOk(result)) {
                    if (cntr_err++ > 10) {
                        break;
                    }
                }
            }
            u64 end_ns = now_ns();
            stats_compute(len * cntr_x, start_ns, end_ns, &last_throughput_kbps);

            if (!isOk(result)) {
                break;
            }

        } while(0);
    }
}
/***********************************************************************************************/
void cmd_get_statisctics(int cli_argc, const char **cli_argv)
{
    UNUSED(cli_argc);
    UNUSED(cli_argv);

    size_t len = 0;
    packet_t request = {0};
    packet_t replay = {0};
    int result = RESULT_OK;

    do {
        /* Prepare packet to server */
        request.packet.header.type = PACKET_TYPE_GET_STATS;
        protocol_packet_prepare(&request, sequence++, len);

        result = cmd_transaction(&request, &replay);
        if (!isOk(result)) {
            break;
        }

    } while(0);
}
/***********************************************************************************************/
void cmd_clr_statisctics(int cli_argc, const char **cli_argv)
{
    UNUSED(cli_argc);
    UNUSED(cli_argv);

    size_t len = 0;
    packet_t request = {0};
    packet_t replay = {0};
    int result = RESULT_OK;

    do {
        /* Prepare packet to server */
        request.packet.header.type = PACKET_TYPE_CLR_STATS;
        protocol_packet_prepare(&request, sequence++, len);

        result = cmd_transaction(&request, &replay);
        if (!isOk(result)) {
            break;
        }

    } while(0);
}
/***********************************************************************************************/
