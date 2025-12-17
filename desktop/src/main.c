/*******************************************************************************
 *   @file   src/main.c
 *   @brief  Implementation of main file.
 *   @author Ruslan
********************************************************************************
 * Copyright 2025(c).
*******************************************************************************/

/******************************************************************************/
/***************************** Include Files **********************************/
/******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include "helpers.h"
#include "logo.h"
#include "cmd.h"
#include "error_code.h"
#include "threads.h"

/***********************************************************************************************/
static int init(void)
{
    int result = RESULT_OK;

    set_raw_mode(1);

    return result;
}
/***********************************************************************************************/
static void deinit(void)
{
    set_raw_mode(0);
}
/***********************************************************************************************/
int main(void)
{
    int result = RESULT_OK;

    signal(SIGINT, handle_sigint);

    result = init();
    if (isOk(result)) {
        cmd_init("Client# ", posix_putch, print_logo, stdout);

        while (1) {
            char ch;
            if (read(STDIN_FILENO, &ch, 1) == 0) {
                continue;
            }
            if (cmd_process_symbol(ch)) {
                break;
            }
        }
    }

    deinit();

    if (isOk(result)) {
        return EXIT_SUCCESS;
    }
    else {
        return EXIT_FAILURE;
    }
}
/***********************************************************************************************/
