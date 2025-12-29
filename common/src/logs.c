//#define DEBUG 1

#include "logs.h"
#include "helpers.h"
#if DEBUG
#include <stdio.h>
#endif

static int g_log_facility = LOG_DAEMON;
/***********************************************************************************************/
void log_msg(int log_prio, const char* message, ...)
{
    va_list args;
    va_start(args, message);
    vsyslog(g_log_facility | log_prio, message, args);
#if DEBUG
    char buf[1024];
    va_list args_copy;
    va_start(args_copy, message);
    vsnprintf(buf, sizeof(buf), message, args_copy);
    va_end(args_copy);
    print_string("%s\n", buf);
#endif
    va_end(args);
}
/***********************************************************************************************/
