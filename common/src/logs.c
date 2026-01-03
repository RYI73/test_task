//#define DEBUG 1

#include <stdio.h>

#include "logs.h"

#ifdef ESP_PLATFORM
#include "esp_log.h"
#define LOG_TAG "L3_ROUTER"
#else
#include <stdarg.h>
static int g_log_facility = LOG_DAEMON;
#endif

/***********************************************************************************************/
void log_msg(int log_prio, const char* message, ...)
{
#ifdef ESP_PLATFORM
    char buf[256];

    va_list args;
    va_start(args, message);

    vsnprintf(buf, sizeof(buf) - 2, message, args);
    va_end(args);

    size_t len = strlen(buf);
    if (len == 0 || buf[len - 1] != '\n') {
        buf[len++] = '\n';
        buf[len] = '\0';
    }

    esp_log_level_t lvl = ESP_LOG_DEBUG;
    switch (log_prio) {
        case LOG_ERR:     lvl = ESP_LOG_ERROR; break;
        case LOG_WARNING: lvl = ESP_LOG_WARN;  break;
        case LOG_INFO:    lvl = ESP_LOG_INFO;  break;
        case LOG_DEBUG:
        default:          lvl = ESP_LOG_DEBUG; break;
    }

    esp_log_write(lvl, LOG_TAG, "%s", buf);

#else
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
#endif
}/***********************************************************************************************/
