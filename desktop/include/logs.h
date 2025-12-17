/*
 * File Name:         logs.h
 * Description:       C Header File
*/

#pragma once

#include <syslog.h>
#include <stdarg.h>

/***********************************************************************************************/
void log_msg(int log_prio, const char* message, ...);
/***********************************************************************************************/
