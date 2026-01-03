#pragma once

#include "types.h"

/***********************************************************************************************/
/**
 * @brief Export a GPIO via sysfs
 *
 * @param gpio Global Linux GPIO number
 * @return 0 on success, -1 on error
 */
int export_gpio(int gpio);

/**
 * @brief Read GPIO chip base number
 *
 * @return Base GPIO number, or -1 on error
 */
int read_gpiochip_base(void);

/***********************************************************************************************/
