#pragma once

#include "types.h"

/***********************************************************************************************/
/**
 * @brief Initialize GPIO via gpiochip device.
 *
 * Opens gpiochip device, reads its base GPIO number and exports
 * a GPIO line using the provided offset.
 *
 * @param[in]  device   Path to gpiochip device (e.g. "/dev/gpiochip0")
 * @param[in]  offset   GPIO offset relative to gpiochip base
 * @param[out] gpio_fd  Pointer to store opened device file descriptor
 *
 * @return
 *  - RESULT_OK on success
 *  - RESULT_FILE_OPEN_ERROR if device open fails
 *  - Other RESULT_* codes returned by helper functions
 *
 * @note
 *  - This function opens the gpiochip device in read-only mode.
 *  - GPIO number is calculated as (gpiochip base + offset).
 *  - Caller is responsible for closing @p gpio_fd.
 */
int gpio_init(const char *device, int offset, int *gpio_fd);

/***********************************************************************************************/
