/*******************************************************************************
 *   @file   src/esp32/gpio_helpers.c
 *   @brief  Implementation of GPIO helper functions.
 *   @author Ruslan
********************************************************************************
 * Copyright 2025(c).
*******************************************************************************/

#include "driver/gpio.h"

#include "gpio_helpers.h"
#include "defaults.h"
#include "error_code.h"
#include "logs.h"

/******************************************************************************/
/***************************** Include Files **********************************/
/******************************************************************************/

/***********************************************************************************************/
int gpio_init(const char *device, int offset, int *gpio_fd)
{
    UNUSED(device);
    UNUSED(offset);
    UNUSED(gpio_fd);

    int result = RESULT_OK;

    do {
        gpio_config_t io = {
            .pin_bit_mask = BIT64(GPIO_SPI_READY),
            .mode = GPIO_MODE_OUTPUT,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .pull_up_en = GPIO_PULLUP_DISABLE,
            .intr_type = GPIO_INTR_DISABLE,
        };

        if (gpio_config(&io) != ESP_OK) {
            log_msg(LOG_ERR, "Failed to configure GPIO_SPI_READY");
            result = RESULT_INTERNAL_ERROR;
            break;
        }

        if (gpio_set_level(GPIO_SPI_READY, 0) != ESP_OK) {
            log_msg(LOG_ERR, "Failed to set GPIO_SPI_READY level");
            result = RESULT_INTERNAL_ERROR;
            break;
        }

    } while (0);

    return result;
}/***********************************************************************************************/
