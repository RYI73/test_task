#idf_component_register(SRCS "esp32_spi_router.c"
#                    INCLUDE_DIRS ".")
idf_component_register(
    SRCS
        "esp32_spi_router.c"
        "lwip_hooks.c"
    INCLUDE_DIRS "."
)

