# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(cyrpto_test_st_hal)
zephyr_compile_definitions(
    MBEDTLS_CONFIG_FILE=<mbedtls_config.h>
    MBEDTLS_USER_CONFIG_FILE=<mbedtls_alt_config.h>
    USE_HAL_DRIVER
)

add_subdirectory_ifdef(CONFIG_MAKE_CRYPTO_WORK_STM32 crypto_wrapper)


target_sources(app PRIVATE src/main.c)
