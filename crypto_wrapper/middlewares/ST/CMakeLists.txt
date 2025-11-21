if(CONFIG_MAKE_CRYPTO_WORK_STM32)
  zephyr_include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_alt/interfaces/patterns
    ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_key_wrap_engine/interface
    ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_key_wrap_engine/core
    ${CMAKE_CURRENT_SOURCE_DIR}/../Third_Party/mbedtls/include/mbedtls
    ${CMAKE_CURRENT_SOURCE_DIR}/../Third_Party/mbedtls/include/psa
  )

  add_subdirectory(mbedtls_alt/interfaces/patterns)
  file(GLOB ST_middleware_source mbedtls_key_wrap_engine/core/*.c mbedtls_key_wrap_engine/interface/*.c)


  target_sources(app PRIVATE
    ${ST_middleware_source}
  )
endif()