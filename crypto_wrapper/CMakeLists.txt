  zephyr_include_directories(
    include/
  )


  add_subdirectory(middlewares/Third_Party/mbedtls/library)
  add_subdirectory(middlewares/ST)

  target_sources(app PRIVATE
    src/stm32_crypto_wrapper.c  
    src/stm32u3xx_hal_msp.c     
    src/storage_interface_zfs.c     
  )
