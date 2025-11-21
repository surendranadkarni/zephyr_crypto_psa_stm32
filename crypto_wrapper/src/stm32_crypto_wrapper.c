/**
  ******************************************************************************
  * @file    MbedTLS_HW_KWE/Cipher_AES_CBC_EncryptDecrypt_KWE/Src/main.c
  * @author  MCD Application Team
  * @brief   This example provides a short description of how to use the
  *          Mbed TLS PSA opaque driver with STM32 Key Wrap Engine to wrap
  *          AES-CBC key and use the wrapped key for AES-CBC encryption 
  *          decryption.
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2024 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include <string.h>
#include "stm32_crypto_wrapper.h"
#include "psa/crypto.h"
#include "kwe_psa_driver_interface.h"
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(crypto, LOG_LEVEL_DBG);
/* Global variables ----------------------------------------------------------*/
/* Private typedef -----------------------------------------------------------*/
typedef enum
{
  FAILED = 0,
  PASSED = 1
} TestStatus;
/* Private defines -----------------------------------------------------------*/
/* Private macros ------------------------------------------------------------*/
/* User key ID should be between PSA_KEY_ID_USER_MIN and PSA_KWE_KEY_ID_RSSE_MIN
 * Key ID from PSA_KWE_KEY_ID_RSSE_MIN to PSA_KEY_ID_USER_MAX are reserved for
 * RSSE keys.
 */
#define PSA_AES_CBC_KEY_ID_USER  ((psa_key_id_t)0x1fff0001)

/* Private variables ---------------------------------------------------------*/
/* AES CBC */
/** Extract from NIST Special Publication 800-38A
  * F.2.1 CBC-AES128.Encrypt
  * Key 2b7e151628aed2a6abf7158809cf4f3c
  * IV 000102030405060708090a0b0c0d0e0f
  * Block #1
  * Plaintext 6bc1bee22e409f96e93d7e117393172a
  * Input Block 6bc0bce12a459991e134741a7f9e1925
  * Output Block 7649abac8119b246cee98e9b12e9197d
  * Ciphertext 7649abac8119b246cee98e9b12e9197d
  * Block #2
  * Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
  * Input Block d86421fb9f1a1eda505ee1375746972c
  * Output Block 5086cb9b507219ee95db113a917678b2
  * Ciphertext 5086cb9b507219ee95db113a917678b2
  * Block #3
  * Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
  * Input Block 604ed7ddf32efdff7020d0238b7c2a5d
  * Output Block 73bed6b8e3c1743b7116e69e22229516
  * Ciphertext 73bed6b8e3c1743b7116e69e22229516
  * Block #4
  * Plaintext f69f2445df4f9b17ad2b417be66c3710
  * Input Block 8521f2fd3c8eef2cdc3da7e5c44ea206
  * Output Block 3ff1caa1681fac09120eca307586e1a7
  * Ciphertext 3ff1caa1681fac09120eca307586e1a7
  */
const uint8_t Aes_CBC_Key[] =
{
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
const uint8_t IV_CBC[] =
{
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
const uint8_t Plaintext_CBC[] =
{
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
  0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
};
const uint8_t Expected_Ciphertext_CBC[] =
{
  0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
  0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
  0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
  0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
};

const uint8_t IV_And_Expected_Ciphertext_CBC[] =
{
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
  0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
  0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
  0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
};

/* Computed data buffer */
uint8_t Computed_Ciphertext_CBC[sizeof(Expected_Ciphertext_CBC)+sizeof(IV_CBC)];
uint8_t Computed_Plaintext_CBC[sizeof(Plaintext_CBC)];

__IO TestStatus glob_status = FAILED;

/* Private function prototypes -----------------------------------------------*/
static void SystemClock_Config(void);
void Error_Handler(void);
/* Functions Definition ------------------------------------------------------*/

/**
  * @brief  Main program
  * @param  None
  * @retval None
  */
int crypto_main(void)
{
  psa_status_t retval;
  size_t computed_size;
  /* Define key attributes */
  psa_key_attributes_t key_attributes;
  psa_key_handle_t key_handle_aes_cbc;
  volatile int64_t start_time, end_time, time_for_encrypt;

  /* --------------------------------------------------------------------------
   *                    PSA Crypto library Initialization
   * --------------------------------------------------------------------------
   */
  
  retval = psa_crypto_init();
  if (retval != PSA_SUCCESS)
  {
    Error_Handler();
  }
  LOG_INF("PSA Crypto Initialized");
  k_sleep(K_MSEC(1000));
  /* --------------------------------------------------------------------------
   *                   STM32 Key Wrap Engine
   * --------------------------------------------------------------------------
   */

  /* --------------------------------------------------------------------------
   *                    AES CBC Encryption & Decryption
   *     PSA Persistent Private Key Wrap using STM32 Key Wrap Engine (KWE)
   *        (Persistent Wrapped key is stored using PSA ITS)
   * --------------------------------------------------------------------------
   */

  /* Init the key attributes */
  key_attributes = psa_key_attributes_init();
  
  LOG_INF("KEY ATTRIB INIT DONE"); k_sleep(K_MSEC(1000));
  /* Setup the key policy for the private key */
  psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
  LOG_INF("psa_set_key_usage_flags"); k_sleep(K_MSEC(1000));
  psa_set_key_algorithm(&key_attributes, PSA_ALG_CBC_NO_PADDING);
  LOG_INF("psa_set_key_algorithm"); k_sleep(K_MSEC(1000));
  psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
  LOG_INF("psa_set_key_type"); k_sleep(K_MSEC(1000));
  psa_set_key_bits(&key_attributes, 8U*sizeof(Aes_CBC_Key));
  LOG_INF("psa_set_key_bits"); k_sleep(K_MSEC(1000));
  /* Set up the key location using PSA_CRYPTO_KWE_DRIVER_LOCATION to wrap the private key using STM32 Key Wrap Engine (KWE) */
  psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_PERSISTENCE_DEFAULT, PSA_CRYPTO_KWE_DRIVER_LOCATION));
  LOG_INF("psa_set_key_lifetime"); k_sleep(K_MSEC(1000));
  /* Set up persistent Key ID */
  psa_set_key_id(&key_attributes, PSA_AES_CBC_KEY_ID_USER);
  LOG_INF("psa_set_key_id"); k_sleep(K_MSEC(1000));
  /* Import the private key */
  retval = psa_import_key(&key_attributes, Aes_CBC_Key, sizeof(Aes_CBC_Key), &key_handle_aes_cbc);
  if (retval != PSA_SUCCESS)
  {
    LOG_INF("PSA IMPORT KEY FAILED %d", retval);
    Error_Handler();
  }

  /* Reset the key attribute */
  psa_reset_key_attributes(&key_attributes);
  LOG_INF("PSA IMPORT KEY DONE"); k_sleep(K_MSEC(1000));

  /* --------------------------------------------------------------------------
   * SINGLE CALL USAGE
   * --------------------------------------------------------------------------
  */
  start_time = k_uptime_get();
  /* Compute directly the ciphertext passing all the needed parameters */
  /* This function use a random IV, data verification is not possible */
  retval = psa_cipher_encrypt(key_handle_aes_cbc,                      /* The key id */
                              PSA_ALG_CBC_NO_PADDING,                  /* Algorithm type */
                              Plaintext_CBC, sizeof(Plaintext_CBC),    /* Plaintext to encrypt */
                              Computed_Ciphertext_CBC,                 /* Data buffer to receive generated ciphertext */
                              sizeof(Computed_Ciphertext_CBC),         /* Size of buffer to receive ciphertext */
                              &computed_size);                         /* Size of computed ciphertext */

  /* Verify API returned value */
  if (retval != PSA_SUCCESS)
  {
    LOG_INF("psa_cipher_encrypt FAILED");
    Error_Handler();
  }

  /* Verify generated data size is the expected one. We can only verify the size of the data.*/
  if (computed_size != sizeof(IV_And_Expected_Ciphertext_CBC))
  {
    LOG_INF("omputed_size != sizeof(IV_And_Expected_Ciphertext_CBC FAILED");
    Error_Handler();
  }
  end_time = k_uptime_get();
  time_for_encrypt = end_time - start_time;
  LOG_INF("Time for AES-CBC Encryption (ms): %lld", time_for_encrypt);

  /* Decrypt directly ciphertext passing all the needed parameters   */
  retval= psa_cipher_decrypt(key_handle_aes_cbc,                      /* The key id */
                             PSA_ALG_CBC_NO_PADDING,                  /* Algorithm type */
                             Computed_Ciphertext_CBC,                 /* IV + Ciphertext to decrypt */
                             sizeof(IV_And_Expected_Ciphertext_CBC),  /* Size of IV + Ciphertext to decrypt */
                             Computed_Plaintext_CBC,                  /* Data buffer to receive generated plaintext */
                             sizeof(Computed_Plaintext_CBC),          /* Size of buffer to receive plaintext */
                             &computed_size);                         /* Size of computed plaintext */

  /* Verify API returned value */
  if (retval != PSA_SUCCESS)
  {
    LOG_INF("psa_cipher_decrypt FAILED");
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != sizeof(Plaintext_CBC))
  {
    LOG_INF("computed_size != sizeof(Plaintext_CBC) FAILED");
    Error_Handler();
  }

  /* Verify generated data are the expected ones */
  if (memcmp(Plaintext_CBC, Computed_Plaintext_CBC, computed_size) != 0)
  {
    LOG_INF("memcmp(Plaintext_CBC, Computed_Plaintext_CBC, computed_size) != 0 FAILED");
    Error_Handler();
  }

  /* --------------------------------------------------------------------------
   * Destroy the PSA key and clear all data
   * --------------------------------------------------------------------------
  */

  /* Destroy the private key */
  retval = psa_destroy_key(key_handle_aes_cbc);
  if (retval != PSA_SUCCESS)
  {
    Error_Handler();
  }

  /* Clear all data associated with the PSA layer */
  mbedtls_psa_crypto_free();

  glob_status = PASSED;
  
  return 0;
}

/**
  * @brief  System Clock Configuration
  *         The system Clock is configured as follow :
  *            System Clock source            = MSIS
  *            SYSCLK(Hz)                     = 96000000
  *            HCLK(Hz)                       = 96000000
  *            AHB Prescaler                  = 1
  *            APB1 Prescaler                 = 1
  *            APB2 Prescaler                 = 1
  *            APB3 Prescaler                 = 1
  *            Flash Latency(WS)              = 2
  * @param  None
  * @retval None
  */
static void SystemClock_Config(void)
{
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  uint32_t latency;

  /* Enable Epod Booster */
  __HAL_RCC_PWR_CLK_ENABLE();
  HAL_RCCEx_EpodBoosterClkConfig(RCC_EPODBOOSTER_SOURCE_MSIS, RCC_EPODBOOSTER_DIV1);
  HAL_PWREx_EnableEpodBooster();

  /* At reset, the regulator is the LDO, in range 2 : Need to move to range 1 to reach 96 MHz */
  if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1) != HAL_OK)
  {
    /* Initialization Error */
    while(1);
  }

  /* Set Flash latency before increasing MSIS */
  __HAL_FLASH_SET_LATENCY(FLASH_LATENCY_2);

  /* Activate MSIS as source */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_MSIS;
  RCC_OscInitStruct.MSISState = RCC_MSI_ON;
  RCC_OscInitStruct.MSISSource = RCC_MSI_RC0;
  RCC_OscInitStruct.MSISDiv = RCC_MSI_DIV1;

  if(HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    /* Initialization Error */
    while(1);
  }

  /* Select MSIS as system clock source and configure the HCLK, PCLK1, PCLK2 and PCLK3
     clocks dividers */
  RCC_ClkInitStruct.ClockType = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2 | RCC_CLOCKTYPE_PCLK3);
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_MSIS;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB3CLKDivider = RCC_HCLK_DIV1;
  latency = FLASH_LATENCY_2;
  if(HAL_RCC_ClockConfig(&RCC_ClkInitStruct, latency) != HAL_OK)
  {
    /* Initialization Error */
    while(1);
  }
}


/**
  * @brief  This function is executed in case of error occurrence
  * @param  None
  * @retval None
  */
void Error_Handler(void)
{
  LOG_ERR("Error Handler Invoked");
  /* User may add here some code to deal with this error */
  while(1)
  {
    k_sleep(K_MSEC(1000));
  }
}

#ifdef USE_FULL_ASSERT

/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */

  /* Infinite loop */
  while (1)
  {}
}
#endif /* USE_FULL_ASSERT */
