
#include <stm32u3xx_hal.h>
#include <soc.h>
#include "stm32_crypto_wrapper.h"
#include "stm32u3xx_hal_ccb.h"

static CCB_HandleTypeDef hccb;

/* Crypto wrapper initialization function */
void amina_crypto_init(void)
{
  /* Initialize the HAL Crypto CCB */
  hccb.Instance = CCB;
  HAL_CCB_Init(&hccb);
}