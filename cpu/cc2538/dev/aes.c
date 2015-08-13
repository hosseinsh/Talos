/*
 * Original file:
 * Copyright (C) 2013 Texas Instruments Incorporated - http://www.ti.com/
 * All rights reserved.
 *
 * Port to Contiki:
 * Copyright (c) 2014 Andreas Dröscher <contiki@anticat.ch>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * \addtogroup cc2538-aes
 * @{
 *
 * \file
 * Implementation of the cc2538 AES driver
 */
#include "contiki.h"
#include "dev/crypto.h"
#include "dev/aes.h"
#include "dev/nvic.h"
#include "reg.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint8_t aes_start(uint8_t *pui8MsgIn, uint8_t *pui8IvIn,
                  uint8_t *pui8MsgOut, uint8_t ui8KeyLocation,
                  uint8_t ui8Encrypt, AES_MODE mode,
                  uint32_t len, struct process *process) {

  uint32_t aes_ctrl = 0;

  switch(mode) {
    case AES_ECB:
      aes_ctrl = 0; //default mode is ECB
      break;
    case AES_CBC:
      aes_ctrl = AES_AES_CTRL_CBC;
      break;
    case AES_CTR:
      aes_ctrl = AES_AES_CTRL_CTR;
      break;
    default:
      return SHA256_INVALID_PARAM;
  }

  if(REG(AES_CTRL_ALG_SEL) != 0x00000000) {
    return AES_RESOURCE_IN_USE;
  }

  /* Workaround for AES registers not retained after PM2 */
  REG(AES_CTRL_INT_CFG) = AES_CTRL_INT_CFG_LEVEL;
  REG(AES_CTRL_INT_EN) = AES_CTRL_INT_EN_DMA_IN_DONE |
                         AES_CTRL_INT_EN_RESULT_AV;

  REG(AES_CTRL_ALG_SEL) = AES_CTRL_ALG_SEL_AES;
  REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_DMA_IN_DONE |
                          AES_CTRL_INT_CLR_RESULT_AV;

  REG(AES_KEY_STORE_READ_AREA) = (uint32_t) ui8KeyLocation;

  /* Wait until key is loaded to the AES module */
  while(REG(AES_KEY_STORE_READ_AREA) & AES_KEY_STORE_READ_AREA_BUSY);

  /* Check for Key Store read error */
  if(REG(AES_CTRL_INT_STAT) & AES_CTRL_INT_STAT_KEY_ST_RD_ERR) {
    /* Clear the Keystore Read error bit */
    REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_KEY_ST_RD_ERR;
    /* Disable the master control / DMA clock */
    REG(AES_CTRL_ALG_SEL) = 0x00000000;
    return AES_KEYSTORE_READ_ERROR;
  }

  /* Write initialization vector */
  REG(AES_AES_IV_0) = ((uint32_t*)pui8IvIn)[0];
  REG(AES_AES_IV_1) = ((uint32_t*)pui8IvIn)[1];
  REG(AES_AES_IV_2) = ((uint32_t*)pui8IvIn)[2];
  REG(AES_AES_IV_3) = ((uint32_t*)pui8IvIn)[3];

  /* Program AES engine */
  if(ui8Encrypt) {
    REG(AES_AES_CTRL) = aes_ctrl
                      | AES_AES_CTRL_DIRECTION_ENCRYPT;
  } else {
    REG(AES_AES_CTRL) = aes_ctrl;
  }

  /* Clear interrupt status */
  REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_DMA_IN_DONE |
                          AES_CTRL_INT_CLR_RESULT_AV;

  if(process != NULL) {
    crypto_register_process_notification(process);
    nvic_interrupt_unpend(NVIC_INT_AES);
    nvic_interrupt_enable(NVIC_INT_AES);
  }

  /* Write the length of the crypto block (lo) */
  REG(AES_AES_C_LENGTH_0) = (uint32_t) len;
  /* Write the length of the crypto block (hi) */
  REG(AES_AES_C_LENGTH_1) = 0;

  /* Configure DMAC */
  /* Enable DMA channel 0 */
  REG(AES_DMAC_CH0_CTRL) = AES_DMAC_CH_CTRL_EN;
  /* Base address of the payload data in ext. memory */
  REG(AES_DMAC_CH0_EXTADDR) = (uint32_t) pui8MsgIn;
  /* input data length in bytes, equal to the message */
  REG(AES_DMAC_CH0_DMALENGTH) = len;

  /* Enable DMA channel 1 */
  REG(AES_DMAC_CH1_CTRL) = AES_DMAC_CH_CTRL_EN;
  /* Base address of the output data buffer */
  REG(AES_DMAC_CH1_EXTADDR) = (uint32_t) pui8MsgOut;
  /* Output data length in bytes */
  REG(AES_DMAC_CH1_DMALENGTH) = len;

  return AES_SUCCESS;
}
/*---------------------------------------------------------------------------*/
uint8_t aes_check_status() {
  return !!(REG(AES_CTRL_INT_STAT) &
            (AES_CTRL_INT_STAT_DMA_BUS_ERR | AES_CTRL_INT_STAT_KEY_ST_WR_ERR |
             AES_CTRL_INT_STAT_KEY_ST_RD_ERR | AES_CTRL_INT_STAT_RESULT_AV));
}
/*---------------------------------------------------------------------------*/
uint8_t aes_get_result(uint8_t *pui8IvOut) {
  uint32_t aes_ctrl_int_stat;

  aes_ctrl_int_stat = REG(AES_CTRL_INT_STAT);
  /* Clear the error bits */
  REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_DMA_BUS_ERR |
                          AES_CTRL_INT_CLR_KEY_ST_WR_ERR |
                          AES_CTRL_INT_CLR_KEY_ST_RD_ERR;

  nvic_interrupt_disable(NVIC_INT_AES);
  crypto_register_process_notification(NULL);

  /* Disable the master control / DMA clock */
  REG(AES_CTRL_ALG_SEL) = 0x00000000;

  if(aes_ctrl_int_stat & AES_CTRL_INT_STAT_DMA_BUS_ERR) {
    return AES_DMA_BUS_ERROR;
  }
  if(aes_ctrl_int_stat & AES_CTRL_INT_STAT_KEY_ST_WR_ERR) {
    return AES_KEYSTORE_WRITE_ERROR;
  }
  if(aes_ctrl_int_stat & AES_CTRL_INT_STAT_KEY_ST_RD_ERR) {
    return AES_KEYSTORE_READ_ERROR;
  }

  /* Read the iv registers */
  ((uint32_t*)pui8IvOut)[0] = REG(AES_AES_IV_0);
  ((uint32_t*)pui8IvOut)[1] = REG(AES_AES_IV_1);
  ((uint32_t*)pui8IvOut)[2] = REG(AES_AES_IV_2);
  ((uint32_t*)pui8IvOut)[3] = REG(AES_AES_IV_3);

  /* Clear the interrupt status */
  REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_DMA_IN_DONE |
                          AES_CTRL_INT_CLR_RESULT_AV;

  /* Clear Mode */
  REG(AES_AES_CTRL) = 0x00000000;
  return AES_SUCCESS;
}
/*---------------------------------------------------------------------------*/
uint8_t aes(uint8_t *pui8MsgIn, uint8_t *pui8Iv,
            uint8_t *pui8MsgOut, uint8_t ui8KeyLocation,
            uint8_t ui8Encrypt, AES_MODE mode, uint32_t len) {

  uint32_t aes_ctrl = 0;
  uint32_t aes_ctrl_int_stat = 0;
  uint32_t i = 0;

  switch(mode) {
    case AES_ECB:
      aes_ctrl = 0; //default mode is ECB
      break;
    case AES_CBC:
      aes_ctrl = AES_AES_CTRL_CBC;
      break;
    case AES_CTR:
      aes_ctrl = AES_AES_CTRL_CTR;
      break;
    default:
      return SHA256_INVALID_PARAM;
  }

  if(REG(AES_CTRL_ALG_SEL) != 0x00000000) {
    return AES_RESOURCE_IN_USE;
  }

  /* Workaround for AES registers not retained after PM2 */
  REG(AES_CTRL_INT_CFG) = AES_CTRL_INT_CFG_LEVEL;
  REG(AES_CTRL_INT_EN)  = 0x00000000;
  REG(AES_CTRL_ALG_SEL) = 0x00000000;

  REG(AES_KEY_STORE_READ_AREA) = (uint32_t) ui8KeyLocation;

  /* Wait until key is loaded to the AES module */
  while(REG(AES_KEY_STORE_READ_AREA) & AES_KEY_STORE_READ_AREA_BUSY);

  /* Check for Key Store read error */
  if(REG(AES_CTRL_INT_STAT) & AES_CTRL_INT_STAT_KEY_ST_RD_ERR) {
    /* Clear the Keystore Read error bit */
    REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_KEY_ST_RD_ERR;
    /* Disable the master control / DMA clock */
    REG(AES_CTRL_ALG_SEL) = 0x00000000;
    return AES_KEYSTORE_READ_ERROR;
  }

  /* Write initialization vector */
  REG(AES_AES_IV_0) = ((uint32_t*)pui8Iv)[0];
  REG(AES_AES_IV_1) = ((uint32_t*)pui8Iv)[1];
  REG(AES_AES_IV_2) = ((uint32_t*)pui8Iv)[2];
  REG(AES_AES_IV_3) = ((uint32_t*)pui8Iv)[3];

  /* Program AES engine */
  if(ui8Encrypt) {
    REG(AES_AES_CTRL) = aes_ctrl
                      | AES_AES_CTRL_DIRECTION_ENCRYPT;
  } else {
    REG(AES_AES_CTRL) = aes_ctrl;
  }

  /* Write the length of the crypto block (lo) */
  REG(AES_AES_C_LENGTH_0) = (uint32_t) len;
  /* Write the length of the crypto block (hi) */
  REG(AES_AES_C_LENGTH_1) = 0;

  /* I/O Data Data through Registers */
  for(i = 0; i < len/4; i += 4) {
    /* Wait until the AES module is ready for a block */
    while(!(REG(AES_AES_CTRL) & AES_AES_CTRL_INPUT_READY));

    /* Write Data */
    REG(AES_AES_DATA_IN_OUT_0) = ((uint32_t*)pui8MsgIn)[0+i];
    REG(AES_AES_DATA_IN_OUT_1) = ((uint32_t*)pui8MsgIn)[1+i];
    REG(AES_AES_DATA_IN_OUT_2) = ((uint32_t*)pui8MsgIn)[2+i];
    REG(AES_AES_DATA_IN_OUT_3) = ((uint32_t*)pui8MsgIn)[3+i];

    /* Start processing next block */
    REG(AES_AES_CTRL) |= AES_AES_CTRL_INPUT_READY |
                         AES_AES_CTRL_OUTPUT_READY;

    /* Wait until the AES module processed the block */
    while(!(REG(AES_AES_CTRL) & AES_AES_CTRL_OUTPUT_READY));

    /* Read Data */
    ((uint32_t*)pui8MsgOut)[0+i] = REG(AES_AES_DATA_IN_OUT_0);
    ((uint32_t*)pui8MsgOut)[1+i] = REG(AES_AES_DATA_IN_OUT_1);
    ((uint32_t*)pui8MsgOut)[2+i] = REG(AES_AES_DATA_IN_OUT_2);
    ((uint32_t*)pui8MsgOut)[3+i] = REG(AES_AES_DATA_IN_OUT_3);
  }

  /* Wait until the AES module is done */
  while(REG(AES_CTRL_ALG_SEL) != 0x00000000);

  aes_ctrl_int_stat = REG(AES_CTRL_INT_STAT);
  /* Clear the error bits */
  REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_DMA_BUS_ERR |
                          AES_CTRL_INT_CLR_KEY_ST_WR_ERR |
                          AES_CTRL_INT_CLR_KEY_ST_RD_ERR;

  if(aes_ctrl_int_stat & AES_CTRL_INT_STAT_DMA_BUS_ERR) {
    return AES_DMA_BUS_ERROR;
  }
  if(aes_ctrl_int_stat & AES_CTRL_INT_STAT_KEY_ST_WR_ERR) {
    return AES_KEYSTORE_WRITE_ERROR;
  }
  if(aes_ctrl_int_stat & AES_CTRL_INT_STAT_KEY_ST_RD_ERR) {
    return AES_KEYSTORE_READ_ERROR;
  }

  /* Read the iv registers */
  ((uint32_t*)pui8Iv)[0] = REG(AES_AES_IV_0);
  ((uint32_t*)pui8Iv)[1] = REG(AES_AES_IV_1);
  ((uint32_t*)pui8Iv)[2] = REG(AES_AES_IV_2);
  ((uint32_t*)pui8Iv)[3] = REG(AES_AES_IV_3);

  /* Clear Mode */
  REG(AES_AES_CTRL) = 0x00000000;
  return AES_SUCCESS;
}

/** @} */
