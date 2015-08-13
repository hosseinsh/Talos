/*
 * Original file: https://github.com/Hellblazer/CryptDB/blob/public/crypto/cmc.hh
 *
 * Copyright (c) 2014, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Port to Contiki:
 *             Andreas Dröscher <contiki@anticat.ch>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE
 */
/**
 * \addtogroup cc2538-aes-cmc
 * @{
 *
 * \file
 * Implementation of the cc2538 AES-CMC driver
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

static uint8_t cmc_init(uint8_t ui8KeyLocation,  uint8_t ui8Encrypt, uint32_t len) {
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
  REG(AES_AES_IV_0) = 0x00000000;
  REG(AES_AES_IV_1) = 0x00000000;
  REG(AES_AES_IV_2) = 0x00000000;
  REG(AES_AES_IV_3) = 0x00000000;

  /* Program AES engine */
  if(ui8Encrypt) {
    REG(AES_AES_CTRL) = AES_AES_CTRL_DIRECTION_ENCRYPT;
  } else {
    REG(AES_AES_CTRL) = 0x00000000;
  }

  /* Write the length of the crypto block (lo) */
  REG(AES_AES_C_LENGTH_0) = (uint32_t) len;
  /* Write the length of the crypto block (hi) */
  REG(AES_AES_C_LENGTH_1) = 0;

  return AES_SUCCESS;
}

static uint8_t cmc_cleanup() {
  uint32_t aes_ctrl_int_stat = 0;

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

  /* Clear Mode */
  REG(AES_AES_CTRL) = 0x00000000;
  return AES_SUCCESS;
}

static void cmc_block(uint8_t* in, uint8_t *out) {
  /* Wait until the AES module is ready for a block */
  while(!(REG(AES_AES_CTRL) & AES_AES_CTRL_INPUT_READY));

  /* Write Data */
  REG(AES_AES_DATA_IN_OUT_0) = ((uint32_t*)in)[0];
  REG(AES_AES_DATA_IN_OUT_1) = ((uint32_t*)in)[1];
  REG(AES_AES_DATA_IN_OUT_2) = ((uint32_t*)in)[2];
  REG(AES_AES_DATA_IN_OUT_3) = ((uint32_t*)in)[3];

  /* Start processing next block */
  REG(AES_AES_CTRL) |= AES_AES_CTRL_INPUT_READY |
                       AES_AES_CTRL_OUTPUT_READY;

  /* Wait until the AES module processed the block */
  while(!(REG(AES_AES_CTRL) & AES_AES_CTRL_OUTPUT_READY));

  /* Read Data */
  ((uint32_t*)out)[0] = REG(AES_AES_DATA_IN_OUT_0);
  ((uint32_t*)out)[1] = REG(AES_AES_DATA_IN_OUT_1);
  ((uint32_t*)out)[2] = REG(AES_AES_DATA_IN_OUT_2);
  ((uint32_t*)out)[3] = REG(AES_AES_DATA_IN_OUT_3);
}

uint8_t cmc_encrypt(uint8_t* ptext, uint8_t *ctext, uint8_t ui8KeyLocation, uint32_t len) {
  uint32_t x[4];
  uint32_t i;
  uint32_t j;

  if(cmc_init(0, 1, len*2)) {
    return AES_DMA_BUS_ERROR;
  }

  /* CBC */
  memset(x, 0, 16);
  for(i = 0; i < len; i += 16) {
    uint32_t y[4];
    for(j = 0; j < 4; j++)
      y[j] = ((uint32_t*)ptext)[i/4 + j] ^ x[j];

    cmc_block((uint8_t*)y, &ctext[i]);
    memcpy(x, &ctext[i], 16);
  }

  /* Mask */
  uint8_t m[16];
  uint8_t carry = 0;
  for(j = 16; j != 0; j--) {
    uint16_t a = ctext[j - 1] ^ ctext[j - 1 + len - 16];
    m[j] = carry | (uint8_t) (a << 1);
    carry = a >> 7;
  }
  m[16 - 1] |= carry;

  for(i = 0; i < len; i += 16) {
    for(j = 0; j < 4; j++)
      ((uint32_t*)ctext)[i/4 + j] ^= ((uint32_t*)m)[j];
  }

  /* CBC */
  memset(x, 0, 16);
  for(i = len; i != 0; i -= 16) {
    uint32_t y[4];
    cmc_block(&ctext[i - 16], (uint8_t*)y);

    uint32_t z[4];
    for(j = 0; j < 4; j++)
      z[j] = y[j] ^ x[j];

    memcpy(x, &ctext[i - 16], 16);
    memcpy(&ctext[i - 16], z, 16);
  }
  return cmc_cleanup();
}

uint8_t cmc_decrypt(uint8_t *ctext, uint8_t *ptext, uint8_t ui8KeyLocation, uint32_t len) {
  uint32_t x[4];
  uint32_t i;
  uint32_t j;

  if(cmc_init(0, 0, len * 2)) {
    return AES_DMA_BUS_ERROR;
  }

  /* CBC */
  memset(x, 0, 16);
  for(i = len; i != 0; i -= 16) {
    uint32_t y[4];
    for(j = 0; j < 4; j++)
      y[j] = ((uint32_t*)ctext)[i/4 - 4 + j] ^ x[j];

    cmc_block((uint8_t*)y, &ptext[i - 16]);
    memcpy(x, &ptext[i - 16], 16);
  }

  /* Mask */
  uint8_t m[16];
  uint8_t carry = 0;
  for(j = 16; j != 0; j--) {
    uint16_t a = ptext[j - 1] ^ ptext[j - 1 + len - 16];
    m[j] = carry | (uint8_t) (a << 1);
    carry = a >> 7;
  }

  m[16 - 1] |= carry;
  for(i = 0; i < len; i += 16) {
    for(j = 0; j < 4; j++)
      ((uint32_t*)ptext)[i/4 + j] ^= ((uint32_t*)m)[j];
  }

  /* CBC */
  memset(x, 0, 16);
  for(i = 0; i < len; i += 16) {
    uint32_t y[4];
    cmc_block(&ptext[i], (uint8_t*)y);

    uint32_t z[4];
    for(j = 0; j < 4; j++)
      z[j] = y[j] ^ x[j];

    memcpy(x, &ptext[i], 16);
    memcpy(&ptext[i], z, 16);
  }

  return cmc_cleanup();
}

/** @} */
