/*
 * Original file: https://github.com/Hellblazer/CryptDB/blob/public/crypto/cmc.hh
 *
 * Copyright (c) 2014, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Port to Contiki:
 *         Andreas Dröscher <contiki@anticat.ch>
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
 * \addtogroup cc2538-crypto
 * @{
 *
 * \defgroup cc2538-aes-cmc cc2538 AES-CMC
 *
 * Driver for the cc2538 AES-CMC in various modes
 * @{
 *
 * \file
 * Header file for the cc2538 AES-CMC driver
 */
#ifndef CMC_H_
#define CMC_H_

#include "contiki.h"
#include "dev/crypto.h"

#include <stdbool.h>
#include <stdint.h>
/*---------------------------------------------------------------------------*/
/** \name AES-CMC functions
 * @{
 */

/** \brief Performs an AES operation and is writing/reading data through registers.
 * \param ptext is pointer to input data.
 * \param ctext is pointer to output data.
 * \param ui8KeyLocation is the location in Key RAM.
 * \param len the data length
 * \return \c AES_SUCCESS if successful, or AES error code
 */
uint8_t cmc_encrypt(uint8_t* ptext, uint8_t *ctext, uint8_t ui8KeyLocation, uint32_t len);

/** \brief Performs an AES operation and is writing/reading data through registers.
 * \param ctext is pointer to input data.
 * \param ptext is pointer to output data.
 * \param ui8KeyLocation is the location in Key RAM.
 * \param len the data length
 * \return \c AES_SUCCESS if successful, or AES error code
 */
uint8_t cmc_decrypt(uint8_t *ctext, uint8_t *ptext, uint8_t ui8KeyLocation, uint32_t len);

/** @} */

#endif /* CMC_H_ */

/**
 * @}
 * @}
 */
