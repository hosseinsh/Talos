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
 * \addtogroup cc2538-crypto
 * @{
 *
 * \defgroup cc2538-aes cc2538 AES
 *
 * Driver for the cc2538 AES in various modes
 * @{
 *
 * \file
 * Header file for the cc2538 AES driver
 */
#ifndef AES_H_
#define AES_H_

#include "contiki.h"
#include "dev/crypto.h"

#include <stdbool.h>
#include <stdint.h>
/*---------------------------------------------------------------------------*/
/** \name AES-CCM functions
 * @{
 */
typedef enum {
  AES_ECB = 1,
  AES_CBC = 2,
  AES_CTR = 3,
} AES_MODE;

/** \brief Starts an AES operation.
 * \param pui8MsgIn is pointer to input data.
 * \param pui8IvIn is pointer to input iv.
 * \param pui8MsgOut is pointer to output data.
 * \param ui8KeyLocation is the location in Key RAM.
 * \param ui8Encrypt is set 'true' to ui8Encrypt or set 'false' to decrypt.
 * \param mode the AES mode to use
 * \param len the data length
 * \param process Process to be polled upon completion of the operation, or \c NULL
 * \return \c AES_SUCCESS if successful, or AES error code
 */
uint8_t aes_start(uint8_t *pui8MsgIn, uint8_t *pui8IvIn,
                  uint8_t *pui8MsgOut, uint8_t ui8KeyLocation,
                  uint8_t ui8Encrypt, AES_MODE mode,
                  uint32_t len, struct process *process);

/** \brief Checks the status of the AES operation.
 * \retval false Result not yet available, and no error occurred
 * \retval true Result available, or error occurred
 */
uint8_t aes_check_status();

/** \brief Gets the result of the AES authentication and encryption operation
 * \param pui8IvOut is pointer to output iv.
 * \return \c AES_SUCCESS if successful, or AES error code
 * \note This function must be called only after \c aes_start().
 */
uint8_t aes_get_result(uint8_t *pui8IvOut);

/** \brief Performs an AES operation and is writing/reading data through registers.
 * \param pui8MsgIn is pointer to input data.
 * \param pui8Iv is pointer to input/output iv.
 * \param pui8MsgOut is pointer to output data.
 * \param ui8KeyLocation is the location in Key RAM.
 * \param ui8Encrypt is set 'true' to ui8Encrypt or set 'false' to decrypt.
 * \param mode the AES mode to use
 * \param len the data length
 * \return \c AES_SUCCESS if successful, or AES error code
 */
uint8_t aes(uint8_t *pui8MsgIn, uint8_t *pui8Iv,
            uint8_t *pui8MsgOut, uint8_t ui8KeyLocation,
            uint8_t ui8Encrypt, AES_MODE mode, uint32_t len);

/** @} */

#endif /* AES_H_ */

/**
 * @}
 * @}
 */
