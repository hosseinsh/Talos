/*
 * Original file: https://raw.githubusercontent.com/jdiez17/blowfish
 *
 * Copyright (c) 2014, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Port to Contiki:
 *       Hossein Shafagh <shafagh@inf.ethz.ch>
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
 * \addtogroup sofware-crypto
 * @{
 *
 * \defgroup crypto blowfish
 *
 * Implementation of blowfish block encryption
 * @{
 *
 * \file
 * Header file for the blowfish block encryption
 */
#ifndef BLOWFISH_H_
#define BLOWFISH_H_

#include <stdint.h>

#define PASSES 16
#define SBOXES 4

#define BLOWFISH_ENCRYPT 1
#define BLOWFISH_DECRYPT 2

#define BLOWFISH_MAX_KEY_BYTES 56

typedef struct {
    uint32_t pass[PASSES+2];
    uint32_t sbox[4][256];
} blowfish_t;

void blowfish_cipher(blowfish_t* container, uint32_t* xl, uint32_t* xr, uint8_t mode);
uint32_t blowfish_initialize(unsigned char* key, uint32_t length, blowfish_t* container);

#endif /* BLOWFISH_H_ */
