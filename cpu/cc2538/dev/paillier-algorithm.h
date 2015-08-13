/*
 * Copyright (c) 2014, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author: Hossein Shafagh <shafagh@inf.ethz.ch>
 *
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
 * SUCH DAMAGE.
 */
/**
 * \addtogroup cc2538
 * @{
 *
 * \defgroup cc2538 RSA Paillier Algorithms
 *
 **
 * \file
 * Header file for the cc2538 Paillier Algorithms
 */
#ifndef PAILLIER_ALGORITHM_H_
#define PAILLIER_ALGORITHM_H_

/*---------------------------------------------------------------------------*/
//#define   key_size                   4  /* 4 * 32bit* 2 = 256 bits*/
//#define   key_size                   8  /* 8 * 32bit* 2 = 512 bits*/
#define   key_size                   16   /* 16 * 32bit* 2 = 1024 bits*/
#define   plain_size                 2*key_size
#define   cipher_size                2*plain_size

/* NOTE: Max_Len equals 64 (32-bit) words swrq319c, p504
 * This is equal to 2048 bit or 256 Byte
 * Maximum vector sizes can be optionally extended to 4096 or 8192 bits (with Max_Len equal to 128 respectively 256)
 */

//structure using create n and e
typedef struct {
  //Containers for the State
  struct pt      pt;
  struct process *process;

  /* Input Variables */
  uint32_t    PrimeP[key_size];       /* prime number p */
  uint32_t    PSize;                 /* size of prime number p*/
  uint32_t    PrimeQ[key_size];       /* prime number q*/
  uint32_t    QSize;                 /* size of prime number Q*/

  uint32_t    rv;                    /* Address of Next Result in PKA SRAM */

  /* computed variables */
  uint32_t    PublicN[plain_size];   /* prime n = p*q the public key */
  uint32_t    NLen;                  /* length of n */
  uint32_t    PrviateL[plain_size];  /* private key L=(p-1)*(q-1) */
  uint32_t    LLen;                  /* length of L */

  uint32_t    PlainText[plain_size]; /* plain-text (max input len is 2*keysize)*/
  uint32_t    PTLen;                 /* plain-text length */

  uint32_t    CipherText[cipher_size*2];/* Cipher-text (def. output len is cipher_size, but more space to hold the value before modulo)*/
  uint32_t    CTLen;                  /* Cipher-text len*/

  uint8_t     result;                 /* Result Code */
} paillier_secrete_state_t;

/*---------------------------------------------------------------------------*/

/**
 * \brief Paillier geneate keys
 */
PT_THREAD(paillier_gen(paillier_secrete_state_t *state));

/**
 * \brief Paillier Encrypt
 */
PT_THREAD(paillier_enc(paillier_secrete_state_t *state));


/**
 * \brief Paillier decrypt
 */
PT_THREAD(paillier_dec(paillier_secrete_state_t *state));

/**
 * \brief Paillier add two ciphers
 */
PT_THREAD(paillier_add(paillier_secrete_state_t *state));


#endif /* PAILLIER_ALGORITHM_H_ */

/**
 * @}
 * @}
 */

