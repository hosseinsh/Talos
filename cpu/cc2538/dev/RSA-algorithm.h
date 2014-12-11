/*
 * Copyright (c) 2014 hu luo <huluo45@163.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
/**
 * \addtogroup cc2538-RSA
 * @{
 *
 * \defgroup cc2538-RSA-algo cc2538 RSA Algorithms
 *
 *
 * \note
 * Only one request can be processed at a time.
 * Maximal supported key length is 2048bit (64 words).
 * @{
 *
 * \file
 * Header file for the cc2538 RSA Algorithms
 */
#ifndef RSA_ALGORITHM_H_
#define RSA_ALGORITHM_H_

#include "ecc-driver.h"

//***********************************************************************
//big prime number 512
/*
static uint32_t Prime_p_256_p[16] = { 0xFAF72D97, 0x665C4766, 0xB9BB3C33, 0x75CC54E0,0x71121F90,0xB4AA944C,0xB88E4BEE,0x64F9D3F8,
                                      0x71DFB9A7, 0x0555DFCE, 0x39193D1B, 0xEBD5FA63,0x01522E01,0x7B05335F,0xF5816AF9,0xC865C765};
static uint32_t Prime_q_256_q[16] = { 0xEAA0F7B0, 0x11D858BC, 0x1FE7D9EA, 0xE62BE368,0x48397A0C,0x165DE358,0x95DBB7CB,0xE8F024B4,
                                      0x65625AEB, 0x2808790A, 0x305318C5, 0x3635DC5C,0xF6667744,0xF2B4BA46,0xCF300ADF,0x05AE4023};

static uint32_t Prime_e_256_e[]   = { 0x00010001};
//big number 1 for subtract
static uint32_t ONE_256_one[]     = { 0x00000001, 0x00000000, 0x00000000, 0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
		                              0x00000000, 0x00000000, 0x00000000, 0x00000000,0x00000000,0x00000000,0x00000000,0x00000000};

*/


//*************************************************************************
//structure using create n and e
typedef struct {
  //Containers for the State
  struct pt      pt;
  struct process *process;

  //Input Variables

  uint32_t    PrimeP[8];       //prime p
  uint8_t     PSize;     /*the size of prime number p*/
  uint32_t    PrimeQ[8];   /*the size of prime number Q*/
  uint8_t     QSize;     /*the size of prime number Q*/
  uint32_t    PrimeE;           //prime e
  uint8_t     ESize;     /*the size of prime number E*/

  uint32_t    ONEDATA[8];

  uint32_t    rv;                     //Address of Next Result in PKA SRAM
  //Output Variables
  uint32_t    PrimeF[16];             // The product of prime number F=(p-1)*(q-1)
  uint32_t    FLen;                   //the size of prime number F
  uint32_t    PublicN[16];            //prime n----the public key
  uint32_t    NLen;                   //the length of n
  uint32_t    PrviateD[16];           //the private key
  uint32_t    DLen;                   //the length of d

  uint32_t    Messagetoencrypt[16];   //clear text
  uint8_t     MLen;                   //message length

  uint32_t    secretMessage[16];      //message be encrypted
  uint8_t     SMLen;

  uint8_t     result;                 //Result Code
} RSA_secrete_state_t;


//structure using to send data
typedef struct {
  //Containers for the State
  struct pt      pt;
  struct process *process;

  //Input Variables

  uint32_t    PrimeE;           //prime e
  uint8_t     ESize;     /*the size of prime number E*/

  uint32_t    rv;                     //Address of Next Result in PKA SRAM
  //Output Variables
  uint32_t    PublicN[16];            //prime n----the public key
  uint32_t    NLen;                   //the length of n

  uint32_t    secretMessage[16];      //message be encrypted
  uint8_t     SMLen;                  //message length

  uint8_t     result;                 //Result Code
} RSA_public_state_t;

/**
 * \create public key
 *
 *
 * Calculating a Public Key
 */
//PT_THREAD(ecc_multiply(ecc_multiply_state_t *state));
PT_THREAD(RSA_create_public(RSA_secrete_state_t *state));
//***********************************************************************
/**
 * \create private key
 *
 *
 * Calculating a private Key
 */
PT_THREAD(RSA_create_private(RSA_secrete_state_t *state));

/**
 * \encrypt message
 *
 *
 * encrypting message
 */
PT_THREAD(RSA_encrypt_message(RSA_secrete_state_t *state));
/**
 * \decrypt message
 *
 *
 * decrypting message
 */
PT_THREAD(RSA_decrypt_message(RSA_secrete_state_t *state));
/**
 * \signature message
 *
 *
 * signature message
 */
PT_THREAD(RSA_signature_message(RSA_secrete_state_t *state));
/**
 * \signature verification
 *
 *
 * signature verification
 */
PT_THREAD(RSA_signature_verification(RSA_secrete_state_t *state));
#endif /* RSA_ALGORITHM_H_ */

/**
 * @}
 * @}
 */

