/*
 * Copyright (c) 2014, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author: Hossein Shafagh <shafagh@inf.ethz.ch>
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
 * \addtogroup cc2538-ecc
 * @{
 *
 * \defgroup cc2538-ecc-algo cc2538 ECC Algorithms
 *
 * This is a implementation of ECDH, ECDSA sign and ECDSA verify. It
 * uses ecc-driver to communicate with the PKA. It uses continuations
 * to free the main CPU / thread while the PKA is calculating.
 *
 * \note
 * Only one request can be processed at a time.
 * Maximal supported key length is 384bit (12 words).
 * @{
 *
 * \file
 * Header file for the cc2538 EC-ElGamal Algorithms
 */
#ifndef EC_ELGAMAL_PROCESS_H_
#define EC_ELGAMAL_PROCESS_H_

#include "bignum-driver.h"
#include "ecc-driver.h"


typedef struct {
  /* Containers for the State */
  struct pt      pt;
  struct process *process;

  /* Configuration Variables */
  ecc_curve_info_t* curve_info; /* Curve defining the CyclicGroup */
  ec_point_t  public;           /* Public Point */
  uint32_t    secret[8];        /* Secret Key */
  uint32_t    random[8];        /* Ephemeral Key */
  ec_point_t  rand_public;      /* Random x Public Point (rQ: summand of first part of cipher)*/
  ec_point_t  inverse_secret_cipher_p2;  /* DEC: inverse of Secret multiplied C" */

  /* Variables Holding intermediate data (initialized/used internally) */
  uint32_t    rv;               /* Address of Next Result in PKA SRAM */
  uint32_t    len;              /* len of input */

  /* In/Output Variables */
  uint8_t     result;           /* Result Code */
  ec_point_t  cipher_p1;        /* C': first part of the cipher: M + rQ */
  ec_point_t  cipher_p2;        /* C": second part of cipher: Random x Generator Point */
  ec_point_t  plain;            /* plain text */
} ec_elgmal_enc_state_t;


typedef struct {
  /* Containers for the State */
  struct pt      pt;
  struct process *process;

  /* Config Variables */
  ecc_curve_info_t* curve_info;   /* Curve defining the CyclicGroup */
  uint8_t     int_to_ecpoint;     /* direction of the mapping */
  uint32_t    K;                 /* (m+1)K < prime p and 1/2^K chance of failure */
  uint32_t    exponent[6];        /* NIST-Routines 3.2.2  (mp_mod_sqrt_192) = 2^190 - 2^62 */

  /* Variables Holding intermediate data (initialized/used internally) */
  uint32_t    rv;                 /* Address of Next Result in PKA SRAM */

  /* Input/Output */
  uint8_t     result;             /* Result Code */
  uint8_t     j_rounds;           /* Number of iterations to find sqr root*/
  uint32_t    plain_int[6];       /* plain text integer */
  uint32_t    plain_len;          /* length of the plain text integer */
  ec_point_t  plain_ec;           /* plain text as ECC curve point */
} ec_elgmal_map_state_t;

//TODO Documentation
PT_THREAD(ec_elgamal_generate(ec_elgmal_enc_state_t *state));

/**
 * \brief Plaintext representation as ec-point
 *
 * Maps integers values to EC points and reverse!
 * ec-point = mG
 *
 */
PT_THREAD(ec_elgamal_map_scalar(ec_elgmal_map_state_t *state));

/**
 * \brief Plaintext representation as ec-point
 *
 * Maps integers values to EC points and reverse!
 * By the help of Koublitz method
 * x = mK + j, for a given K such that (m+1)K < prime p, and 0<=j<K
 * y^2 = x^3 + 3x + b mod p
 * ec-point = (x,y)
 * reverse: m = floor(x/K)
 */
PT_THREAD(ec_elgamal_map_koblitz(ec_elgmal_map_state_t *state));


/**
 * \brief Encryption with EC-ElGamal
 *
 * Encryption consists of two parts:
 * Given: random r, public key Q, Generator G, plaintext M
 * 1:  C'= M + rQ
 * 2:  C"= rG
 * the final cipher is = (C', C")
 */
PT_THREAD(ec_elgamal_enc(ec_elgmal_enc_state_t *state));


/**
 * \brief Decryption with EC-ElGamal
 *
 * Basically computes a ECC-ADD:
 * M = C'+ -dC
 * * This is repeated for every word of the cipher.
 */
PT_THREAD(ec_elgamal_dec(ec_elgmal_enc_state_t *state));



#endif /* EC_ELGAMAL_PROCESS_H_ */

/**
 * @}
 * @}
 */
