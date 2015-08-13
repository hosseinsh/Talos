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
 * \addtogroup c2538-ecc-algo
 * @{
 *
 * \file
 * Implementation of the cc2538 EC-ElGamal Algorithms
 */
#include <contiki.h>
#include <process.h>

#include <limits.h>
#include <stdio.h>
#include <random.h>

#include "ec-elgamal-algorithm.h"
#include "ecc-algorithm.h"
#include "ecc-driver.h"
#include "bignum-driver.h"
#include "pka.h"

#define CHECK_RESULT(...)                                                    \
  state->result = __VA_ARGS__;                                               \
  if(state->result) {                                                        \
    printf("Line: %u Error: %u\n", __LINE__, (unsigned int) state->result);  \
    PT_EXIT(&state->pt);                                                     \
  }

static void ecc_random(uint32_t *secret, uint32_t size) {
  uint32_t i; for (i = 0; i < size; ++i) {
    secret[i] = (uint32_t)random_rand() | (uint32_t)random_rand() << 16;
  }
}

PT_THREAD(ec_elgamal_map_koblitz(ec_elgmal_map_state_t *state)){
  uint32_t ec_len = state->curve_info->ui8Size;

  PT_BEGIN(&state->pt);
  static uint32_t tmp[10], tmp2[10];
  static uint32_t tmp_len = 10;

  if (state->int_to_ecpoint == 1) {
    state->j_rounds = 0;
    /* Define x = mK + j, m our plaintext message, 0 <= j < K */
    /* store x = mK */
    // FIXME: our PKI requires the lowest bit of the first byte of the divisor to be set!
    tmp2[0] = state->K + 0x00010000;
    CHECK_RESULT(PKABigNumMultiplyStart(state->plain_int,ec_len, tmp2, 1, &state->rv, state->process));
    PT_WAIT_UNTIL(&state->pt, pka_check_status());
    CHECK_RESULT(PKABigNumMultGetResult(state->plain_ec.pui32X, &ec_len, state->rv));
      /* plain to ec-point */
      do{
         memset(tmp,0, sizeof(tmp));
         memset(tmp2,0, sizeof(tmp2));
         if (state->j_rounds > 0){
           /* iterate over j; x = mK + j, */
           tmp2[0] = 1;
           // TODO: This would do as well the job and saves code space! state->plain_ec.pui32X[0] += 1 (issue: possible overflow!);
           CHECK_RESULT(PKABigNumAddStart(state->plain_ec.pui32X, ec_len, tmp2, 1, &state->rv, state->process));
           PT_WAIT_UNTIL(&state->pt, pka_check_status());
           CHECK_RESULT(PKABigNumAddGetResult(state->plain_ec.pui32X, &ec_len, state->rv));
         }
         /* Compute step by step: y^2 = x^3 - 3x + b (mod p) */
         /* tmp = 3x mod p (we save the mod operation since 3x << p)*/
         tmp2[0] = 3;
         CHECK_RESULT(PKABigNumMultiplyStart(tmp2, 1, state->plain_ec.pui32X, ec_len, &state->rv, state->process));
         PT_WAIT_UNTIL(&state->pt, pka_check_status());
         CHECK_RESULT(PKABigNumMultGetResult(tmp, &tmp_len, state->rv));

         /* tmp2 = x^3 mod p*/
         tmp2[0] = 3;
         CHECK_RESULT(PKABigNumExpModStart(tmp2, 1,
                                       state->curve_info->pui32Prime, ec_len,
                                       state->plain_ec.pui32X, ec_len,  &state->rv, state->process));
         PT_WAIT_UNTIL(&state->pt, pka_check_status());
         CHECK_RESULT(PKABigNumExpModGetResult(tmp2, tmp_len, state->rv));

         /* tmp = tmp2 - tmp; x^3 - 3x */
         CHECK_RESULT(PKABigNumSubtractStart(tmp2, ec_len, tmp, ec_len, &state->rv, state->process));
         PT_WAIT_UNTIL(&state->pt, pka_check_status());
         CHECK_RESULT(PKABigNumSubtractGetResult(tmp, &tmp_len, state->rv));

         /* tmp = tmp + b;  x^3 - 3x + b */
         CHECK_RESULT(PKABigNumAddStart(tmp, tmp_len, state->curve_info->pui32B, ec_len, &state->rv, state->process));
         PT_WAIT_UNTIL(&state->pt, pka_check_status());
         tmp_len=10; // reset the len
         CHECK_RESULT(PKABigNumAddGetResult(tmp, &tmp_len, state->rv));

         /* tmp = tmp (mod p) INFO: this is due to distributive feature of Modulo:
          * (a+b) mod p = ((a mod p) + (b mod p)) mod p
          */
         CHECK_RESULT(PKABigNumModStart(tmp, ec_len, state->curve_info->pui32Prime, ec_len, &state->rv,state->process));
         PT_WAIT_UNTIL(&state->pt, pka_check_status());
         CHECK_RESULT(PKABigNumModGetResult(tmp, tmp_len, state->rv));

         /* y^2 = x^3 - 3x + b (mod p) */
         /* y^2 = tmp (mod p) */
         /* compute the square root: (exp, len, mod p, len, base, len) */
         CHECK_RESULT(PKABigNumExpModStart(state->exponent, ec_len,
                                       state->curve_info->pui32Prime, ec_len,
                                       tmp, ec_len,  &state->rv, state->process));
         PT_WAIT_UNTIL(&state->pt, pka_check_status());
         CHECK_RESULT(PKABigNumExpModGetResult(state->plain_ec.pui32Y, ec_len, state->rv));

         /* check if the squire root was correct by
          * calculating y2 */
         tmp2[0] = 2;
         CHECK_RESULT(PKABigNumExpModStart(tmp2, 1,
                                          state->curve_info->pui32Prime, ec_len,
                                          state->plain_ec.pui32Y, ec_len,  &state->rv, state->process));
         PT_WAIT_UNTIL(&state->pt, pka_check_status());
         CHECK_RESULT(PKABigNumExpModGetResult(tmp2, tmp_len, state->rv));

         /* tmp = tmp (mod p)*/
         CHECK_RESULT(PKABigNumModStart(tmp, ec_len, state->curve_info->pui32Prime, ec_len, &state->rv,state->process));
         PT_WAIT_UNTIL(&state->pt, pka_check_status());
         CHECK_RESULT(PKABigNumModGetResult(tmp, tmp_len, state->rv));

         /* comparison*/
         CHECK_RESULT(PKABigNumCmpStart(tmp2, tmp, tmp_len, state->process));
         PT_WAIT_UNTIL(&state->pt, pka_check_status());
         state->result = PKABigNumCmpGetResult();
         state->j_rounds += 1;
      }while(state->result != 0 && state->j_rounds < state->K);
  } else {
    /* ec-point to plain */
    /* m = floor(x/K) (greatest integer less or equal to x/K)*/
    memset(tmp2,0, sizeof(tmp2));
    // FIXME: our PKI requires the lowest bit of the first byte of the divisor to be set!
    tmp2[0] = state->K + 0x00010000;
    CHECK_RESULT(PKABigNumDivideStart(state->plain_ec.pui32X, ec_len, tmp2, 1, &state->rv, state->process));
    PT_WAIT_UNTIL(&state->pt, pka_check_status());
    CHECK_RESULT(PKABigNumDivideGetResult(state->plain_int, &state->plain_len, state->rv));
  }

  PT_END(&state->pt);
}




PT_THREAD(ec_elgamal_map_scalar(ec_elgmal_map_state_t *state)){
  PT_BEGIN(&state->pt);
  if (state->int_to_ecpoint == 1) {
    /* m = integer * G */
    CHECK_RESULT(PKAECCMultGenPtStart((uint32_t*)&state->plain_int, state->curve_info, &state->rv, state->process));
    PT_WAIT_UNTIL(&state->pt, pka_check_status());
    CHECK_RESULT(PKAECCMultGenPtGetResult(&state->plain_ec, state->rv));
  }else{
    //This is a very hard problem!
  };

  PT_END(&state->pt);
}

PT_THREAD(ec_elgamal_generate(ec_elgmal_enc_state_t *state)) {
  PT_BEGIN(&state->pt);
  /* secret: a random integer */
  do {
    ecc_random(state->secret, state->curve_info->ui8Size);
    CHECK_RESULT(PKABigNumCmpStart(state->secret, state->curve_info->pui32N, state->curve_info->ui8Size, state->process));
    PT_WAIT_UNTIL(&state->pt, pka_check_status());
    state->result = PKABigNumCmpGetResult();
  } while (state->result != PKA_STATUS_A_LT_B);

  /* another random integer */
  do {
    ecc_random(state->random, state->curve_info->ui8Size);
    CHECK_RESULT(PKABigNumCmpStart(state->random, state->curve_info->pui32N, state->curve_info->ui8Size, state->process));
    PT_WAIT_UNTIL(&state->pt, pka_check_status());
    state->result = PKABigNumCmpGetResult();
  } while (state->result != PKA_STATUS_A_LT_B);

  /* Public key = secret * G  */
  CHECK_RESULT(PKAECCMultGenPtStart(state->secret, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCMultGenPtGetResult(&state->public, state->rv));

  PT_END(&state->pt);
}


PT_THREAD(ec_elgamal_enc(ec_elgmal_enc_state_t *state)){
  PT_BEGIN(&state->pt);
  /* Encryption:
   * compute C'= M + rQ, r is random and Q the public key (rQ is pre-calculated)
   * compute C"= rG, G is the base point (C" is pre-calculated)
   * cipher is (C', C")
   */

  /* C" = r * G */
  CHECK_RESULT(PKAECCMultGenPtStart(state->random, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCMultGenPtGetResult(&state->cipher_p2, state->rv));

  /* rQ = r * Q, This should always be the same to have add. HOM ! */
  CHECK_RESULT(PKAECCMultiplyStart(state->random, &state->public, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCMultiplyGetResult(&state->rand_public, state->rv));

  /* C' = M + rQ */
  CHECK_RESULT(PKAECCAddStart(&state->plain, &state->rand_public, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCAddGetResult(&state->cipher_p1, state->rv));

  PT_END(&state->pt);
}


PT_THREAD(ec_elgamal_dec(ec_elgmal_enc_state_t *state)){
   PT_BEGIN(&state->pt);
  /* Decryption: M = C' - dC" */

   state->len =  state->curve_info->ui8Size;

   /* dC = d * C", where C" is the second parameter (rG) */
   CHECK_RESULT(PKAECCMultiplyStart(state->secret, &state->cipher_p2, state->curve_info, &state->rv, state->process));
   PT_WAIT_UNTIL(&state->pt, pka_check_status());
   CHECK_RESULT(PKAECCMultiplyGetResult(&state->inverse_secret_cipher_p2, state->rv));

   /* Compute the inverse of elliptic curve point dC = (x, y), by (x, -y mode p) */
   /* (p-y) + y  = p = 0 (mod p) (BigNum) */
   /* inverse of y = p-y */
   CHECK_RESULT(PKABigNumSubtractStart(state->curve_info->pui32Prime, state->curve_info->ui8Size,
                                       state->inverse_secret_cipher_p2.pui32Y, state->curve_info->ui8Size,
                                        &state->rv, state->process));
   PT_WAIT_UNTIL(&state->pt, pka_check_status());
   CHECK_RESULT(PKABigNumSubtractGetResult(state->inverse_secret_cipher_p2.pui32Y, &state->len, state->rv));

  /* M = C' + -dC; */
  CHECK_RESULT(PKAECCAddStart(&state->cipher_p1, &state->inverse_secret_cipher_p2, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCAddGetResult(&state->plain, state->rv));

  PT_END(&state->pt);
}




/**
 * @}
 * @}
 */
