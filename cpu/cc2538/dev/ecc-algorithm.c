/*
 * Copyright (c) 2014, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author: Andreas Dröscher <contiki@anticat.ch>
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
 * Implementation of the cc2538 ECC Algorithms
 */
#include <contiki.h>
#include <process.h>

#include <limits.h>
#include <stdio.h>
#include <random.h>

#include "ecc-algorithm.h"
#include "ecc-driver.h"
#include "pka.h"

#if !defined(START_ECC_TIMER)
#define START_ECC_TIMER(index)
#endif

#if !defined(STOP_ECC_TIMER)
#define STOP_ECC_TIMER(index, id)
#endif

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

PT_THREAD(ecc_compare(ecc_compare_state_t *state)) {
  PT_BEGIN(&state->pt);

  CHECK_RESULT(PKABigNumCmpStart(state->a, state->b, state->size, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  state->result = PKABigNumCmpGetResult();

  PT_END(&state->pt);
}

PT_THREAD(ecc_multiply(ecc_multiply_state_t *state)) {
  PT_BEGIN(&state->pt);

  START_ECC_TIMER(7);
  CHECK_RESULT(PKAECCMultiplyStart(state->secret, &state->point_in, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCMultiplyGetResult(&state->point_out, state->rv));
  STOP_ECC_TIMER(7, 7);

  PT_END(&state->pt);
}

PT_THREAD(ecc_generate(ecc_generate_state_t *state)) {
  PT_BEGIN(&state->pt);

  do {
    ecc_random(state->secret, state->curve_info->ui8Size);
    CHECK_RESULT(PKABigNumCmpStart(state->secret, state->curve_info->pui32N, state->curve_info->ui8Size, state->process));
    PT_WAIT_UNTIL(&state->pt, pka_check_status());
    state->result = PKABigNumCmpGetResult();
  } while (state->result != PKA_STATUS_A_LT_B);

  CHECK_RESULT(PKAECCMultGenPtStart(state->secret, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCMultGenPtGetResult(&state->public, state->rv));

  PT_END(&state->pt);
}

PT_THREAD(ecc_add(ecc_add_state_t *state)) {
  PT_BEGIN(&state->pt);

  CHECK_RESULT(PKAECCAddStart(&state->point_a, &state->point_b, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCAddGetResult(&state->point_out, state->rv));

  PT_END(&state->pt);
}

PT_THREAD(ecc_dsa_sign(ecc_dsa_sign_state_t *state)) {
  //Executed Every Time
  uint8_t   size = state->curve_info->ui8Size;
  uint32_t  *ord = state->curve_info->pui32N;

  ec_point_t point;
  memcpy(point.pui32X, state->curve_info->pui32Gx, sizeof(point.pui32X));
  memcpy(point.pui32Y, state->curve_info->pui32Gy, sizeof(point.pui32Y));

  PT_BEGIN(&state->pt);

  //Invert k_e mod n
  CHECK_RESULT(PKABigNumInvModStart(state->k_e, size, ord, size, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumInvModGetResult(state->k_e_inv, size, state->rv));

  //Calculate Point R = K_e * GeneratorPoint
  START_ECC_TIMER(7);
  CHECK_RESULT(PKAECCMultiplyStart(state->k_e, &point, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCMultiplyGetResult(&state->point_r, state->rv));
  STOP_ECC_TIMER(7, 7);

  //Calculate signature using big math functions
  //d*r (r is the x coordinate of PointR)
  CHECK_RESULT(PKABigNumMultiplyStart(state->secret, size, state->point_r.pui32X, size, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  state->len = 24;
  CHECK_RESULT(PKABigNumMultGetResult(state->signature_s, &state->len, state->rv));

  //d*r mod n
  CHECK_RESULT(PKABigNumModStart(state->signature_s, state->len, ord, size, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumModGetResult(state->signature_s, size, state->rv));

  //hash + d*r
  CHECK_RESULT(PKABigNumAddStart(state->hash, size, state->signature_s, size, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  state->len = 24;
  CHECK_RESULT(PKABigNumAddGetResult(state->signature_s, &state->len, state->rv));

  //hash + d*r mod n
  CHECK_RESULT(PKABigNumModStart(state->signature_s, state->len, ord, size, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumModGetResult(state->signature_s, size, state->rv));

  //k_e_inv * (hash + d*r)
  CHECK_RESULT(PKABigNumMultiplyStart(state->k_e_inv, size, state->signature_s, size, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  state->len = 24;
  CHECK_RESULT(PKABigNumMultGetResult(state->signature_s, &state->len, state->rv));

  //k_e_inv * (hash + d*r) mod n
  CHECK_RESULT(PKABigNumModStart(state->signature_s, state->len, ord, size, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumModGetResult(state->signature_s, size, state->rv));

  PT_END(&state->pt);
}

PT_THREAD(ecc_dsa_verify(ecc_dsa_verify_state_t *state)) {
  //Executed Every Time
  uint8_t   size = state->curve_info->ui8Size;
  uint32_t *ord  = state->curve_info->pui32N;

  ec_point_t point;
  memcpy(point.pui32X, state->curve_info->pui32Gx, sizeof(point.pui32X));
  memcpy(point.pui32Y, state->curve_info->pui32Gy, sizeof(point.pui32Y));

  PT_BEGIN(&state->pt);

  //Invert s mod n
  CHECK_RESULT(PKABigNumInvModStart(state->signature_s, size, ord, size, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumInvModGetResult(state->s_inv, size, state->rv));

  //Calculate u1 = s_inv * hash
  CHECK_RESULT(PKABigNumMultiplyStart(state->s_inv, size, state->hash, size, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  state->len  = 24;
  CHECK_RESULT(PKABigNumMultGetResult(state->u1, &state->len, state->rv));

  //Calculate u1 = s_inv * hash mod n
  CHECK_RESULT(PKABigNumModStart(state->u1, state->len, ord, size, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumModGetResult(state->u1, size, state->rv));

  //Calculate u2 = s_inv * r
  CHECK_RESULT(PKABigNumMultiplyStart(state->s_inv, size, state->signature_r, size, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  state->len = 24;
  CHECK_RESULT(PKABigNumMultGetResult(state->u2, &state->len, state->rv));

  //Calculate u2 = s_inv * r mod n
  CHECK_RESULT(PKABigNumModStart(state->u2, state->len, ord, size, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumModGetResult(state->u2, size, state->rv));

  //Calculate p1 = u1 * A (Generator)
  START_ECC_TIMER(7);
  CHECK_RESULT(PKAECCMultiplyStart(state->u1, &point, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCMultiplyGetResult(&state->p1, state->rv));

  //Calculate p2 = u2 * B (Public Key)
  CHECK_RESULT(PKAECCMultiplyStart(state->u2, &state->public, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCMultiplyGetResult(&state->p2, state->rv));
  STOP_ECC_TIMER(7, 7);

  //Calculate P = p1 + p2
  CHECK_RESULT(PKAECCAddStart(&state->p1, &state->p2, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCAddGetResult(&state->p1, state->rv));

  //Verify Result
  CHECK_RESULT(PKABigNumCmpStart(state->signature_r, state->p1.pui32X, size, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  state->result = PKABigNumCmpGetResult();
  if((state->result == PKA_STATUS_A_GR_B) || (state->result == PKA_STATUS_A_LT_B)) {
    state->result = PKA_STATUS_SIGNATURE_INVALID;
  }

  PT_END(&state->pt);
}

/**
 * @}
 * @}
 */
