/*
 * Copyright (c) 2014 Andreas Dröscher <contiki@anticat.ch>
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

#include "ecc-algorithm.h"
#include "ecc-driver.h"
#include "pka.h"

#define CHECK_RESULT(...)                                                    \
  state->result = __VA_ARGS__;                                               \
  if(state->result) {                                                        \
    printf("Line: %u Error: %u\n", __LINE__, (unsigned int) state->result);  \
    PT_EXIT(&state->pt);                                                     \
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

  CHECK_RESULT(PKAECCMultiplyStart(state->secret, &state->point_in, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCMultiplyGetResult(&state->point_out, state->rv));

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
  CHECK_RESULT(PKAECCMultiplyStart(state->k_e, &point, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCMultiplyGetResult(&state->point_r, state->rv));

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
  CHECK_RESULT(PKAECCMultiplyStart(state->u1, &point, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCMultiplyGetResult(&state->p1, state->rv));

  //Calculate p2 = u2 * B (Public Key)
  CHECK_RESULT(PKAECCMultiplyStart(state->u2, &state->public, state->curve_info, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKAECCMultiplyGetResult(&state->p2, state->rv));

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
