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
#include "contiki.h"
#include "ecc-glue.h"
#include "ccm-glue.h"
#include "ecc-algorithm.h"
#include "ecc-curve.h"
#include "pt.h"
#include "mt.h"
#include "debug.h"

void ecc_ecdh(const uint32_t *px, const uint32_t *py, const uint32_t *secret, uint32_t *resultx, uint32_t *resulty) {
  //Prepare Data
  static ecc_multiply_state_t state = {
    .curve_info = &nist_p_256,
  };
  state.process = PROCESS_CURRENT();
  memcpy(state.point_in.pui32X, px, sizeof(uint32_t)*8);
  memcpy(state.point_in.pui32Y, py, sizeof(uint32_t)*8);
  memcpy(state.secret, secret, sizeof(uint32_t)*8);

  //Process
  pka_enable();
  PT_INIT(&state.pt);
  while(PT_SCHEDULE(ecc_multiply(&state))) {
    mt_yield();
  }
  pka_disable();
  if(state.result) { dtls_crit("can not calculate shared secret\n"); }

  //Get Result
  memcpy(resultx, state.point_out.pui32X, sizeof(uint32_t)*8);
  memcpy(resulty, state.point_out.pui32Y, sizeof(uint32_t)*8);
}

int ecc_is_valid_key(const uint32_t * priv_key) {
  //Prepare Data
  static ecc_compare_state_t state;
  state.process = PROCESS_CURRENT();
  memcpy(state.a, priv_key, sizeof(uint32_t)*8);
  memcpy(state.b, nist_p_256.pui32N, sizeof(uint32_t)*8);

  //Process
  pka_enable();
  PT_INIT(&state.pt);
  while(PT_SCHEDULE(ecc_compare(&state))) {
    mt_yield();
  }
  pka_disable();

  //A key is valid if it is smaller as the order of the cyclic group
  return state.result != PKA_STATUS_A_LT_B;
}

void ecc_gen_pub_key(const uint32_t *priv_key, uint32_t *pub_x, uint32_t *pub_y) {
  //Prepare Data
  static ecc_multiply_state_t state = {
    .curve_info = &nist_p_256,
  };
  state.process = PROCESS_CURRENT();
  memcpy(state.point_in.pui32X, nist_p_256.pui32Gx, sizeof(uint32_t)*8);
  memcpy(state.point_in.pui32Y, nist_p_256.pui32Gy, sizeof(uint32_t)*8);
  memcpy(state.secret, priv_key, sizeof(uint32_t)*8);

  //Process
  pka_enable();
  PT_INIT(&state.pt);
  while(PT_SCHEDULE(ecc_multiply(&state))) {
    mt_yield();
  }
  pka_disable();
  if(state.result) { dtls_crit("can not calculate public key\n"); }

  //Get Result
  memcpy(pub_x, state.point_out.pui32X, sizeof(uint32_t)*8);
  memcpy(pub_y, state.point_out.pui32Y, sizeof(uint32_t)*8);
}

int ecc_ecdsa_sign(const uint32_t *d, const uint32_t *e, const uint32_t *k, uint32_t *r, uint32_t *s) {
  //Prepare Data
  static ecc_dsa_sign_state_t state = {
    .curve_info = &nist_p_256,
  };
  state.process = PROCESS_CURRENT();
  memcpy(state.secret, d, sizeof(uint32_t)*8);
  memcpy(state.hash,   e, sizeof(uint32_t)*8);
  memcpy(state.k_e,    k, sizeof(uint32_t)*8);

  //Process
  pka_enable();
  PT_INIT(&state.pt);
  while(PT_SCHEDULE(ecc_dsa_sign(&state))) {
    mt_yield();
  }
  pka_disable();

  //Get Result
  memcpy(r, state.point_r.pui32X, sizeof(uint32_t)*8);
  memcpy(s, state.signature_s, sizeof(uint32_t)*8);
  return -state.result;
}

int ecc_ecdsa_validate(const uint32_t *x, const uint32_t *y, const uint32_t *e, const uint32_t *r, const uint32_t *s) {
  //Prepare Data
  static ecc_dsa_verify_state_t state = {
    .curve_info = &nist_p_256,
  };
  state.process = PROCESS_CURRENT();
  memcpy(state.public.pui32X, x, sizeof(uint32_t)*8);
  memcpy(state.public.pui32Y, y, sizeof(uint32_t)*8);
  memcpy(state.hash,          e, sizeof(uint32_t)*8);
  memcpy(state.signature_r,   r, sizeof(uint32_t)*8);
  memcpy(state.signature_s,   s, sizeof(uint32_t)*8);

  //Process
  pka_enable();
  PT_INIT(&state.pt);
  while(PT_SCHEDULE(ecc_dsa_verify(&state))) {
    mt_yield();
  }
  pka_disable();
  if(state.result) { dtls_crit("can not validate signature: %u\n", (unsigned int)state.result); }

  //Get Result
  return -state.result;
}
