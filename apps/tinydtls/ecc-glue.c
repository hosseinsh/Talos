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
