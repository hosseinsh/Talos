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
#include <project-conf.h>

//Contiki OS Includes
#include <contiki.h>
#include <contiki-lib.h>
#include <contiki-net.h>
#include <ecc-algorithm.h>
#include <mt.h>

//System Includes
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//Relic Includes
#if HAVE_RELIC
#include "relic_err.h"
#include "relic_ecc.h"
#endif

//Additional Apps and Drivers
#include <app_debug.h>
#include <app_timer.h>
#include <test-interface.h>
#include <sha256.h>

//Selected ECC Engine
int8_t ecc_engine = 0;

//Is SimMul Enabled
static int8_t ecc_simmul = 1;

//Storage for keying material
char                    name[16];
uint32_t                pui32Prime[12];
uint32_t                pui32N[12];
uint32_t                pui32A[12];
uint32_t                pui32B[12];
uint32_t                pui32Gx[12];
uint32_t                pui32Gy[12];
ecc_curve_info_t        ec_custrom_curve;
ecc_multiply_state_t*   ecdsa_multiply_state = 0;
ecc_dsa_sign_state_t*   ecdsa_sign_state = 0;
ecc_dsa_verify_state_t* ecdsa_verify_state = 0;

void ec_multiply_hw(void* ptr) {
  ecc_multiply_state_t* state = (ecc_multiply_state_t*)ptr;

  start_high_res_timer();
  PT_INIT(&state->pt);
  while(PT_SCHEDULE(ecc_multiply(state))) {
    mt_yield();
  }
  stop_high_res_timer(1);
}

void ec_multiply_sw(void *ptr) {
#if HAVE_RELIC
  relic_ecc_multiply((ecc_multiply_state_t*)ptr);
#endif
  mt_exit();
}

void ec_generate_sw(void *ptr) {
#if HAVE_RELIC
  relic_ecc_generate((ecc_multiply_state_t*)ptr);
#endif
  mt_exit();
}

void ecdsa_sign_hw(void *ptr) {
  ecc_dsa_sign_state_t* state = (ecc_dsa_sign_state_t*)ptr;

  //Calculate Hash
  uint32_t hash[12];
  memset(hash, 0, 12*4);
  memset(state->hash, 0, 12*4);
  static sha256_state_t hash_state;
  if((state->result = sha256_init(&hash_state)) != 0) return;
  if((state->result = sha256_process(&hash_state, BUFFER.uint8, UIP_HTONL(INCOMMING.payload.uint32[0]))) != 0) return;
  if((state->result = sha256_done(&hash_state, hash)) != 0) return;
  if(state->curve_info->ui8Size > 8) {
    uint32_t i; for(i = 0; i < 8; i++) {
      state->hash[8 - i - 1] = UIP_HTONL(hash[i]);
    }
  } else {
    uint32_t i; for(i = 0; i < state->curve_info->ui8Size; i++) {
      state->hash[state->curve_info->ui8Size - i - 1] = UIP_HTONL(hash[i]);
    }
  }

  //Sign Hash
  start_high_res_timer();
  PT_INIT(&state->pt);
  while(PT_SCHEDULE(ecc_dsa_sign(state))) {
    mt_yield();
  }
  stop_high_res_timer(1);
}

void ecdsa_sign_sw(void *ptr) {
#if HAVE_RELIC
  relic_ecc_sign((ecc_dsa_sign_state_t*)ptr, BUFFER.uint8, UIP_HTONL(INCOMMING.payload.uint32[0]));
#endif
  mt_exit();
}

void ecdsa_verify_hw(void *ptr) {
  ecc_dsa_verify_state_t* state = (ecc_dsa_verify_state_t*)ptr;

  //Calculate Hash
  uint32_t hash[12];
  memset(hash, 0, 12*4);
  memset(state->hash, 0, 12*4);
  static sha256_state_t hash_state;
  if((state->result = sha256_init(&hash_state)) != 0) return;
  if((state->result = sha256_process(&hash_state, BUFFER.uint8, UIP_HTONL(INCOMMING.payload.uint32[0]))) != 0) return;
  if((state->result = sha256_done(&hash_state, hash)) != 0) return;
  if(state->curve_info->ui8Size > 8) {
    uint32_t i; for(i = 0; i < 8; i++) {
      state->hash[8 - i - 1] = UIP_HTONL(hash[i]);
    }
  } else {
    uint32_t i; for(i = 0; i < state->curve_info->ui8Size; i++) {
      state->hash[state->curve_info->ui8Size - i - 1] = UIP_HTONL(hash[i]);
    }
  }

  //Verify Hash
  start_high_res_timer();
  PT_INIT(&state->pt);
  while(PT_SCHEDULE(ecc_dsa_verify(state))) {
    mt_yield();
  }
  stop_high_res_timer(1);
}

void ecdsa_verify_sw(void *ptr) {
#if HAVE_RELIC
  relic_ecc_verify((ecc_dsa_verify_state_t*)ptr, BUFFER.uint8, UIP_HTONL(INCOMMING.payload.uint32[0]));
#endif
  mt_exit();
}

PT_THREAD(app_ecc(struct pt *pt, struct packet_t *packet)) {
  PT_BEGIN(pt);

  //Initialize states
  if(!ecdsa_multiply_state) { ecdsa_multiply_state = malloc(sizeof(ecc_multiply_state_t)); }
  if(!ecdsa_multiply_state) { EXIT_APP(pt, RES_OUT_OF_MEMORY); }
  if(!ecdsa_sign_state) { ecdsa_sign_state = malloc(sizeof(ecc_dsa_sign_state_t)); }
  if(!ecdsa_sign_state) { EXIT_APP(pt, RES_OUT_OF_MEMORY); }
  if(!ecdsa_verify_state) { ecdsa_verify_state = malloc(sizeof(ecc_dsa_verify_state_t)); }
  if(!ecdsa_verify_state) { EXIT_APP(pt, RES_OUT_OF_MEMORY); }

  ec_custrom_curve.name           = (char*)&name;
  ec_custrom_curve.pui32Prime     = (uint32_t*)&pui32Prime;
  ec_custrom_curve.pui32N         = (uint32_t*)&pui32N;
  ec_custrom_curve.pui32A         = (uint32_t*)&pui32A;
  ec_custrom_curve.pui32B         = (uint32_t*)&pui32B;
  ec_custrom_curve.pui32Gx        = (uint32_t*)&pui32Gx;
  ec_custrom_curve.pui32Gy        = (uint32_t*)&pui32Gy;
  ecdsa_multiply_state->curve_info = &ec_custrom_curve;
  ecdsa_multiply_state->process    = PROCESS_CURRENT();
  ecdsa_sign_state->curve_info     = &ec_custrom_curve;
  ecdsa_sign_state->process        = PROCESS_CURRENT();
  ecdsa_verify_state->curve_info   = &ec_custrom_curve;
  ecdsa_verify_state->process      = PROCESS_CURRENT();

  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == SELECT_ECC_ENGINE) {
    if(UIP_HTONS(packet->payload_length) != 1) {
      ERROR_MSG("payload_length != 1");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
#if !HAVE_RELIC
    if(packet->payload.uint8[0]) {
      ERROR_MSG("Relic not compiled in");
      EXIT_APP(pt, RES_NOT_IMPLEMENTED);
    }
#endif

    ecc_engine = packet->payload.uint8[0];

#if HAVE_RELIC
    if(ecc_engine != 0) { //Use Software
      core_init();
      ep_curve_init();
    }
#endif

    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == SWITCH_SIM_MUL) {
    if(UIP_HTONS(packet->payload_length) != 1) {
      ERROR_MSG("payload_length != 1");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    ecc_simmul = packet->payload.uint8[0];
    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EC_SET_CURVE) {
    if(UIP_HTONS(packet->payload_length) < 4) {
      ERROR_MSG("payload_length < 4");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    if(UIP_HTONS(packet->payload_length) != (UIP_HTONL(packet->payload.uint32[0]) * 6 + 1) * 4) {
      ERROR_MSG("payload_length to short for curve info\n");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    ec_custrom_curve.ui8Size = UIP_HTONL(packet->payload.uint32[0]);
    uint8_t i; for(i = 0; i< ec_custrom_curve.ui8Size; i++) {
      ec_custrom_curve.pui32Prime[i] = UIP_HTONL(packet->payload.uint32[(i+1) + ec_custrom_curve.ui8Size*0]);
      ec_custrom_curve.pui32N[i]     = UIP_HTONL(packet->payload.uint32[(i+1) + ec_custrom_curve.ui8Size*1]);
      ec_custrom_curve.pui32A[i]     = UIP_HTONL(packet->payload.uint32[(i+1) + ec_custrom_curve.ui8Size*2]);
      ec_custrom_curve.pui32B[i]     = UIP_HTONL(packet->payload.uint32[(i+1) + ec_custrom_curve.ui8Size*3]);
      ec_custrom_curve.pui32Gx[i]    = UIP_HTONL(packet->payload.uint32[(i+1) + ec_custrom_curve.ui8Size*4]);
      ec_custrom_curve.pui32Gy[i]    = UIP_HTONL(packet->payload.uint32[(i+1) + ec_custrom_curve.ui8Size*5]);
    }
    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EC_SET_GENERATOR) {
    if(UIP_HTONS(packet->payload_length) != ec_custrom_curve.ui8Size * 4 * 2) {
      ERROR_MSG("payload_length to short for generator\n");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    uint8_t i; for(i = 0; i< ec_custrom_curve.ui8Size; i++) {
      ec_custrom_curve.pui32Gx[i]    = UIP_HTONL(packet->payload.uint32[(i+1) + ec_custrom_curve.ui8Size*0]);
      ec_custrom_curve.pui32Gy[i]    = UIP_HTONL(packet->payload.uint32[(i+1) + ec_custrom_curve.ui8Size*1]);
    }
    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EC_GENERATE) {
    if(UIP_HTONS(packet->payload_length) != ec_custrom_curve.ui8Size * 4) {
      ERROR_MSG("payload_length to short for private key\n");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    uint8_t i; for(i = 0; i< ec_custrom_curve.ui8Size; i++) {
      ecdsa_multiply_state->secret[i]          = UIP_HTONL(packet->payload.uint32[i+ec_custrom_curve.ui8Size*0]);
      ecdsa_multiply_state->point_in.pui32X[i] = ecdsa_multiply_state->curve_info->pui32Gx[i];
      ecdsa_multiply_state->point_in.pui32Y[i] = ecdsa_multiply_state->curve_info->pui32Gy[i];
    }

    if(ecc_engine == 0) { //Use Hardware
      mt_start(&test_thread, ec_multiply_hw, ecdsa_multiply_state);
    } else {              //Use Software
      mt_start(&test_thread, ec_generate_sw, ecdsa_multiply_state);
    }
    while(test_thread.state != 5) {
      mt_exec(&test_thread);
      PT_YIELD(pt);
    }

    CHECK_RESULT(pt, ecdsa_multiply_state->result);
    for(i = 0; i< ec_custrom_curve.ui8Size; i++) {
      OUTGOING.payload.uint32[i+ec_custrom_curve.ui8Size*0] = UIP_HTONL(ecdsa_multiply_state->point_out.pui32X[i]);
      OUTGOING.payload.uint32[i+ec_custrom_curve.ui8Size*1] = UIP_HTONL(ecdsa_multiply_state->point_out.pui32Y[i]);
    }

    send_result(ec_custrom_curve.ui8Size * 4 * 2);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EC_MULTIPLY) {
    if(UIP_HTONS(packet->payload_length) != ec_custrom_curve.ui8Size * 4 * 3) {
      ERROR_MSG("payload_length to short for private key and generator\n");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    uint8_t i; for(i = 0; i< ec_custrom_curve.ui8Size; i++) {
      ecdsa_multiply_state->secret[i]          = UIP_HTONL(packet->payload.uint32[i+ec_custrom_curve.ui8Size*0]);
      ecdsa_multiply_state->point_in.pui32X[i] = UIP_HTONL(packet->payload.uint32[i+ec_custrom_curve.ui8Size*1]);
      ecdsa_multiply_state->point_in.pui32Y[i] = UIP_HTONL(packet->payload.uint32[i+ec_custrom_curve.ui8Size*2]);
    }

    if(ecc_engine == 0) { //Use Hardware
      mt_start(&test_thread, ec_multiply_hw, ecdsa_multiply_state);
    } else {              //Use Software
      mt_start(&test_thread, ec_multiply_sw, ecdsa_multiply_state);
    }
    while(test_thread.state != 5) {
      mt_exec(&test_thread);
      PT_YIELD(pt);
    }

    CHECK_RESULT(pt, ecdsa_multiply_state->result);
    for(i = 0; i< ec_custrom_curve.ui8Size; i++) {
      OUTGOING.payload.uint32[i+ec_custrom_curve.ui8Size*0] = UIP_HTONL(ecdsa_multiply_state->point_out.pui32X[i]);
      OUTGOING.payload.uint32[i+ec_custrom_curve.ui8Size*1] = UIP_HTONL(ecdsa_multiply_state->point_out.pui32Y[i]);
    }
    send_result(ec_custrom_curve.ui8Size * 4 * 2);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EC_SET_PRIVATE_KEY) {
    if(UIP_HTONS(packet->payload_length) != ec_custrom_curve.ui8Size * 4) {
      ERROR_MSG("payload_length to short for private key\n");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    uint8_t i; for(i = 0; i< ec_custrom_curve.ui8Size; i++) {
      ecdsa_sign_state->secret[i] = UIP_HTONL(packet->payload.uint32[i]);
    }

    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EC_SET_EPHEMERAL_KEY) {
    if(UIP_HTONS(packet->payload_length) != ec_custrom_curve.ui8Size * 4) {
      ERROR_MSG("payload_length to short for ephemeral key\n");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    uint8_t i; for(i = 0; i< ec_custrom_curve.ui8Size; i++) {
      ecdsa_sign_state->k_e[i] = UIP_HTONL(packet->payload.uint32[i]);
    }

    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EC_SIGN) {
    if(UIP_HTONS(packet->payload_length) != 4) {
      ERROR_MSG("payload_length != 4");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    if(ecc_engine == 0) { //Use Hardware
      mt_start(&test_thread, ecdsa_sign_hw, ecdsa_sign_state);
    } else {              //Use Software
      mt_start(&test_thread, ecdsa_sign_sw, ecdsa_sign_state);
    }
    while(test_thread.state != 5) {
      mt_exec(&test_thread);
      PT_YIELD(pt);
    }

    CHECK_RESULT(pt, ecdsa_sign_state->result);
    uint8_t i; for(i = 0; i< ec_custrom_curve.ui8Size; i++) {
      OUTGOING.payload.uint32[i+ec_custrom_curve.ui8Size*0] = UIP_HTONL(ecdsa_sign_state->point_r.pui32X[i]);
      OUTGOING.payload.uint32[i+ec_custrom_curve.ui8Size*1] = UIP_HTONL(ecdsa_sign_state->signature_s[i]);
    }
    send_result(ec_custrom_curve.ui8Size * 4 * 2);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EC_SET_PUBLIC_KEY) {
    if(UIP_HTONS(packet->payload_length) != ec_custrom_curve.ui8Size * 8) {
      ERROR_MSG("payload_length to short for public key\n");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    uint8_t i; for(i = 0; i< ec_custrom_curve.ui8Size; i++) {
      ecdsa_verify_state->public.pui32X[i] = UIP_HTONL(packet->payload.uint32[i+ec_custrom_curve.ui8Size*0]);
      ecdsa_verify_state->public.pui32Y[i] = UIP_HTONL(packet->payload.uint32[i+ec_custrom_curve.ui8Size*1]);
    }

    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EC_VERIFY) {
    if(UIP_HTONS(packet->payload_length) != 4+ec_custrom_curve.ui8Size *4*2) {
      ERROR_MSG("payload_length to short for r and s\n");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    uint8_t i; for(i = 0; i< ec_custrom_curve.ui8Size; i++) {
      ecdsa_verify_state->signature_r[i] = UIP_HTONL(packet->payload.uint32[1+i+ec_custrom_curve.ui8Size*0]);
      ecdsa_verify_state->signature_s[i] = UIP_HTONL(packet->payload.uint32[1+i+ec_custrom_curve.ui8Size*1]);
    }

    if(ecc_engine == 0) { //Use Hardware
      mt_start(&test_thread, ecdsa_verify_hw, ecdsa_verify_state);
    } else {              //Use Software
      mt_start(&test_thread, ecdsa_verify_sw, ecdsa_verify_state);
    }
    while(test_thread.state != 5) {
      mt_exec(&test_thread);
      PT_YIELD(pt);
    }

    OUTGOING.payload.uint32[0] = UIP_HTONL(ecdsa_verify_state->result);
    send_result(4);
  /*--------------------------------------------------------------------------*/
 } else {
    ERROR_MSG("Unknown Function");
    EXIT_APP(pt, RES_UNKOWN_FUNCTION);
  }
  PT_END(pt);
}
