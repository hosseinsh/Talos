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
#include <sha256.h>

//System Includes
#include <stdio.h>
#include <string.h>

//Relic Includes
#if HAVE_RELIC
#include "relic_md.h"
#endif

//Additional Apps and Drivers
#include <app_debug.h>
#include <test-interface.h>
#include <app_timer.h>

//Selected Hash Engine
int8_t sha_engine = 0;

PT_THREAD(app_sha256(struct pt *pt, struct packet_t *packet)) {
  PT_BEGIN(pt);
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == SELECT_SHA256_ENGINE) {
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

    sha_engine = packet->payload.uint8[0];
    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == CALC_HASH) {
    if(UIP_HTONS(packet->payload_length) != 2) {
      ERROR_MSG("payload_length != 2");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    if(sha_engine == 0) { //Use Hardware Crypto
      start_high_res_timer();
      static sha256_state_t state;
      CHECK_RESULT(pt, sha256_init(&state));
      CHECK_RESULT(pt, sha256_process(&state, BUFFER.uint8, UIP_HTONS(INCOMMING.payload.uint16[0])));
      CHECK_RESULT(pt, sha256_done(&state, OUTGOING.payload.uint8));
      stop_high_res_timer(1);

      PT_YIELD(pt);
    } else {              //Use Software Crypto
      start_high_res_timer();
#if HAVE_RELIC
      md_map_sh256(OUTGOING.payload.uint8, BUFFER.uint8, UIP_HTONS(INCOMMING.payload.uint16[0]));
#endif
      stop_high_res_timer(1);
    }
    send_result(32);
  /*--------------------------------------------------------------------------*/
  } else {
    ERROR_MSG("Unknown Function");
    EXIT_APP(pt, RES_UNKOWN_FUNCTION);
  }
  PT_END(pt);
}
