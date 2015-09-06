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

//System Includes
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//Additional Apps and Drivers
#include <app_debug.h>
#include <test-interface.h>
#include <app_timer.h>
#include <blowfish.h>

//Blowfish State
static uint32_t high, low;
static blowfish_t *container = 0;

PT_THREAD(app_blowfish(struct pt *pt, struct packet_t *packet)) {
  PT_BEGIN(pt);
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == BLOWFISH_INIT) {
    if(UIP_HTONS(packet->payload_length) < 4) {
      ERROR_MSG("payload_length < 4");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    if(UIP_HTONS(packet->payload_length) > 56) {
      ERROR_MSG("payload_length > 56");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    //Allocate Memory during first run
    if(!container) { container = malloc(sizeof(blowfish_t)); }
    if(!container) { EXIT_APP(pt, RES_OUT_OF_MEMORY); }

    start_high_res_timer();
    blowfish_initialize(packet->payload.uint8, UIP_HTONS(packet->payload_length), container);
    stop_high_res_timer(1);

    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == BLOWFISH_ENC) {
    if(UIP_HTONS(packet->payload_length) != 8) {
      ERROR_MSG("payload_length != 8");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    low = UIP_HTONL(packet->payload.uint32[0]);
    high = UIP_HTONL(packet->payload.uint32[1]);

    start_high_res_timer();
    blowfish_cipher(container, &high, &low, BLOWFISH_ENCRYPT);
    stop_high_res_timer(1);

    OUTGOING.payload.uint32[0] = UIP_HTONL(low);
    OUTGOING.payload.uint32[1] = UIP_HTONL(high);

    send_result(8);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == BLOWFISH_DEC) {
    if(UIP_HTONS(packet->payload_length) != 8) {
      ERROR_MSG("payload_length != 8");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    low = UIP_HTONL(packet->payload.uint32[0]);
    high = UIP_HTONL(packet->payload.uint32[1]);

    start_high_res_timer();
    blowfish_cipher(container, &high, &low, BLOWFISH_DECRYPT);
    stop_high_res_timer(1);

    OUTGOING.payload.uint32[0] = UIP_HTONL(low);
    OUTGOING.payload.uint32[1] = UIP_HTONL(high);

    send_result(8);
  }
  /*--------------------------------------------------------------------------*/
  else {
    ERROR_MSG("Unknown Function");
    EXIT_APP(pt, RES_UNKOWN_FUNCTION);
  }
  PT_END(pt);
}
