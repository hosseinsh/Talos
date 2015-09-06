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
#include <paillier-algorithm.h>
#include <pt.h>

//System Includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//Additional Apps and Drivers
#include <app_debug.h>
#include <app_timer.h>
#include <test-interface.h>

//Storage for keying material
static paillier_secrete_state_t* paillier_state = 0;

PT_THREAD(app_pailler(struct pt *pt, struct packet_t *packet)) {
  PT_BEGIN(pt);

  //Initialize states on first use
  if(!paillier_state) { paillier_state = malloc(sizeof(paillier_secrete_state_t)); }
  if(!paillier_state) { EXIT_APP(pt, RES_OUT_OF_MEMORY); }
  paillier_state->process    = PROCESS_CURRENT();

  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == PAILLER_SET_P) {
    if(UIP_HTONS(packet->payload_length)/4 > key_size) {
      ERROR_MSG("payload_length > key_size");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    paillier_state->PSize = UIP_HTONS(packet->payload_length)/4;
    uint32_t i; for(i = 0; i < paillier_state->PSize; i++) {
      paillier_state->PrimeP[i] = UIP_HTONL(packet->payload.uint32[i]);
    }

    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == PAILLER_SET_Q) {
    if(UIP_HTONS(packet->payload_length)/4 > key_size) {
      ERROR_MSG("payload_length > key_size");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    paillier_state->QSize = UIP_HTONS(packet->payload_length)/4;
    uint32_t i; for(i = 0; i < paillier_state->QSize; i++) {
      paillier_state->PrimeQ[i] = UIP_HTONL(packet->payload.uint32[i]);
    }

    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == PAILLER_SET_PLAINT) {
    if(UIP_HTONS(packet->payload_length)/4 > plain_size) {
      ERROR_MSG("payload_length > plain_size");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    paillier_state->PTLen = UIP_HTONS(packet->payload_length)/4;
    uint32_t i; for(i = 0; i < paillier_state->PTLen; i++) {
      paillier_state->PlainText[i] = UIP_HTONL(packet->payload.uint32[i]);
    }

    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == PAILLER_GET_PLAINT) {
    uint32_t i; for(i = 0; i < paillier_state->PTLen; i++) {
      OUTGOING.payload.uint32[i] = UIP_HTONL(paillier_state->PlainText[i]);
    }
    send_result(paillier_state->PTLen*4);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == PAILLER_SET_CIPHERT) {
    if(UIP_HTONS(packet->payload_length)/4 > cipher_size) {
      ERROR_MSG("payload_length > cipher_size");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    paillier_state->CTLen = UIP_HTONS(packet->payload_length)/4;
    uint32_t i; for(i = 0; i < paillier_state->CTLen; i++) {
      paillier_state->CipherText[i] = UIP_HTONL(packet->payload.uint32[i]);
    }

    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == PAILLER_GET_CIPHERT) {
    uint32_t i; for(i = 0; i < paillier_state->CTLen; i++) {
      OUTGOING.payload.uint32[i] = UIP_HTONL(paillier_state->CipherText[i]);
    }
    send_result(paillier_state->CTLen*4);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == PAILLER_GEN) {
    //Clear Output Variable
    memset(paillier_state->PublicN, 0,  sizeof(uint32_t) * plain_size);
    paillier_state->NLen = plain_size;
    memset(paillier_state->PrviateL, 0, sizeof(uint32_t) * plain_size);
    paillier_state->LLen = plain_size;

    start_timer(0);
    PT_SPAWN(pt, &(paillier_state->pt), paillier_gen(paillier_state));
    stop_timer(0, 1);

    if(paillier_state->result) {
      EXIT_APP(pt, RES_ERROR);
    } else {
      EXIT_APP(pt, RES_SUCCESS);
    }
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == PAILLER_ENC) {
    //Clear Output Variable
    memset(paillier_state->CipherText, 0, sizeof(uint32_t) * cipher_size);
    paillier_state->CTLen = cipher_size;

    start_timer(0);
    PT_SPAWN(pt, &(paillier_state->pt), paillier_enc(paillier_state));
    stop_timer(0, 1);

    if(paillier_state->result) {
      EXIT_APP(pt, RES_ERROR);
    } else {
      EXIT_APP(pt, RES_SUCCESS);
    }
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == PAILLER_ADD) {
    start_timer(0);
    PT_SPAWN(pt, &(paillier_state->pt), paillier_add(paillier_state));
    stop_timer(0, 1);

    if(paillier_state->result) {
      EXIT_APP(pt, RES_ERROR);
    } else {
      EXIT_APP(pt, RES_SUCCESS);
    }
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == PAILLER_DEC) {
    //Clear Output Variable
    memset(paillier_state->PlainText, 0, sizeof(uint32_t) * plain_size);
    paillier_state->PTLen = plain_size;

    start_timer(0);
    PT_SPAWN(pt, &(paillier_state->pt), paillier_dec(paillier_state));
    stop_timer(0, 1);

    if(paillier_state->result) {
      EXIT_APP(pt, RES_ERROR);
    } else {
      EXIT_APP(pt, RES_SUCCESS);
    }
  /*--------------------------------------------------------------------------*/
 } else {
    ERROR_MSG("Unknown Function");
    EXIT_APP(pt, RES_UNKOWN_FUNCTION);
  }
  PT_END(pt);
}
