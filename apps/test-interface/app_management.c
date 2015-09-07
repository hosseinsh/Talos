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
#include <stdio.h>
#include <string.h>

//Additional Apps and Drivers
#include <pka.h>
#include <crypto.h>
#include <app_debug.h>
#include <dev/rom-util.h>
#include <test-interface.h>

PT_THREAD(app_management(struct pt *pt, struct packet_t *packet)) {
  PT_BEGIN(pt);
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == REBOOT) {
    rom_util_reset_device();
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == SWITCH_PKA) {
    if(UIP_HTONS(packet->payload_length) != 1) {
      ERROR_MSG("payload_length != 1");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    if(packet->payload.uint8[0]) {
      pka_enable();
    } else {
      pka_disable();
    }
    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == SWITCH_CRYPTO) {
    if(UIP_HTONS(packet->payload_length) != 1) {
      ERROR_MSG("payload_length != 1");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    if(packet->payload.uint8[0]) {
      crypto_enable();
    } else {
      crypto_disable();
    }
    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  #if USE_APP_SHA256 || USE_APP_CCM || USE_APP_ECC
  if(INCOMMING.function == READ_BUFFER) {
    if(UIP_HTONS(packet->payload_length) < 4) {
      ERROR_MSG("payload_length < 4");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    int16_t offset = UIP_HTONS(packet->payload.uint16[0]);
    int16_t len    = UIP_HTONS(packet->payload.uint16[1]);

    if(len > PAYLOAD_SIZE) {
      ERROR_MSG("len > PAYLOAD_SIZE");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    if(offset + len > BUFFER_SIZE) {
      ERROR_MSG("offset + len > BUFFER_SIZE");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    memcpy(OUTGOING.payload.uint8, &BUFFER.uint8[offset], len);

    send_result(len);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == WRITE_BUFFER) {
    if(UIP_HTONS(packet->payload_length) < 4) {
      ERROR_MSG("payload_length < 4");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    int16_t offset = UIP_HTONS(packet->payload.uint16[0]);
    int16_t len    = UIP_HTONS(packet->payload.uint16[1]);

    if(len > UIP_HTONS(packet->payload_length) + 4) {
      ERROR_MSG("len > packet->payload_length + 4");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    if(offset + len > BUFFER_SIZE) {
      ERROR_MSG("offset + len > BUFFER_SIZE");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    memcpy(&BUFFER.uint8[offset], &packet->payload.uint8[4], len);

    EXIT_APP(pt, RES_SUCCESS);
  /*--------------------------------------------------------------------------*/
  } else
  #endif
  {
    ERROR_MSG("Unknown Function");
    EXIT_APP(pt, RES_UNKOWN_FUNCTION);
  }
  PT_END(pt);
}
