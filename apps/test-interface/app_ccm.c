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

//Relic Includes
#if HAVE_RELIC
#include <relic_ccm.h>
#endif

//Additional Apps and Drivers
#include <app_debug.h>
#include <test-interface.h>
#include <app_timer.h>
#include <ccm.h>

//Selected CCM Engine
static int8_t ccm_engine = 0;

//Is Upload Enabled
static int8_t ccm_upload = 1;

//Storage for keying material
#if HAVE_RELIC
static uint32_t* ctx = 0;
#endif

PT_THREAD(app_ccm(struct pt *pt, struct packet_t *packet)) {
  PT_BEGIN(pt);
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == SELECT_CCM_ENGINE) {
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
    ccm_engine = packet->payload.uint8[0];
    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == CCM_SWITCH_UPLOAD) {
    if(UIP_HTONS(packet->payload_length) != 1) {
      ERROR_MSG("payload_length != 1");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    ccm_upload = packet->payload.uint8[0];
    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == CCM_SET_KEY) {
    if(UIP_HTONS(packet->payload_length) != 16) {
      ERROR_MSG("payload_length != 16");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    if(ccm_engine == 0) { //Use Hardware Crypto
      aes_load_keys(INCOMMING.payload.uint8, AES_KEY_STORE_SIZE_KEY_SIZE_128, 1, 0);
    } else {              //Use Software Crypto
#if HAVE_RELIC
      //Allocate Memory during first run
      if(!ctx) { ctx = malloc(sizeof(uint32_t)*60); }
      if(!ctx) { EXIT_APP(pt, RES_OUT_OF_MEMORY); }

      rijndaelKeySetupEnc((u32*)ctx, INCOMMING.payload.uint8, 128);
#endif
    }

    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == CCM_ENCRYPT) {
    if(UIP_HTONS(packet->payload_length) != 8) {
      ERROR_MSG("payload_length != 8");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    static int res = 0; static uint8_t* buffer;
    static size_t mac_len; mac_len = UIP_HTONS(packet->payload.uint16[0]);
    static size_t len_len; len_len = UIP_HTONS(packet->payload.uint16[1]);
    static size_t msg_len; msg_len = UIP_HTONS(packet->payload.uint16[2]);
    static size_t add_len; add_len = UIP_HTONS(packet->payload.uint16[3]);

    buffer = malloc(BUFFER_SIZE);
    if(buffer == NULL) {
      EXIT_APP(pt, RES_OUT_OF_MEMORY);
    }

    memcpy(buffer, BUFFER.uint8, BUFFER_SIZE);
    start_high_res_timer();
    if(ccm_engine == 0) { //Use Hardware Crypto
      if(ccm_auth_encrypt_start(len_len, 0, buffer+msg_len+16, buffer+msg_len+32, add_len, buffer, msg_len, mac_len, PROCESS_CURRENT())) {
        EXIT_APP(pt, RES_ERROR);
      }

      while(!ccm_auth_encrypt_check_status()) {
        asm("nop");
      }

      if(ccm_auth_encrypt_get_result(buffer+msg_len, mac_len)) {
        EXIT_APP(pt, RES_ERROR);
      }
      res = msg_len + mac_len;
    } else {              //Use Software Crypto
#if HAVE_RELIC
      res = dtls_ccm_encrypt_message(ctx, mac_len, len_len, buffer+msg_len+16, buffer, msg_len, buffer+msg_len+32, add_len);
#endif
    }
    stop_high_res_timer(1);

    if(ccm_upload) {
      memcpy(BUFFER.uint8, buffer, BUFFER_SIZE);
    }
    free(buffer);

    if(res > 0) {
      OUTGOING.payload.uint32[0] = UIP_HTONL(res);
      send_result(4);
    } else {
      EXIT_APP(pt, RES_ERROR);
    }
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == CCM_DECRYPT) {
    if(UIP_HTONS(packet->payload_length) != 8) {
      ERROR_MSG("payload_length != 8");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    static int res = 0; static uint8_t *buffer;
    static size_t mac_len; mac_len = UIP_HTONS(packet->payload.uint16[0]);
    static size_t len_len; len_len = UIP_HTONS(packet->payload.uint16[1]);
    static size_t msg_len; msg_len = UIP_HTONS(packet->payload.uint16[2]);
    static size_t add_len; add_len = UIP_HTONS(packet->payload.uint16[3]);

    buffer = malloc(BUFFER_SIZE);
    if(buffer == NULL) {
      EXIT_APP(pt, RES_OUT_OF_MEMORY);
    }

    memcpy(buffer, BUFFER.uint8, BUFFER_SIZE);
    start_high_res_timer();
    if(ccm_engine == 0) { //Use Hardware Crypto
      if(ccm_auth_decrypt_start(len_len, 0, buffer+msg_len+16, buffer+msg_len+32, add_len, buffer, msg_len, mac_len, PROCESS_CURRENT())) {
        EXIT_APP(pt, RES_ERROR);
      }

      while(!ccm_auth_decrypt_check_status()) {
        asm("nop");
      }

      if(ccm_auth_decrypt_get_result(buffer, msg_len, buffer+msg_len-mac_len, mac_len)) {
        res = 0;
      } else {
        res = msg_len-mac_len;
      }
    } else {              //Use Software Crypto
#if HAVE_RELIC
      res = dtls_ccm_decrypt_message(ctx, mac_len, len_len, buffer+msg_len+16, buffer, msg_len, buffer+msg_len+32, add_len);
#endif
    }
    stop_high_res_timer(1);

    if(ccm_upload) {
      memcpy(BUFFER.uint8, buffer, BUFFER_SIZE);
    }
    free(buffer);

    if(res > 0) {
      OUTGOING.payload.uint32[0] = UIP_HTONL(res);
      send_result(4);
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
