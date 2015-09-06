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
#include <crypto.h>
#include <aes.h>
#include <cmc.h>

//Is Upload Enabled
static int8_t aes_upload = 1;

//Initialization Vector In
static uint8_t iv_in[16];

//Initialization Vector Out
static uint8_t iv_out[16];

//AES Mode
static AES_MODE aes_mode = 0;

//AES Interface
static uint8_t aes_interface = 0;

//Selected AES Engine
static int8_t aes_engine = 0;

//Storage for keying material
#if HAVE_RELIC
static uint32_t *ctxe;
static uint32_t *ctxd;
#endif

PT_THREAD(app_aes(struct pt *pt, struct packet_t *packet)) {
  PT_BEGIN(pt);
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == SELECT_AES_ENGINE) {
    if(UIP_HTONS(packet->payload_length) != 1) {
      ERROR_MSG("payload_length != 1");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    aes_engine = packet->payload.uint8[0];
    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == SELECT_AES_MODE) {
    if(UIP_HTONS(packet->payload_length) != 1) {
      ERROR_MSG("payload_length != 1");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    aes_mode = packet->payload.uint8[0];
    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == SELECT_AES_INTERFACE) {
    if(UIP_HTONS(packet->payload_length) != 1) {
      ERROR_MSG("payload_length != 1");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    aes_interface = packet->payload.uint8[0];
    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == AES_SWITCH_UPLOAD) {
    if(UIP_HTONS(packet->payload_length) != 1) {
      ERROR_MSG("payload_length != 1");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    aes_upload = packet->payload.uint8[0];
    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == AES_SET_KEY) {
    if(UIP_HTONS(packet->payload_length) != 16) {
      ERROR_MSG("payload_length != 16");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    if(aes_engine == 0) { //Use Hardware Crypto
      aes_load_keys(INCOMMING.payload.uint8, AES_KEY_STORE_SIZE_KEY_SIZE_128, 1, 0);
    } else {              //Use Software Crypto
      #if HAVE_RELIC
      //Allocate Memory during first run
      if(!ctxe) { ctxe = malloc(sizeof(uint32_t)*60); }
      if(!ctxe) { EXIT_APP(pt, RES_OUT_OF_MEMORY); }
      if(!ctxd) { ctxd = malloc(sizeof(uint32_t)*60); }
      if(!ctxd) { EXIT_APP(pt, RES_OUT_OF_MEMORY); }

      rijndaelKeySetupEnc((u32*)ctxe, INCOMMING.payload.uint8, 128);
      rijndaelKeySetupDec((u32*)ctxd, INCOMMING.payload.uint8, 128);
      #endif
    }

    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == AES_SET_IV) {
    if(UIP_HTONS(packet->payload_length) != 16) {
      ERROR_MSG("payload_length != 16");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    memcpy(iv_in, INCOMMING.payload.uint8, 16);
    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == AES_GET_IV) {
    memcpy(OUTGOING.payload.uint8, iv_out, 16);
    send_result(16);
  } else
  /*--------------------------------------------------------------------------*/
  if((INCOMMING.function == AES_ENCRYPT) || (INCOMMING.function == AES_DECRYPT)) {
    if(UIP_HTONS(packet->payload_length) != 4) {
      ERROR_MSG("payload_length != 4");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    static uint8_t* buffer;
    static uint8_t  enc; enc = (INCOMMING.function == AES_ENCRYPT);

    buffer = malloc(BUFFER_SIZE);
    if(buffer == NULL) {
      EXIT_APP(pt, RES_OUT_OF_MEMORY);
    }

    memcpy(buffer, BUFFER.uint8, BUFFER_SIZE);

    if(aes_engine == 0) { //Use Hardware Crypto
      if(aes_interface) { //aes_interface selects between DMA and Register based i/o)
        memcpy(iv_out, iv_in, 16);
        start_high_res_timer();
        if(aes(buffer, iv_out, buffer, 0, enc, aes_mode, UIP_HTONL(INCOMMING.payload.uint32[0]))) {
          EXIT_APP(pt, RES_ERROR);
        }
        stop_high_res_timer(1);
      } else {
        start_high_res_timer();
        if(aes_start(buffer, iv_in, buffer, 0, enc, aes_mode, UIP_HTONL(INCOMMING.payload.uint32[0]), PROCESS_CURRENT())) {
          EXIT_APP(pt, RES_ERROR);
        }

        while(!aes_check_status()) {
          asm("nop");
        }

        if(aes_get_result(iv_out)) {
          EXIT_APP(pt, RES_ERROR);
        }
        stop_high_res_timer(1);
      }
    } else { //Relic (supports only AES ECB encrypt)
      #if HAVE_RELIC
      if(aes_mode != AES_ECB) {
        free(buffer);
        EXIT_APP(pt, RES_NOT_IMPLEMENTED);
      }

      if(enc) {
        start_high_res_timer();
        int i; for(i = 0; i < UIP_HTONL(INCOMMING.payload.uint32[0]); i = i+16) {
          rijndaelEncrypt((u32*)ctxe, 10, buffer+i, buffer+i);
        }
        stop_high_res_timer(1);
      } else {
        start_high_res_timer();
        int i; for(i = 0; i < UIP_HTONL(INCOMMING.payload.uint32[0]); i = i+16) {
          rijndaelDecrypt((u32*)ctxd, 10, buffer+i, buffer+i);
        }
        stop_high_res_timer(1);
      }
      #else
      free(buffer);
      EXIT_APP(pt, RES_NOT_IMPLEMENTED);
      #endif
    }


    if(aes_upload) {
      memcpy(BUFFER.uint8, buffer, BUFFER_SIZE);
    }
    free(buffer);

    OUTGOING.payload.uint32[0] = INCOMMING.payload.uint32[0];
    send_result(4);
  } else
  /*--------------------------------------------------------------------------*/
  if((INCOMMING.function == CMC_ENCRYPT) || (INCOMMING.function == CMC_DECRYPT)) {
    if(UIP_HTONS(packet->payload_length) != 4) {
      ERROR_MSG("payload_length != 4");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    static uint8_t* buffer;
    buffer = malloc(BUFFER_SIZE);
    if(buffer == NULL) {
      EXIT_APP(pt, RES_OUT_OF_MEMORY);
    }

    if(INCOMMING.function == CMC_ENCRYPT) {
      start_high_res_timer();
      if(cmc_encrypt(BUFFER.uint8, buffer, 0, UIP_HTONL(INCOMMING.payload.uint32[0]))) {
        EXIT_APP(pt, RES_ERROR);
      }
      stop_high_res_timer(1);
    } else {
      start_high_res_timer();
      if(cmc_decrypt(BUFFER.uint8, buffer, 0, UIP_HTONL(INCOMMING.payload.uint32[0]))) {
        EXIT_APP(pt, RES_ERROR);
      }
      stop_high_res_timer(1);
    }

    if(aes_upload) {
      memcpy(BUFFER.uint8, buffer, BUFFER_SIZE);
    }
    free(buffer);

    OUTGOING.payload.uint32[0] = INCOMMING.payload.uint32[0];
    send_result(4);
  }
  /*--------------------------------------------------------------------------*/
  else {
    ERROR_MSG("Unknown Function");
    EXIT_APP(pt, RES_UNKOWN_FUNCTION);
  }
  PT_END(pt);
}
