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
#include <ec-elgamal-algorithm.h>
#include <pt.h>

//System Includes
#include <stdio.h>
#include <string.h>

//Additional Apps and Drivers
#include <app_debug.h>
#include <app_timer.h>
#include <test-interface.h>

//Storage for keying material
extern char                  name[16];
extern uint32_t              pui32Prime[12];
extern uint32_t              pui32N[12];
extern uint32_t              pui32A[12];
extern uint32_t              pui32B[12];
extern uint32_t              pui32Gx[12];
extern uint32_t              pui32Gy[12];
static ecc_curve_info_t      ec_custrom_curve;
static ec_elgmal_map_state_t ec_elgmal_map;
static ec_elgmal_enc_state_t ec_elgmal;

PT_THREAD(app_elgamal(struct pt *pt, struct packet_t *packet)) {
  PT_BEGIN(pt);

  //Initialize states
  ec_custrom_curve.name       = (char*)&name;
  ec_custrom_curve.pui32Prime = (uint32_t*)&pui32Prime;
  ec_custrom_curve.pui32N     = (uint32_t*)&pui32N;
  ec_custrom_curve.pui32A     = (uint32_t*)&pui32A;
  ec_custrom_curve.pui32B     = (uint32_t*)&pui32B;
  ec_custrom_curve.pui32Gx    = (uint32_t*)&pui32Gx;
  ec_custrom_curve.pui32Gy    = (uint32_t*)&pui32Gy;
  ec_elgmal_map.curve_info    = &ec_custrom_curve;
  ec_elgmal_map.process       = PROCESS_CURRENT();
  ec_elgmal.curve_info        = &ec_custrom_curve;
  ec_elgmal.process           = PROCESS_CURRENT();

  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EG_SET_CURVE) {
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
  if(INCOMMING.function == EG_SET_EXPONENT) {
    if(UIP_HTONS(packet->payload_length)/4 != ec_custrom_curve.ui8Size) {
      ERROR_MSG("payload_length != curve_size");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    uint8_t i; for(i = 0; i< ec_custrom_curve.ui8Size; i++) {
      ec_elgmal_map.exponent[i] = UIP_HTONL(packet->payload.uint32[i]);
    }

    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EG_SET_PLAIN_TEXT) {
    if(UIP_HTONS(packet->payload_length) > sizeof(ec_elgmal_map.plain_int)) {
      ERROR_MSG("payload_length > curve_size");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    ec_elgmal_map.plain_len = UIP_HTONS(packet->payload_length)/4;
    uint8_t i; for(i = 0; i < ec_elgmal_map.plain_len; i++) {
      ec_elgmal_map.plain_int[i] = UIP_HTONL(packet->payload.uint32[i]);
    }

    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EG_GET_PLAIN_TEXT) {
    uint8_t i; for(i = 0; i < ec_elgmal_map.plain_len; i++) {
      OUTGOING.payload.uint32[i] = UIP_HTONL(ec_elgmal_map.plain_int[i]);
    }

    send_result(ec_elgmal_map.plain_len*4);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EG_GENERATE) {
    start_timer(0);
    PT_SPAWN(pt, &(ec_elgmal.pt), ec_elgamal_generate(&ec_elgmal));
    stop_timer(0, 1);

    if(ec_elgmal.result) {
      EXIT_APP(pt, RES_ERROR);
    } else {
      EXIT_APP(pt, RES_SUCCESS);
    }
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EG_MAP_TO_EC) {
    if(UIP_HTONS(packet->payload_length) != 1) {
      ERROR_MSG("payload_length != 1");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    //Clear Output Variable
    memset(ec_elgmal_map.plain_ec.pui32X, 0,sizeof(ec_elgmal_map.plain_ec.pui32X));
    memset(ec_elgmal_map.plain_ec.pui32Y, 0,sizeof(ec_elgmal_map.plain_ec.pui32Y));

    //Set Direction
    ec_elgmal_map.int_to_ecpoint = 1;
    ec_elgmal_map.K = packet->payload.uint8[0];

    start_timer(0);
    PT_SPAWN(pt, &(ec_elgmal_map.pt), ec_elgamal_map_koblitz(&ec_elgmal_map));
    stop_timer(0, 1);

    if(ec_elgmal_map.result) {
      EXIT_APP(pt, RES_ERROR);
    }

    //Copy output to ec_elgmal input
    memcpy(ec_elgmal.plain.pui32X, ec_elgmal_map.plain_ec.pui32X, sizeof(ec_elgmal_map.plain_ec.pui32X));
    memcpy(ec_elgmal.plain.pui32Y, ec_elgmal_map.plain_ec.pui32Y, sizeof(ec_elgmal_map.plain_ec.pui32Y));

    //We Upload number of rounds
    OUTGOING.payload.uint32[0] = ec_elgmal_map.j_rounds;
    send_result(4);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EG_MAP_TO_EC_ALT) {
    //Prepare Input
    memcpy(ec_elgmal_map.plain_ec.pui32X, ec_elgmal_map.curve_info->pui32Gx, sizeof(ec_elgmal_map.plain_ec.pui32X));
    memcpy(ec_elgmal_map.plain_ec.pui32Y, ec_elgmal_map.curve_info->pui32Gy, sizeof(ec_elgmal_map.plain_ec.pui32Y));

    start_timer(0);
    PKAECCMultiplyStart(ec_elgmal_map.plain_int, &ec_elgmal_map.plain_ec,
                        ec_elgmal_map.curve_info, &ec_elgmal_map.rv, ec_elgmal_map.process);
    PT_WAIT_UNTIL(pt, pka_check_status());
    PKAECCMultiplyGetResult(&ec_elgmal_map.plain_ec, ec_elgmal_map.rv);
    stop_timer(0, 1);

    if(ec_elgmal_map.result) {
      EXIT_APP(pt, RES_ERROR);
    }

    //Copy output to ec_elgmal input
    memcpy(ec_elgmal.plain.pui32X, ec_elgmal_map.plain_ec.pui32X, sizeof(ec_elgmal_map.plain_ec.pui32X));
    memcpy(ec_elgmal.plain.pui32Y, ec_elgmal_map.plain_ec.pui32Y, sizeof(ec_elgmal_map.plain_ec.pui32Y));

    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EG_MAP_FROM_EC) {
    if(UIP_HTONS(packet->payload_length) != 1) {
      ERROR_MSG("payload_length != 1");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }

    //Clear Output Variable
    memset(ec_elgmal_map.plain_int, 0,sizeof(ec_elgmal_map.plain_int));

    //Copy input from ec_elgmal output
    memcpy(ec_elgmal_map.plain_ec.pui32X, ec_elgmal.plain.pui32X, sizeof(ec_elgmal_map.plain_ec.pui32X));
    memcpy(ec_elgmal_map.plain_ec.pui32Y, ec_elgmal.plain.pui32Y, sizeof(ec_elgmal_map.plain_ec.pui32Y));

    //Set Direction
    ec_elgmal_map.int_to_ecpoint = 0;
    ec_elgmal_map.K = packet->payload.uint8[0];

    start_timer(0);
    PT_SPAWN(pt, &(ec_elgmal_map.pt), ec_elgamal_map_koblitz(&ec_elgmal_map));
    stop_timer(0, 1);

    if(ec_elgmal_map.result) {
      EXIT_APP(pt, RES_ERROR);
    } else {
      EXIT_APP(pt, RES_SUCCESS);
    }
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EG_ADD) {
    // new cipher: cipher + cipher; (c_p1'+c_p1' , c_p2'+c_p2')
    start_timer(0);
    PKAECCAddStart(&ec_elgmal.cipher_p1, &ec_elgmal.cipher_p1, ec_elgmal.curve_info, &ec_elgmal.rv, PROCESS_CURRENT());
    PT_WAIT_UNTIL(pt, pka_check_status());
    PKAECCAddGetResult(&ec_elgmal.cipher_p1, ec_elgmal.rv);

    PKAECCAddStart(&ec_elgmal.cipher_p2, &ec_elgmal.cipher_p2, ec_elgmal.curve_info, &ec_elgmal.rv, PROCESS_CURRENT());
    PT_WAIT_UNTIL(pt, pka_check_status());
    PKAECCAddGetResult(&ec_elgmal.cipher_p2, ec_elgmal.rv);
    stop_timer(0, 1);

    if(ec_elgmal.result) {
      EXIT_APP(pt, RES_ERROR);
    } else {
      EXIT_APP(pt, RES_SUCCESS);
    }
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EG_ENC) {
    //Clear Output Variable
    memset(ec_elgmal.cipher_p1.pui32X, 0, sizeof(ec_elgmal.cipher_p1.pui32X));
    memset(ec_elgmal.cipher_p1.pui32Y, 0, sizeof(ec_elgmal.cipher_p1.pui32Y));
    memset(ec_elgmal.cipher_p2.pui32X, 0, sizeof(ec_elgmal.cipher_p2.pui32X));
    memset(ec_elgmal.cipher_p2.pui32Y, 0, sizeof(ec_elgmal.cipher_p2.pui32Y));

    start_timer(0);
    PT_SPAWN(pt, &(ec_elgmal.pt), ec_elgamal_enc(&ec_elgmal));
    stop_timer(0, 1);

    if(ec_elgmal.result) {
      EXIT_APP(pt, RES_ERROR);
    } else {
      EXIT_APP(pt, RES_SUCCESS);
    }
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == EG_DEC) {
    //Clear Output Variable
    memset(ec_elgmal.plain.pui32X, 0, sizeof(ec_elgmal.plain.pui32X));
    memset(ec_elgmal.plain.pui32Y, 0, sizeof(ec_elgmal.plain.pui32Y));

    start_timer(0);
    PT_SPAWN(pt, &(ec_elgmal.pt), ec_elgamal_dec(&ec_elgmal));
    stop_timer(0, 1);

    if(ec_elgmal.result) {
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
