/*
 * Copyright (c) 2014, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author: Hosein Shafagh <shafagh@inf.ethz.ch>
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
/**
 * \addtogroup cc2538-examples
 * @{
 **
 * @{
 *
 * \file
 *     Example demonstrating Paillier crypto system on the cc2538dk platform
 */
//Contiki OS Includes
#include <contiki.h>
#include <contiki-lib.h>
#include <contiki-net.h>

//Additional Apps and Drivers
#include <flash-erase.h>

#include "sys/rtimer.h"
#include "pt.h"


//Relic Includes
#include "relic_err.h"
#include "relic_bn.h"
#include "relic_ec.h"
#include "relic_paillier.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "watchdog.h"

/*---------------------------------------------------------------------------*/
//Define Process
PROCESS(paillier_test_process, "Paillier Test Process");
// Start Process
AUTOSTART_PROCESSES(&paillier_test_process, &flash_erase_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(paillier_test_process, ev, data) {
	PROCESS_BEGIN();

  uint8_t plain_text = 144;
  static uint8_t cipher_out[256];
  int cipher_len = 256;
  static uint8_t plain_out[12];
  int plain_out_len = 12;
  /*
   * Variable for Time Measurement
   */
  static rtimer_clock_t time;
  watchdog_stop();
  /*
   * Activate Engine
   */
  printf("-----------------------------------------\n"
       "paillier");

  static bn_t n, l;
  int key_size = 512;

  bn_null(n);
  bn_null(l);

  bn_new(n);
  bn_new(l);

  printf("init:%i \n",core_init());
  printf("initialized\n");
  printf("DV_DIGS %d\n", DV_DIGS);


  time = RTIMER_NOW();
  relic_paillier_gen(n, l, key_size);
  time = RTIMER_NOW() - time;
  printf("paillier_gen(), %lu ms\n",
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));


  time = RTIMER_NOW();
  relic_paillier_enc(cipher_out, &cipher_len, &plain_text, sizeof(plain_text), n);
  time = RTIMER_NOW() - time;
  printf("paillier_enc(), %lu ms\n",
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));
  printf("cipherlen %i\n", cipher_len);



  time = RTIMER_NOW();
  relic_paillier_enc(cipher_out, &cipher_len, &plain_text, sizeof(plain_text), n);
  time = RTIMER_NOW() - time;
  printf("paillier_enc(), %lu ms\n",
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));
  printf("cipherlen %i\n", cipher_len);



  time = RTIMER_NOW();
  relic_paillier_dec(plain_out, &plain_out_len, cipher_out, cipher_len, n, l);
  time = RTIMER_NOW() - time;
  printf("paillier_dec(), %lu ms\n",
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));

  printf("cipherlen %i %s\n", plain_out_len, plain_out[0] == plain_text ?  "CORRECT" : "FAILED");

  printf("Done!\n");

  watchdog_start();
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
