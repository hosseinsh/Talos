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
#include <blowfish.h>
#include "sys/rtimer.h"


#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "watchdog.h"

#define LOW_INPUT            0xdeadbeef
#define HIGH_INPUT           0xc0debabe
/*---------------------------------------------------------------------------*/
//Define Process
PROCESS(blowfish_test_process, "Blowfish Test Process");
// Start Process
AUTOSTART_PROCESSES(&blowfish_test_process, &flash_erase_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(blowfish_test_process, ev, data) {
	PROCESS_BEGIN();

  static uint32_t high, low;
  static blowfish_t container;
  /* our value: high and low 32bit value! */
  high = HIGH_INPUT;
  low = LOW_INPUT;

  /*
   * Variable for Time Measurement
   */
  static rtimer_clock_t time;
  watchdog_stop();
  printf("Blowfish\n"
         "-----------------------------------------\n");

  time = RTIMER_NOW();
  blowfish_initialize("test", 4, &container);
  time = RTIMER_NOW() - time;
  printf("blowfish_initialize(), %lu ms\n",
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));

  //printf("high: %x low: %x\n", (unsigned int)high, (unsigned int)low);

  time = RTIMER_NOW();
  blowfish_cipher(&container, &high, &low, BLOWFISH_ENCRYPT);
  time = RTIMER_NOW() - time;
  printf("blowfish_cipher(), %lu ms\n",
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));

  //printf("high: %x low: %x\n", (unsigned int)high, (unsigned int)low);

  time = RTIMER_NOW();
  blowfish_cipher(&container, &high, &low, BLOWFISH_DECRYPT);
  time = RTIMER_NOW() - time;
  printf("blowfish_cipher(), %lu ms\n",
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));

  //printf("high: %x low: %x\n", (unsigned int)high, (unsigned int)low);
  printf("%s\n", (low == LOW_INPUT && high == HIGH_INPUT)? "Correct!" : "Failed!");

  printf("Done!\n"
         "-----------------------------------------\n");

  watchdog_start();
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
