/*
 * Copyright (c) 2014, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author: Hossein Shafagh <shafagh@inf.ethz.ch>
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
 *
 * \defgroup cc2538dk Paillier Test Project
 *
 *   ECDH example for CC2538 on SmartRF06EB.
 *
 * @{
 *
 * \file
 *     Example demonstrating Paillier on the cc2538dk platform
 */
#include "contiki.h"
#include "flash-erase.h"
#include "paillier-algorithm.h"
#include "random.h"
#include "rtimer.h"
#include "pka.h"
#include "pt.h"

#include <string.h>
#include <stdio.h>

/*---------------------------------------------------------------------------*/
/* big prime numbers for 2*key_size bit key*, Stored in ‘little endian’ words */
#if key_size==4
static uint32_t Prime_p_128_p[key_size] = { 0x60E98809, 0xE1C01FE2, 0xAAF1CA8A, 0xA8B39246 };
static uint32_t Prime_q_128_q[key_size] = { 0x6321C8D9, 0x6F0DEF41, 0x8DE0E9F1, 0xDEBDD858 };
#define Prime_P Prime_p_128_p
#define Prime_Q Prime_q_128_q
#elif key_size==8
static uint32_t Prime_p_256_p[key_size] = { 0xEEFED167, 0x1A7893C6, 0x3A34603E, 0x3100C97E,
                             0xE58E4F2A, 0x0DDEC084, 0xB8228EF8, 0x8C445E5C };
static uint32_t Prime_q_256_q[key_size] = { 0x30A60457, 0x4EEC6F9C, 0x98185B64, 0x4626A746,
                             0x6192540C, 0x6964F06E, 0xDDF485D8, 0xD3A2D540 };

//static uint32_t Prime_p_256_p[key_size] = { 0xF985A751, 0xDE9C16B9, 0x62E69796, 0x1EEF7552,
//                                     0xF822A21F, 0xE53762B1, 0x05CEDA45, 0x8E6C15AD};
//static uint32_t Prime_q_256_q[key_size] = { 0xC70FE581, 0x47F5AC52, 0x1A7EAC6D, 0x2F2CC232,
//                                     0x35E53B44, 0x5BC346B0, 0xD8FF24D2, 0xFC75F982};
#define Prime_P Prime_p_256_p
#define Prime_Q Prime_q_256_q

#elif key_size==16
static uint32_t Prime_p_512_p[key_size] = {
0x33760457, 0xE3935094, 0xC0D70FED, 0x86FB3614, 0xCFDDD6FA, 0x7F1E6876, 0x6071DF95, 0x2EAD7E25, 0xF7FAEC70, 0x51219209, 0xBC72BC90, 0xD066BAB6, 0xBFFDD413, 0xE9965B14, 0xC3D790EA, 0xED7B34A9};
static uint32_t Prime_q_512_q[key_size] = {
0x9E027D79, 0x89D2FD82, 0x1B6D3B4A, 0x7643BCDE, 0x65AB5B2A, 0xE8035C5B, 0xC981A978, 0x19118E35, 0x324341DD, 0x2D940629, 0x80F98215, 0xB6EBD2A2, 0x64126437, 0x7A616471, 0x62EA0DE6, 0xF404BC3F};

#define Prime_P Prime_p_512_p
#define Prime_Q Prime_q_512_q
#endif

#define input_size               plain_size/2

//static uint32_t plain_txt[input_size]     = { 0x00000032, 0x00000033 }; // decimal: 51
static uint32_t plain_txt[input_size]     = { 0x11111111, 0x0000000, 0x22222222, 0x0000000, 0x33333333, 0x0000000, 0xf0000000, 0x0000000,
                                              0x55555555, 0x0000000, 0x66666666, 0x0000000, 0x77777777, 0x0000000, 0xf0000000, 0x0000000};

/*---------------------------------------------------------------------------*/
PROCESS(paillier_test, "paillier test");
AUTOSTART_PROCESSES(&paillier_test, &flash_erase_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(paillier_test, ev, data) {
	PROCESS_BEGIN();

  /*
   * Variable for Time Measurement
   */
  static rtimer_clock_t time;


  //Initialize the secrete structure
   static paillier_secrete_state_t state = {
       .process    = &paillier_test,
       .PSize  = key_size,
       .QSize  = key_size,
       .NLen   = plain_size, /* Public key  */
       .LLen   = plain_size, /* Private key */
       .CTLen  = cipher_size  /* Cipher-text */
     };

  /*
   * Activate Engine
   */
  printf("Initializing PKA...\n"
         "-----------------------------------------\n");
  pka_init();

  /* initialize values */
  memcpy(state.PrimeP, Prime_P,sizeof(uint32_t)*key_size);
  memcpy(state.PrimeQ, Prime_Q,sizeof(uint32_t)*key_size);
  memcpy(state.PlainText, plain_txt, sizeof(uint32_t)*input_size);
  state.PTLen = input_size;



  time = RTIMER_NOW();
  PT_SPAWN(&(paillier_test.pt), &(state.pt), paillier_gen(&state));
  time = RTIMER_NOW() - time;
  printf("paillier_gen(), %lu ms\n",
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));

  printf("Encrypt:\n");
  hexdump(state.PlainText, input_size/2);
  printf("\n");

  time = RTIMER_NOW();
  PT_SPAWN(&(paillier_test.pt), &(state.pt), paillier_enc(&state));
  time = RTIMER_NOW() - time;
  printf("paillier_enc(), %lu ms\n",
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));

  printf("ADD the same cipher!\n");
  time = RTIMER_NOW();
  PT_SPAWN(&(paillier_test.pt), &(state.pt), paillier_add(&state));
  time = RTIMER_NOW() - time;
  printf("paillier_add(), %lu ms\n",
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));


  printf("Decrypt the resulting Cipher ciphers:\n");
  memset(state.PlainText, 0, sizeof(uint32_t) * plain_size);
  state.PTLen = plain_size;

  time = RTIMER_NOW();
  PT_SPAWN(&(paillier_test.pt), &(state.pt), paillier_dec(&state));
  time = RTIMER_NOW() - time;
  printf("paillier_dec(), %lu ms\n",
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));

  /* decryption is written back to the plaintext space */
  //printf("plainlen %lu, plain %lu ==%lu, %s\n", state.PTLen, state.PlainText[0], plain_txt[0] , state.PlainText[0] == plain_txt[0] ?  "CORRECT" : "FAILED");


  hexdump(state.PlainText, input_size/2);
  printf("\n");
  printf("-----------------------------------------\n"
       "Disabling PKA...\n");
  pka_disable();

  printf("Done\n");

	PROCESS_END();
}
/*---------------------------------------------------------------------------*/
void hexdump(const uint32_t *packet, int length) {
  int n = 0;

  while (length--) {
    if (n % 16 == 0)
      printf("%08X ",n);

    printf("%08X ", *packet++);

    n++;
    if (n % 8 == 0) {
      if (n % 16 == 0)
        printf("\n");
      else
        printf("  ");
    }
  }
}
/*---------------------------------------------------------------------------*/
