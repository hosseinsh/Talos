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
 * \addtogroup c2538
 * @{
 *
 * \file
 * Implementation of the cc2538 Paillier Algorithm
 */
#include <contiki.h>
#include <process.h>

#include <limits.h>
#include <stdio.h>

#include "bignum-driver.h"
#include "pka.h"
#include "random.h"
#include "paillier-algorithm.h"

#define DEBUG 0
#if DEBUG
 #define PRINTF(...) printf(__VA_ARGS__)
#else
 #define PRINTF(...)
#endif /* DEBUG */

#if !defined(START_PAILLIER_TIMER)
#define START_PAILLIER_TIMER(index)
#endif

#if !defined(STOP_PAILLIER_TIMER)
#define STOP_PAILLIER_TIMER(index, id)
#endif

#define CHECK_RESULT(...)                                                    \
  state->result = __VA_ARGS__;                                               \
  if(state->result) {                                                        \
    PRINTF("Line: %u Error: %u\n", __LINE__, (unsigned int) state->result);  \
    PT_EXIT(&state->pt);                                                     \
  }

  /* Variables: Rand, Square */
  static uint32_t  S[cipher_size];           /* Square */
  static uint32_t  SSize = cipher_size;      /* size of Square */
  static uint32_t  G[cipher_size];           /* G */
  static uint32_t  GSize = cipher_size;      /* size of G */
  static uint32_t  Rand[cipher_size];        /* Random number R */
  static uint32_t  RSize = cipher_size;      /* size of R */


PT_THREAD(paillier_gen(paillier_secrete_state_t *state)) {
  PT_BEGIN(&state->pt);
  /* TODO: Generate primes p and q with equivalent length */

  /* Compute n= p*q */
  CHECK_RESULT(PKABigNumMultiplyStart(state->PrimeQ, state->QSize, state->PrimeP, state->PSize, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumMultGetResult(state->PublicN, &state->NLen,state->rv));

  /* S=1 (tmp use of S) */
  memset(S, 0, sizeof(uint32_t) * state->PSize);
  S[0] = 1;  /* represent one */

  /* p-1 */
  CHECK_RESULT(PKABigNumSubtractStart(state->PrimeP, state->PSize, S, state->PSize, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumSubtractGetResult(state->PrimeP, &state->PSize, state->rv));

  /* q-1 */
  CHECK_RESULT(PKABigNumSubtractStart(state->PrimeQ, state->QSize, S, state->QSize, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumSubtractGetResult(state->PrimeQ, &state->QSize, state->rv));

  /* L = (q-1)*(p-1), coz we use |q| = |p|*/
  CHECK_RESULT(PKABigNumMultiplyStart(state->PrimeQ,state->QSize,state->PrimeP,state->PSize,&state->rv,state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumMultGetResult(state->PrviateL,&state->LLen,state->rv));


  PT_END(&state->pt);
}

PT_THREAD(paillier_enc(paillier_secrete_state_t *state)) {
  PT_BEGIN(&state->pt);

  int i;
  /*  m (message) is represented as a padded element of Z_n. */

  /* Generate R in Z_n^*. */
  RSize = state->NLen;
  for (i = 0; i < RSize; ++i) {
     Rand[i] = (uint32_t)random_rand() | (uint32_t)random_rand() << 16;
  }

  /* r =  r mod n*/
  CHECK_RESULT(PKABigNumModStart(Rand, (uint8_t)RSize, state->PublicN, (uint8_t) state->NLen, &state->rv,state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumModGetResult(Rand, RSize, state->rv));
  PRINTF("%d: %lu\n", __LINE__, RSize);

  /* Compute c = (g^m)(r^n) mod n^2. */
  /* s=1 (tmp use of s) */
  memset(S, 0, sizeof(uint32_t) * plain_size);
  S[0] = 1;  /* represent one */

  /* g = n + 1 */
  CHECK_RESULT(PKABigNumAddStart(state->PublicN, (uint8_t) state->NLen, S, (uint8_t) state->NLen, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumAddGetResult(G, &GSize, state->rv));
  PRINTF("%d: %lu\n", __LINE__, GSize);

  /* s =  n^2 == n * n*/
  CHECK_RESULT(PKABigNumMultiplyStart(state->PublicN, (uint8_t) state->NLen, state->PublicN, (uint8_t) state->NLen, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumMultGetResult(S, &SSize, state->rv));
  PRINTF("%d: %lu\n", __LINE__, SSize);

  GSize = cipher_size;   /* g should be as large as S*/
  /* c = g^m mod s   */
  CHECK_RESULT(PKABigNumExpModStart(state->PlainText, (uint8_t) state->PTLen, S, (uint8_t)SSize, G, (uint8_t) GSize, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumExpModGetResult(state->CipherText, state->CTLen, state->rv));
  PRINTF("%d: %lu\n", __LINE__, state->CTLen);

  RSize=cipher_size; /*increase the size to cipher size, so that |S|==|Rand| */
  /* R = R^n mod s   */
  CHECK_RESULT(PKABigNumExpModStart(state->PublicN, (uint8_t) state->NLen, S, SSize, Rand, (uint8_t) RSize, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumExpModGetResult(Rand, RSize, state->rv));
  PRINTF("%d: %lu\n", __LINE__, RSize);

  /* c = c * R */
  CHECK_RESULT(PKABigNumMultiplyStart(state->CipherText, (uint8_t) state->CTLen, Rand, (uint8_t)RSize, &state->rv,state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  state->CTLen=cipher_size*2; /* *2: additional space to hold the result */
  CHECK_RESULT(PKABigNumMultGetResult(state->CipherText, &state->CTLen, state->rv));
  PRINTF("%d: %lu\n", __LINE__, state->CTLen);

  /* c = c mod s */
  CHECK_RESULT(PKABigNumModStart(state->CipherText, (uint8_t) state->CTLen, S, (uint8_t) SSize, &state->rv,state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumModGetResult(state->CipherText, state->CTLen, state->rv));
  state->CTLen = cipher_size;
  PRINTF("%d: %lu\n", __LINE__, state->CTLen);

  PT_END(&state->pt);
}


PT_THREAD(paillier_dec(paillier_secrete_state_t *state)) {
  PT_BEGIN(&state->pt);

  /* Compute L(c^l mod n^2) * u mod n, where L(x) = (x-1)/L, and u = L(g^l mod n^2)^-1 */
  /* Since we use |q| = |p| => g = n + 1 and u = L^-1 mod n */
  /* s =  n^2 == n * n*/
  SSize = cipher_size;
  CHECK_RESULT(PKABigNumMultiplyStart(state->PublicN,state->NLen,state->PublicN,state->NLen,&state->rv,state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumMultGetResult(S, &SSize, state->rv));
  PRINTF("%d: %lu\n", __LINE__, SSize);

  /* c = c^l mod s INFO: state->CipherText has a length of 2*cipher_size, however in ExpMod |Base|=|Mode| */
  CHECK_RESULT(PKABigNumExpModStart(state->PrviateL, state->LLen, S, SSize, state->CipherText, cipher_size, &state->rv,state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumExpModGetResult(state->CipherText, state->CTLen, state->rv));
  PRINTF("%d: %lu\n", __LINE__, state->CTLen);
  //state->CTLen = SSize;

  /* g=1  using G temp for representation of 1 */
  memset(G, 0, sizeof(uint32_t) * cipher_size);
  G[0] = 1;

  /*c = c - 1 */
  CHECK_RESULT(PKABigNumSubtractStart(state->CipherText,  cipher_size, G, cipher_size, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumSubtractGetResult(state->CipherText, &state->CTLen, state->rv));
  PRINTF("%d: %lu\n", __LINE__, state->CTLen);

  /*c = c / n */
  CHECK_RESULT(PKABigNumDivideStart(state->CipherText, state->CTLen, state->PublicN, state->NLen, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumDivideGetResult(state->CipherText, &state->CTLen, state->rv));
  PRINTF("%d: %lu\n", __LINE__, state->CTLen);

  /* u = l^-1 mod n*/
  CHECK_RESULT(PKABigNumInvModStart(state->PrviateL, state->LLen, state->PublicN, state->NLen, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  /* U will be tmp stored in plaintext, the size will be always <= plain_size; */
  CHECK_RESULT(PKABigNumInvModGetResult(state->PlainText, state->PTLen, state->rv));
  PRINTF("%d: %lu\n", __LINE__, state->PTLen);

  /* c = c * u */
  CHECK_RESULT(PKABigNumMultiplyStart(state->CipherText, state->CTLen, state->PlainText, state->PTLen, &state->rv,state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  state->CTLen=cipher_size*2; /* *2: additional space to hold the result*/
  CHECK_RESULT(PKABigNumMultGetResult(state->CipherText, &state->CTLen, state->rv));
  PRINTF("%d: %lu\n", __LINE__, state->CTLen);

  /* m = c mod n */
  CHECK_RESULT(PKABigNumModStart(state->CipherText, state->CTLen, state->PublicN, state->NLen, &state->rv,state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumModGetResult(state->PlainText, state->PTLen, state->rv));
  PRINTF("%d: %lu\n", __LINE__, state->PTLen);

  PT_END(&state->pt);
}


PT_THREAD(paillier_add(paillier_secrete_state_t *state)) {
  PT_BEGIN(&state->pt);

  /* plain + plain mod n = cipher * cipher mod s */
  /* s =  n^2 == n * n*/
  CHECK_RESULT(PKABigNumMultiplyStart(state->PublicN, (uint8_t) state->NLen, state->PublicN, (uint8_t) state->NLen, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumMultGetResult(S, &SSize, state->rv));
  PRINTF("%d: %lu\n", __LINE__, SSize);

  /* cipher * cipher  */
  CHECK_RESULT(PKABigNumMultiplyStart(state->CipherText, cipher_size, state->CipherText, cipher_size, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  state->CTLen=cipher_size*2; /* *2: additional space to hold the result*/
  CHECK_RESULT(PKABigNumMultGetResult(state->CipherText, &state->CTLen, state->rv));
  PRINTF("%d: %lu\n", __LINE__, state->CTLen);

  /* cipher * cipher mod s */
  CHECK_RESULT(PKABigNumModStart(state->CipherText, (uint8_t) state->CTLen, S, (uint8_t) SSize, &state->rv,state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumModGetResult(state->CipherText, state->CTLen, state->rv));
  state->CTLen = cipher_size;
  PRINTF("%d: %lu\n", __LINE__, state->CTLen);

  PT_END(&state->pt);
}
