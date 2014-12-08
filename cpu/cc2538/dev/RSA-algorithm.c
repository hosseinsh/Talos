/*
 * Copyright (c) 2014 hu luo <huluo45@163.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
/**
 * \addtogroup c2538-RSA-algo
 * @{
 *
 * \file
 * Implementation of the cc2538 RSA Algorithms
 */
#include <contiki.h>
#include <process.h>

#include <limits.h>
#include <stdio.h>

#include "RSA-algorithm.h"
#include "ecc-driver.h"
#include "pka.h"

#define CHECK_RESULT(...)                                                    \
  state->result = __VA_ARGS__;                                               \
  if(state->result) {                                                        \
    printf("Line: %u Error: %u\n", __LINE__, (unsigned int) state->result);  \
    PT_EXIT(&state->pt);                                                     \
  }


PT_THREAD(RAS_create_public(RSA_secrete_state_t *state)) {
  PT_BEGIN(&state->pt);
 //n=p*q
  CHECK_RESULT(PKABigNumMultiplyStart(state->PrimeQ,state->QSize,state->PrimeP,state->PSize,&state->rv,state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  //printf("end of public key\n");
  CHECK_RESULT(PKABigNumMultGetResult(state->PublicN,&state->NLen,state->rv));
 //p-1
  CHECK_RESULT(PKABigNumSubtractStart(state->PrimeP, state->PSize, state->ONEDATA, state->PSize, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumSubtractGetResult(state->PrimeP, &state->PSize, state->rv));
  //Q-1
  CHECK_RESULT(PKABigNumSubtractStart(state->PrimeQ, state->QSize, state->ONEDATA, state->QSize, &state->rv, state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  CHECK_RESULT(PKABigNumSubtractGetResult(state->PrimeQ, &state->QSize, state->rv));
// (q-1)*(p-1)
  CHECK_RESULT(PKABigNumMultiplyStart(state->PrimeQ,state->QSize,state->PrimeP,state->PSize,&state->rv,state->process));
  PT_WAIT_UNTIL(&state->pt, pka_check_status());
  //printf("end of pre-private key\n");
  CHECK_RESULT(PKABigNumMultGetResult(state->PrimeF,&state->FLen,state->rv));
  printf("get the F\n");
  PT_END(&state->pt);
}


PT_THREAD(RAS_create_private(RSA_secrete_state_t *state)){
	PT_BEGIN(&state->pt);

	uint32_t result_temp;
	uint32_t result_store[17];
	uint32_t size=17;


//d=(1+((p-1)*(q-1)*(e-ModInv((q-1)*(p-1),e)))/e
	CHECK_RESULT(PKABigNumInvModStart(state->PrimeF, state->FLen, &state->PrimeE, state->ESize,&state->rv, state->process));
	PT_WAIT_UNTIL(&state->pt, pka_check_status());
	CHECK_RESULT(PKABigNumInvModGetResult(&result_temp, state->ESize, state->rv));
//
	CHECK_RESULT(PKABigNumSubtractStart(&state->PrimeE, state->ESize, &result_temp, state->ESize, &state->rv, state->process));
	PT_WAIT_UNTIL(&state->pt, pka_check_status());
	CHECK_RESULT(PKABigNumSubtractGetResult(&result_temp, &state->ESize, state->rv));
//
	CHECK_RESULT(PKABigNumMultiplyStart(state->PrimeF,state->FLen,&result_temp,state->ESize,&state->rv,state->process));
	PT_WAIT_UNTIL(&state->pt, pka_check_status());
	CHECK_RESULT(PKABigNumMultGetResult(result_store,&size,state->rv));
//
	CHECK_RESULT(PKABigNumAddStart(state->ONEDATA, 1, result_store, size, &state->rv, state->process));
	PT_WAIT_UNTIL(&state->pt, pka_check_status());
	CHECK_RESULT(PKABigNumAddGetResult(result_store, &size, state->rv));
//
	CHECK_RESULT(PKABigNumDivideStart(result_store, size, &state->PrimeE, state->ESize, &state->rv, state->process));
	PT_WAIT_UNTIL(&state->pt, pka_check_status());
	CHECK_RESULT(PKABigNumDivideGetResult(state->PrviateD, &state->DLen, state->rv));

	PT_END(&state->pt);
}


PT_THREAD(RAS_encrypt_message(RSA_secrete_state_t *state)){
	PT_BEGIN(&state->pt);
	static uint32_t mymesssage[16] = {0xFFFF1111, 0xFFFF1111, 0x00000000, 0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	                                      0x00000000, 0x00000000, 0x00000000, 0x00000000,0x00000000,0x00000000,0xFFFF1111,0x00000001};

	CHECK_RESULT(PKABigNumExpModStart(&state->PrimeE, state->ESize, state->PublicN, state->NLen,mymesssage,state->MLen,&state->rv, state->process));
	PT_WAIT_UNTIL(&state->pt, pka_check_status());
	CHECK_RESULT(PKABigNumExpModGetResult(state->secretMessage,state->SMLen, state->rv));

	PT_END(&state->pt);
}


PT_THREAD(RAS_decrypt_message(RSA_secrete_state_t *state)){
	PT_BEGIN(&state->pt);

	CHECK_RESULT(PKABigNumExpModStart(state->PrviateD, state->DLen, state->PublicN, state->NLen,state->secretMessage,state->SMLen,&state->rv, state->process));
	PT_WAIT_UNTIL(&state->pt, pka_check_status());
	CHECK_RESULT(PKABigNumExpModGetResult(state->Messagetoencrypt,state->MLen, state->rv));

	PT_END(&state->pt);
};

/**
 * @}
 * @}
 */
