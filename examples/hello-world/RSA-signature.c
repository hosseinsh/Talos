/*
 * Copyright (c) 2006, Swedish Institute of Computer Science.
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
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
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         A RSA algorithm Contiki application showing how using the RSA in contiki
 *
 * (1)what is RSA
 * RSA is a kind of encryption algorithm. RSA algorithm steps is
 * a.  choose random 2 big prime number p,q
 * b.  compute n=p*q and f=(p-1)*(q-1)
 * c.  Select a random integer e, with 1 < e < f and gcd(e,f) ≡ 1.
 * d.  Calculate d, such that (e•d) mod f ≡ 1 or d=e^(-1) mod f
 * e.  we call the pair (n,e) as the public key and the pair (n,d) as private key
 * f.  m is the actual message and M is the encryption message. use M = m^e mod n to encrypt m
 * g.  use m=M^d mod n to decrypt the M and get the actual message.
 * (2)this example check the procedure of encryption
 * a.  the child thread RSA_create_public create public key (n,e)
 * b.  the child thread RSA_create_private create private key (n,d)
 * c.  the child thread RSA_encrypt_message encrypt the message
 * d.  the child thread RSA_decrypt_message decrypt the message
 * (3) support file to run this example
 * a.  (/cpu/cc2538/dev/)ecc-driver.h ,ecc-driver.c which include the driver for RSA basic operation such as big
 * number add,subtract,multiply,modInv,Expmod operation
 * b.  (/cpu/cc2538/dev/)RSA-algorithm.h,RSA-algorithm.c which include the RSA algorithm functions and data structure
 * \author
 *         hu luo  <huluo45@163.com>
 */

#include "contiki.h"
#include "RSA-algorithm.h"

#include "rtimer.h"
#include "pt.h"

//#include <string.h>

#include <stdio.h> /* For printf() */


//big prime number 256
static uint32_t Prime_p_256_p[8] = { 0xEEFED167, 0x1A7893C6, 0x3A34603E, 0x3100C97E,
		                             0xE58E4F2A, 0x0DDEC084, 0xB8228EF8, 0x8C445E5C };
static uint32_t Prime_q_256_q[8] = { 0x30A60457, 0x4EEC6F9C, 0x98185B64, 0x4626A746,
		                             0x6192540C, 0x6964F06E, 0xDDF485D8, 0xD3A2D540 };
static uint32_t Prime_e_256_e    =   0x00010001;
static uint32_t ONE_256_one[8]   = { 0x00000001, 0x00000000, 0x00000000, 0x00000000,
                                     0x00000000, 0x00000000, 0x00000000, 0x00000000 };


/*---------------------------------------------------------------------------*/
PROCESS(RSA_signature_process, "RSA signature process");
AUTOSTART_PROCESSES(&RSA_signature_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(RSA_signature_process, ev, data)
{
  PROCESS_BEGIN();

  int8_t kk;
  static rtimer_clock_t time;

  puts("-----------------------------------------\n"
        "Initializing pka...");
   pka_init();

 //Initialize the secrete structure
  static RSA_secrete_state_t state = {
      .process    = &RSA_signature_process,
      .PSize  = 8,
	  .QSize  = 8,
	  .ESize =1,
	  .NLen =16,
	  .FLen =16,
	  .DLen =16,
    };

    memcpy(state.PrimeP, Prime_p_256_p,sizeof(uint32_t)*8);//copy the prime P
    memcpy(state.PrimeQ, Prime_q_256_q,sizeof(uint32_t)*8);//copy the prime Q
    memcpy(state.ONEDATA, ONE_256_one ,sizeof(uint32_t)*8);//copy the one
    memcpy(&state.PrimeE,&Prime_e_256_e,sizeof(uint32_t)*1);//copy one of public key---e
    //step1:create the public key
      //--------------------------------------------------------------------------------

    time = RTIMER_NOW();
    PT_SPAWN(&(RSA_signature_process.pt), &(state.pt), RSA_create_public(&state));

    time = RTIMER_NOW() - time;

    printf("using time is %d\n",time);

    for(kk = 15; kk >=0; kk--)
    {
        printf("%X ",(unsigned int) state.PublicN[kk]);

    }
    printf("\n");

    for(kk = 15; kk >=0; kk--)
        {
            printf("%X ",(unsigned int) state.PrimeF[kk]);

        }
    printf("\n");

    printf("the public key created\n");
    //step2:create the private key
    //--------------------------------------------------------------------------------


    printf("the another public key is e= %X \n",(unsigned int) state.PrimeE);

   PT_SPAWN(&(RSA_signature_process.pt), &(state.pt), RSA_create_private(&state));
   //uint32_t temp;

       for(kk = 15; kk >=0; kk--)
       {

    	   printf("%X ",(unsigned int) state.PrviateD[kk]);

       }

       printf("\n");
       printf("the private key created\n");

//the data structure for sending
       static RSA_public_state_t public_state = {
                    .process    = &RSA_signature_process,

            };


       memcpy(&public_state.PrimeE,&state.PrimeE,sizeof(uint32_t)*1);//copy one of public key---e
       memcpy(&public_state.ESize, &state.ESize ,sizeof(uint8_t)*1);//copy one of public key e size
       memcpy(public_state.PublicN, state.PublicN,sizeof(uint32_t)*16);//copy one of another public key--n
       memcpy(&public_state.NLen, &state.NLen,sizeof(uint32_t)*1);//copy one of another public key-n size

  //step3:signature the message
  //-----------------------------------------------------------------------------
    //the plaintext message
    static uint32_t mymesssage[16] = {0xFFFF1111, 0x00000000, 0x00000000, 0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
                                      0x00000000, 0x00000000, 0x00000000, 0x00000000,0x00000000,0x00000000,0xFFFF1111,0x00000001};

    memcpy(state.Messagetoencrypt, mymesssage,sizeof(uint32_t)*16);
    state.MLen = 16;
    state.SMLen = 16;
    PT_SPAWN(&(RSA_signature_process.pt), &(state.pt), RSA_signature_message(&state));

     for(kk = 15; kk >=0; kk--)
            {

            printf("%X ",(unsigned int) state.secretMessage[kk]);

            }
     printf("\n");
     memcpy(public_state.secretMessage, state.secretMessage,sizeof(uint32_t)*16);//copy to send data structure

//step4: RSA signature verification
//-----------------------------------------------------------------------------

    //memcpy(&state.Messagetoencrypt, &mymesssage,sizeof(uint32_t)*1);
    //state.MLen = 1;
    PT_SPAWN(&(RSA_signature_process.pt), &(state.pt), RSA_signature_verification(&state));

          for(kk = 15; kk >=0; kk--)
             {
                     	   //memcpy(temp, state.PublicN+sizeof(uint32_t)*kk,sizeof(uint32_t));
              printf("%X ",(unsigned int) state.Messagetoencrypt[kk]);

             }


  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
