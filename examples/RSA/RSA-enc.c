/**
 * \file
 *         A RSA algorithm Contiki application showing how using the RSA in contiki
 *
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
PROCESS(rsa_test_process, "RSA Test process");
AUTOSTART_PROCESSES(&rsa_test_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rsa_test_process, ev, data)
{
  PROCESS_BEGIN();

  int8_t kk;
  //static rtimer_clock_t time;

  puts("-----------------------------------------\n"
        "Initializing pka...");
   pka_init();

 //Initialize the secrete structure
  static RSA_secrete_state_t state = {
      .process    = &rsa_test_process,
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

    //time = RTIMER_NOW();
    PT_SPAWN(&(rsa_test_process.pt), &(state.pt), RAS_create_public(&state));

    //time = RTIMER_NOW() - time;


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


    printf("the another public key is e%X \n",(unsigned int) state.PrimeE);

   PT_SPAWN(&(rsa_test_process.pt), &(state.pt), RAS_create_private(&state));
   //uint32_t temp;

       for(kk = 15; kk >=0; kk--)
       {

    	   printf("%X ",(unsigned int) state.PrviateD[kk]);

       }

       printf("\n");
       printf("the private key created\n");

//the data structure for sending
       static RSA_public_state_t public_state = {
                    .process    = &rsa_test_process,

            };


       memcpy(&public_state.PrimeE,&state.PrimeE,sizeof(uint32_t)*1);//copy one of public key---e
       memcpy(&public_state.ESize, &state.ESize ,sizeof(uint8_t)*1);//copy one of public key e size
       memcpy(public_state.PublicN, state.PublicN,sizeof(uint32_t)*16);//copy one of another public key--n
       memcpy(&public_state.NLen, &state.NLen,sizeof(uint32_t)*1);//copy one of another public key-n size

  //step3:encrypt the message
  //-----------------------------------------------------------------------------
    //the clear message
    static uint32_t mymesssage[16] = {0xFFFF1111, 0x00000000, 0x00000000, 0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
                                      0x00000000, 0x00000000, 0x00000000, 0x00000000,0x00000000,0x00000000,0xFFFF1111,0x00000001};

    memcpy(state.Messagetoencrypt, mymesssage,sizeof(uint32_t)*16);
    state.MLen = 16;
    state.SMLen = 16;
    PT_SPAWN(&(rsa_test_process.pt), &(state.pt), RAS_encrypt_message(&state));

     for(kk = 15; kk >=0; kk--)
            {

            printf("%X ",(unsigned int) state.secretMessage[kk]);

            }
     printf("\n");
     memcpy(public_state.secretMessage, state.secretMessage,sizeof(uint32_t)*16);//copy to send data structure

//step4: decrypt the message
//-----------------------------------------------------------------------------

    //memcpy(&state.Messagetoencrypt, &mymesssage,sizeof(uint32_t)*1);
    //state.MLen = 1;
    PT_SPAWN(&(rsa_test_process.pt), &(state.pt), RAS_decrypt_message(&state));

          for(kk = 15; kk >=0; kk--)
             {
                     	   //memcpy(temp, state.PublicN+sizeof(uint32_t)*kk,sizeof(uint32_t));
              printf("%X ",(unsigned int) state.Messagetoencrypt[kk]);

             }


  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
