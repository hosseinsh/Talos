/*
 * Original file: https://github.com/burrows-labs/cryptdb/blob/public/crypto/online_ope.cc
 *
 * Copyright (c) 2014, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Port to Contiki:
 *       Hossein Shafagh <shafagh@inf.ethz.ch>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * \addtogroup cc2538-mOPE OPE
 * @{
 *
 * \file
 * Implementation of the cc2538 mutable Order Preserving Encryption (OPE) driver
 */
#include "contiki.h"
#include "dev/crypto.h"
#include "dev/aes.h"
#include "dev/nvic.h"
#include "mope.h"
#include "reg.h"
#include <uip-ds6.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if (CIPHER_BLOCK==BLOWFISH_CIPHER_BLOCK)
#include "blowfish.h"
#endif /*CIPHER_BLOCK*/


//Initialization Vector Out
static uint8_t iv_inout[16];

void hexdump(const uint32_t *packet, int length) {
  int n = 0;

  while (length--) {
    if (n % 16 == 0)
      printf("%02X: ",n);

    printf("%08lX ", *packet++);

    n++;
    if (n % 8 == 0) {
      if (n % 16 == 0)
        printf("\n");
      else
        printf("  ");
    }
  }
}

int aes_operation(uint8_t *pui8MsgIn, uint8_t *pui8MsgOut, uint8_t ui8KeyLocation,
                     uint8_t ui8Encrypt, uint32_t len){

    memset(iv_inout, 0, sizeof(iv_inout));
    //printf("AES-%s len %lu\n", ui8Encrypt == AES_ENC ? "ENC" : "DEC", len);
    if(aes(pui8MsgOut, iv_inout, pui8MsgOut, ui8KeyLocation, ui8Encrypt, AES_ECB, len)) {
      return 0;
    }

    if(aes_start(pui8MsgIn, iv_inout, pui8MsgOut, ui8KeyLocation, ui8Encrypt, AES_ECB, len, PROCESS_CURRENT())) {
      return 0;
    }

    while(!aes_check_status()) {
      asm("nop");
    }

    if(aes_get_result(iv_inout)) {
      return 0;
    }

    return 1;
}


uint8_t mope_handle_interaction(struct mope_context_t* ctx, uint8_t* msg, uint16_t len){
   uint8_t stop_flag = 0;
   uint8_t index, ret;
   uint8_t* pkt = ctx->readbuf;
   uint32_t low, high;
   uint16_t len_msg;

   if (len < sizeof(packet_insert_t))
     return 0;

   //printf("Received inquiry from server\n");

   packet_insert_t* request = (packet_insert_t*) msg;
   len_msg = UIP_HTONS(request->len);
   uint8_t elements = (len_msg - sizeof(packet_insert_t))/CIPHER_LEN_BYTE; // deduce 3 bytes for header: len and type
   uint8_t* node_elements = msg + sizeof(packet_insert_t);

   switch(request->type) {
    case INTERACT_FOR_LOOKUP_S: {
       /* iterate through the elements of the node and stop if
        * to_be_inserted_value smaller or equal the key,
        * remember if there was an equal value*/

       for(index=1; index < elements; index++) {
          #if (CIPHER_BLOCK==BLOWFISH_CIPHER_BLOCK)
          low  =  *(uint32_t*)(node_elements + CIPHER_LEN_BYTE*index);
          high =  *(uint32_t*)(node_elements + CIPHER_LEN_BYTE*index + 4);
          blowfish_cipher(ctx->container, &high, &low, BLOWFISH_DECRYPT);
          high = UIP_HTONL(high);
          low  = UIP_HTONL(low);
          #elif (CIPHER_BLOCK==ECB_CIPHER_BLOCK)
            aes_operation((uint8_t *) &tmp_value, node_elements + CIPHER_LEN_BYTE*index , ctx->ui8KeyLocation, AES_DEC, CIPHER_LEN_BYTE);
          #endif /*CIPHER_BLOCK*/
          stop_flag  =  (ctx->to_be_inserted_value==high);
          if (high >= ctx->to_be_inserted_value){
              break;
          }
       }
       len_msg = sizeof(packet_response_t);
       pkt[0] = UIP_HTONS(len_msg);             // uint16_t
       pkt[2] = INTERACT_FOR_LOOKUP_C;          // uint8_t
       pkt[3] = index-1;                        // uint8_t
       pkt[4] = stop_flag;                      // uint8_t
       ret = ctx->h->write(ctx, ctx->h->session, ctx->readbuf, len_msg);
       break;
    }
    case OPE_ENCODING:{
       /* we got the final encoding */
       memcpy(ctx->mope_encoding, node_elements, sizeof(ctx->mope_encoding));
       //printf("mOPE insert succeeded.\n");
       ret = 0;
       break;
    }
    default:
      ret = -1;
   }

   return ret <= 0 ? 0 : len_msg;;
}


uint8_t mope_client_encrypt(struct mope_context_t* ctx, uint32_t ptext) {
    uint8_t ret;
    uint16_t len_msg = 0;
    uint8_t* pkt = ctx->readbuf;
    memset(pkt, 0, sizeof(ctx->readbuf));
    ctx->to_be_inserted_value = ptext;

    //printf("Initiating mOPE encrypt and insert %x\n", (unsigned int) ptext);

#if (CIPHER_BLOCK==BLOWFISH_CIPHER_BLOCK)
    uint32_t low  = UIP_HTONL(0);
    uint32_t high = UIP_HTONL(ptext); /* we assume 32bit values!*/
    blowfish_cipher(ctx->container, &high, &low, BLOWFISH_ENCRYPT);
    ctx->to_be_inserted_cipher[0] = low;
    ctx->to_be_inserted_cipher[1] = high;
#elif (CIPHER_BLOCK==ECB_CIPHER_BLOCK)
    /* DET encryption for short blocks: ECM */
    ret = aes_operation((uint8_t*)&ptext, (uint8_t*) ctx->to_be_inserted_cipher, ctx->ui8KeyLocation, AES_ENC, (uint32_t) sizeof(uint32_t));
#endif /*CIPHER_BLOCK*/

    //printf("Cipher           ");
    //hexdump(ctx->to_be_inserted_cipher, CIPHER_LEN_WORD);
    //printf("\n");

    /*FIXME: our system is little endian, we should transmit in big endian! */
    /* send insert request to the mOPE server
     * Format: "MsgType TableName DET " FIXME: no TableName for now!*/
    len_msg = sizeof(packet_insert_t) + CIPHER_LEN_BYTE; // in bytes
    pkt[0] = len_msg;                                  // uint16_t
    pkt[2] = ENC_INS;                           // uint8_t

    memcpy(&pkt[3], (uint8_t*) ctx->to_be_inserted_cipher, CIPHER_LEN_BYTE);

    //printf("Message (len %u) ", len_msg);
    //hexdump((uint32_t*)ctx->readbuf, len_msg/4 + 1);
    //printf("\n");
    ret = ctx->h->write(ctx, ctx->h->session, ctx->readbuf, len_msg);

    //printf("Send first message (wait for server) \n");

    /* Guess number of bytes sent:
     * len_msg is the number of bytes to be send,
     * ret will contain the bytes actually sent. */
    return ret <= 0 ? 0 : len_msg;
}

/** @} */
