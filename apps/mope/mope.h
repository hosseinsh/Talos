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
 * \addtogroup cc2538-crypto
 * @{
 *
 * \defgroup cc2538-mOPE cc2538 OPE
 *
 * Driver for mutable Order Preserving Encryption (OPE)
 * @{
 *
 * \file
 * Header file for the cc2538 mutable Order Preserving Encryption (OPE) driver
 */
#ifndef MOPE_H_
#define MOPE_H_

#include "contiki.h"
#include "dev/crypto.h"

#include <stdbool.h>
#include <stdint.h>
#include <uip-ds6.h>

enum MsgType {
    ENC_INS               =  0,
    QUERY,
    INTERACT_FOR_LOOKUP_C, /* Client Response */
    INTERACT_FOR_LOOKUP_S, /* Server Request */
    OPE_ENCODING,  /*OPE ENCCODING in tree*/
    CLOSE /* Close connection*/
};

#if (CIPHER_BLOCK==BLOWFISH_CIPHER_BLOCK)
#include "blowfish.h"
  #define CIPHER_LEN_BYTE    8
#elif (CIPHER_BLOCK==ECB_CIPHER_BLOCK)
  #define CIPHER_LEN_BYTE    16
#endif /*CIPHER_BLOCK*/

#define CIPHER_LEN_WORD     CIPHER_LEN_BYTE/4  /* ECB 16Byte/32bit */
#define AES_ENC             1
#define AES_DEC             0

#define ENCODING_LEN        8



typedef struct {
  unsigned char    size;
  uip_ipaddr_t     addr;
  unsigned short   port;
  int              ifindex;
} session_t;

struct mope_context_t;
/**
 * This structure contains callback functions used by mOPE to
 * communicate with the application. At least the write function must
 * be provided. It is called by the mOPE state machine to send request packets
 * over the network.
 */
typedef struct {
  /**
   * Called from dtls_handle_message() to send DTLS packets over the
   * network. The callback function must use the network interface
   * denoted by session->ifindex to send the data.
   *
   * @param ctx  The current DTLS context.
   * @param session The session object, including the address of the
   *              remote peer where the data shall be sent.
   * @param buf  The data to send.
   * @param len  The actual length of @p buf.
   * @return The callback function must return the number of bytes
   *         that were sent, or a value less than zero to indicate an
   *         error.
   */
  int (*write)(struct mope_context_t *ctx,
          session_t *session, uint8_t
		  *buf, uint16_t len);
  session_t* session;
} mope_handler_t;

/** Holds global information of the mOPE. */
typedef struct mope_context_t{
#if (CIPHER_BLOCK==BLOWFISH_CIPHER_BLOCK)
  blowfish_t       *container;
#endif /*CIPHER_BLOCK*/
  mope_handler_t   *h;                                /* callback handlers */
  unsigned char    readbuf[UIP_CONF_BUFFER_SIZE];
  /* new element to be inserted in the mOPE tree*/
  uint32_t         to_be_inserted_cipher[CIPHER_LEN_WORD];
  uint32_t         to_be_inserted_value;
  uint8_t          mope_encoding[ENCODING_LEN];
  uint8_t          ui8KeyLocation;                   /*AES key in the storage*/
} mope_context_t;



/* Structure of the Packets for Client response */
typedef struct __attribute__((__packed__)) {
 uint16_t       len;
 uint8_t        type;
 uint8_t        index;
 uint8_t        stop_flg;
} packet_response_t;

/* Structure of the Packets for Client response */
typedef struct __attribute__((__packed__)) {
 uint16_t       len;
 uint8_t        type;
 /*payload cipher!*/
} packet_insert_t;

/*---------------------------------------------------------------------------*/
/** \name mOPE functions on the client side
 * @{
 */

/** \brief Performs an mOPE encryption, consisting of DET encryption and sending the frist
 * request to mOPE server. After several interactions with the server, the server constructs
 * the order encoding.
 *
 * \param ctx   A pointer the mope context
 * \param ptext A pointer to plaintext
 * \param len_p The length of plaintext
 * \return \c successful transmitted bytes
 */
uint8_t mope_client_encrypt(struct mope_context_t* ctx, uint32_t ptext);

/** \brief handles interaction with the server so that the encoding is constructed at the server
 *
 * \param ctx   A pointer the mope context
 * \param msg   A pointer to the received msg from server
 * \param len   The length of the message
 * \return \c successful transmitted bytes
 */
uint8_t mope_handle_interaction(struct mope_context_t* ctx, uint8_t* msg, uint16_t len);
#endif /* MOPE_H_ */

/**
 * @}
 * @}
 */
