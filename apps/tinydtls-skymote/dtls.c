/* dtls -- a very basic DTLS implementation
 *
 * Copyright (C) 2011--2012 Olaf Bergmann <bergmann@tzi.org>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#define clock_time() (time(NULL))
#endif
#ifndef WITH_CONTIKI
#include <stdlib.h>
#include "uthash.h"
#else /* WITH_CONTIKI */
# ifndef NDEBUG
#   define DEBUG DEBUG_PRINT
#   include "net/uip-debug.h"
#  endif /* NDEBUG */
#endif /* WITH_CONTIKI */

#include "debug.h"
#include "numeric.h"
#include "netq.h"
#include "dtls.h"
#include "crypto.h"
#if WITH_PKI
#include "cert-parser.h"
#include "watchdog.h"
/* Signature values (r,s) */
static bn_t sig_r;
static bn_t sig_s;
#endif /* WITH_PKI */

#ifdef WITH_SHA256
#  include "sha2/sha2.h"
#endif

#define dtls_set_version(H,V) dtls_int_to_uint16(&(H)->version, (V))
#define dtls_set_content_type(H,V) ((H)->content_type = (V) & 0xff)
#define dtls_set_length(H,V)  ((H)->length = (V))

#define dtls_get_content_type(H) ((H)->content_type & 0xff)
#define dtls_get_version(H) dtls_uint16_to_int(&(H)->version)
#define dtls_get_epoch(H) dtls_uint16_to_int(&(H)->epoch)
#define dtls_get_sequence_number(H) dtls_uint48_to_ulong(&(H)->sequence_number)
#define dtls_get_fragment_length(H) dtls_uint24_to_int(&(H)->fragment_length)

#ifndef WITH_CONTIKI
#define HASH_FIND_PEER(head,sess,out)		\
  HASH_FIND(hh,head,sess,sizeof(session_t),out)
#define HASH_ADD_PEER(head,sess,add)		\
  HASH_ADD(hh,head,sess,sizeof(session_t),add)
#define HASH_DEL_PEER(head,delptr)		\
  HASH_DELETE(hh,head,delptr)
#endif /* WITH_CONTIKI */

#define DTLS_RH_LENGTH sizeof(dtls_record_header_t)
#define DTLS_HS_LENGTH sizeof(dtls_handshake_header_t)
#define DTLS_CH_LENGTH sizeof(dtls_client_hello_t) /* no variable length fields! */
#define DTLS_HV_LENGTH sizeof(dtls_hello_verify_t)
#define DTLS_KE_LENGTH sizeof(dtls_key_exchange_t)
#define DTLS_CR_LENGTH sizeof(dtls_certificate_request_t)
#define DTLS_ST_LENGTH sizeof(new_session_ticket_t)
#define DTLS_KE_HASH_INPUT_LENGHT  (32 + 32 + 2 + ECDH_PKEY_LENGTH)  /* 2x rand + curve_name + ecdh_Pkey*/
#define DTLS_SH_LENGTH (2 + 32 + 1 + 2 + 1)
#define DTLS_CKX_LENGTH 1
#define DTLS_FIN_LENGTH 12

#define HS_HDR_LENGTH  DTLS_RH_LENGTH + DTLS_HS_LENGTH
#define HV_HDR_LENGTH  HS_HDR_LENGTH + DTLS_HV_LENGTH

#define HIGH_(V) (((V) >> 8) & 0xff)
#define LOW_(V)  ((V) & 0xff)

#define DTLS_RECORD_HEADER(M) ((dtls_record_header_t *)(M))
#define DTLS_HANDSHAKE_HEADER(M) ((dtls_handshake_header_t *)(M))

#define HANDSHAKE(M) ((dtls_handshake_header_t *)((M) + DTLS_RH_LENGTH))
#define CLIENTHELLO(M) ((dtls_client_hello_t *)((M) + HS_HDR_LENGTH))

#define IS_HELLOVERIFY(M,L) \
      ((L) >= DTLS_HS_LENGTH + DTLS_HV_LENGTH && (M)[0] == DTLS_HT_HELLO_VERIFY_REQUEST)
#define IS_SERVERHELLO(M,L) \
      ((L) >= DTLS_HS_LENGTH + 6 && (M)[0] == DTLS_HT_SERVER_HELLO)
#define IS_SERVERHELLODONE(M,L) \
      ((L) >= DTLS_HS_LENGTH && (M)[0] == DTLS_HT_SERVER_HELLO_DONE)
#define IS_FINISHED(M,L) \
      ((L) >= DTLS_HS_LENGTH + DTLS_FIN_LENGTH && (M)[0] == DTLS_HT_FINISHED)
#define IS_CERTIFICATE(M, L) \
      ((L) >= DTLS_HS_LENGTH && (M)[0] == DTLS_HT_CERTIFICATE)
#define IS_SERVERKEYEXCHANGE(M, L) \
      ((L) >= DTLS_HS_LENGTH && (M)[0] == DTLS_HT_SERVER_KEY_EXCHANGE)
#define IS_CERTIFICATEREQUEST(M, L) \
      ((L) >= DTLS_HS_LENGTH && (M)[0] == DTLS_HT_CERTIFICATE_REQUEST)
#define IS_CLIENTKEYEXCHANGE(M, L) \
      ((L) >= DTLS_HS_LENGTH && (M)[0] == DTLS_HT_CLIENT_KEY_EXCHANGE)
#define IS_CERTIFICATEVERIFY(M, L) \
      ((L) >= DTLS_HS_LENGTH && (M)[0] == DTLS_HT_CERTIFICATE_VERIFY)
#define IS_NEWSESSIONTICKET(M, L) \
    ((L) >= DTLS_HS_LENGTH && (M)[0] == DTLS_EX_SESSIONTICKET_CLIENT)

/* The length check here should work because dtls_*_to_int() works on
 * unsigned char. Otherwise, broken messages could cause severe
 * trouble. Note that this macro jumps out of the current program flow
 * when the message is too short. Beware!
 */
#define SKIP_VAR_FIELD(P,L,T) {						\
    if (L < dtls_ ## T ## _to_int(P) + sizeof(T))			\
      return 0;							\
    L -= dtls_ ## T ## _to_int(P) + sizeof(T);				\
    P += dtls_ ## T ## _to_int(P) + sizeof(T);				\
  }

#define CURRENT_CONFIG(Peer) (&(Peer)->security_params[(Peer)->config])
#define OTHER_CONFIG(Peer) (&(Peer)->security_params[!((Peer)->config & 0x01)])

#define SWITCH_CONFIG(Peer) ((Peer)->config = !((Peer)->config & 0x01))

//uint8 _clear[DTLS_MAX_BUF]; /* target buffer message decryption */
//uint8 _buf[DTLS_MAX_BUF]; /* target buffer for several crypto operations */
typedef union {
  uint32_t u32[(DTLS_MAX_BUF + 3) / 4];
  uint8_t u8[DTLS_MAX_BUF];
} dtls_buf_t;

static dtls_buf_t dtls_aligned_buf;
#define dtls_buf (dtls_aligned_buf.u8)  /* temp buffer to put messages together */

#if EVAL_IN_NODE_PROCESSING
static rtimer_clock_t start_time;
static rtimer_clock_t end_time;
#define START_TIMER start_time = clock_counter();\
        INT2_SET_1()
#define STOP_TIMER end_time = clock_counter();\
        INT2_SET_0()
#define PRINT_EVAL(modul) printf("Energy (%s_full): cpu %u %u\n", modul,(end_time - start_time), RTIMER_ARCH_SECOND)
#else /* EVAL_IN_NODE_PROCESSING */
#define START_TIMER
#define STOP_TIMER
#define PRINT_EVAL
#endif /* EVAL_IN_NODE_PROCESSING */

#if EVAL_HANDSHAKE_RUN_TIME
static rtimer_clock_t start_time;
static rtimer_clock_t end_time;
#define START_TIMER_H start_time = clock_time();\
        INT1_SET_1()
#define STOP_TIMER_H end_time = clock_time();\
        INT1_SET_0()
#define PRINT_EVAL_H(modul, retrans) printf("Energy (%s_full): retrans %d cpu %u %u \n", modul, retrans, (end_time - start_time), CLOCK_SECOND)
#else /* EVAL_HANDSHAKE_RUN_TIME */
#define START_TIMER_H
#define STOP_TIMER_H
#define PRINT_EVAL_H
#endif /* EVAL_HANDSHAKE_RUN_TIME */

#if EVAL_SYMMETRIC_CRYPTO
static rtimer_clock_t start_time;
static rtimer_clock_t end_time;
#define START_TIMER_S start_time = clock_counter()
#define STOP_TIMER_S end_time = clock_counter()
#define PRINT_EVAL_S(modul, len) printf("Energy (%s_sym_%d): cpu %u %u\n", modul, len, (end_time - start_time), RTIMER_ARCH_SECOND)
#else /*EVAL_SYMMETRIC_CRYPTO*/
#define START_TIMER_S
#define STOP_TIMER_S
#define PRINT_EVAL_S
#endif /*EVAL_SYMMETRIC_CRYPTO*/

static uint8_t retrans_number;

#ifndef NDEBUG
void hexdump(const unsigned char *packet, int length);
void dump(unsigned char *buf, size_t len);
#define HEXDUMP(...) hexdump(__VA_ARGS__)
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define HEXDUMP(...)
#define PRINTF(...)
#endif

#if STACK_DUMP
extern int16_t stack_i;
extern unsigned char *stack_base;
#endif /* STACK_DUMP */


/* some constants for the PRF */
#define PRF_LABEL(Label) prf_label_##Label
#define PRF_LABEL_SIZE(Label) (sizeof(PRF_LABEL(Label)) - 1)

static const unsigned char prf_label_master[] = "master secret";
static const unsigned char prf_label_key[] = "key expansion";
static const unsigned char prf_label_client[] = "client";
static const unsigned char prf_label_server[] = "server";
static const unsigned char prf_label_finished[] = " finished";

extern void netq_init();
extern void crypto_init();

dtls_context_t the_dtls_context;

#ifndef WITH_CONTIKI
static inline dtls_peer_t *
dtls_malloc_peer() {
  return (dtls_peer_t *)malloc(sizeof(dtls_peer_t));
}

static inline void
dtls_free_peer(dtls_peer_t *peer) {
  free(peer);
}
#else /* WITH_CONTIKI */
PROCESS(dtls_retransmit_process, "DTLS retransmit process");

#include "memb.h"
MEMB(peer_storage, dtls_peer_t, DTLS_PEER_MAX);

static inline dtls_peer_t *
dtls_malloc_peer() {
  return memb_alloc(&peer_storage);
}
static inline void
dtls_free_peer(dtls_peer_t *peer) {
  memb_free(&peer_storage, peer);
}
#endif /* WITH_CONTIKI */

void
dtls_init() {
  retrans_number=0;
  netq_init();
  crypto_init();
#if WITH_PKI
#if !BUSY_WAIT_DSA && !BUSY_WAIT_DH
  init_elliptic_curve_lib();
#endif /* !BUSY_WAIT_DSA & !BUSY_WAIT_DH */
#endif /* WITH_PKI */
#ifdef WITH_CONTIKI
  memb_init(&peer_storage);
#endif /* WITH_CONTIKI */
}

/* Calls cb_alert() with given arguments if defined, otherwise
 * error message is logged and the result is -1. This is just an
 * internal helper.
 */
#define CALL(Context, which, ...)					\
  ((Context)->h && (Context)->h->which					\
   ? (Context)->h->which((Context), ##__VA_ARGS__)			\
   : -1)

/** 
 * Sends the fragment of length \p buflen given in \p buf to the
 * specified \p peer. The data will be MAC-protected and encrypted
 * according to the selected cipher and split into one or more DTLS
 * records of the specified \p type. This function returns the number
 * of bytes that were sent, or \c -1 if an error occurred.
 *
 * \param ctx    The DTLS context to use.
 * \param peer   The remote peer.
 * \param type   The content type of the record. 
 * \param buf    The data to send.
 * \param buflen The actual length of \p buf.
 * \return Less than zero on error, the number of bytes written otherwise.
 */
int dtls_send(dtls_context_t *ctx, dtls_peer_t *peer, unsigned char type,
	      uint8 *buf, size_t buflen);

static inline int
dtls_send_ccs(dtls_context_t *ctx, dtls_peer_t *peer);


/**
 * Stops ongoing retransmissions of handshake messages for @p peer.
 */
void dtls_stop_retransmission(dtls_context_t *context, dtls_peer_t *peer);

dtls_peer_t *
dtls_get_peer(struct dtls_context_t *ctx, const session_t *session) {
  dtls_peer_t *p = NULL;

#ifndef WITH_CONTIKI
  HASH_FIND_PEER(ctx->peers, session, p);
#else /* WITH_CONTIKI */
  for (p = list_head(ctx->peers); p; p = list_item_next(p))
    if (dtls_session_equals(&p->session, session))
      return p;
#endif /* WITH_CONTIKI */
  
  return p;
}

int
dtls_write(struct dtls_context_t *ctx, 
	   session_t *dst, uint8 *buf, size_t len) {
  
  dtls_peer_t *peer = dtls_get_peer(ctx, dst);
  
  if (peer && peer->state == DTLS_STATE_CONNECTED)
    return dtls_send(ctx, peer, DTLS_CT_APPLICATION_DATA, buf, len);
  else
    return peer ? 0 : -1;
}
#if !ONLY_RESUMPTION
int
dtls_get_cookie(uint8 *msg, int msglen, uint8 **cookie) {
  /* To access the cookie, we have to determine the session id's
   * length and skip the whole thing. */
  if (msglen < DTLS_HS_LENGTH + DTLS_CH_LENGTH + sizeof(uint8)
      || dtls_uint16_to_int(msg + DTLS_HS_LENGTH) != DTLS_VERSION)
    return -1;
  msglen -= DTLS_HS_LENGTH + DTLS_CH_LENGTH;
  msg += DTLS_HS_LENGTH + DTLS_CH_LENGTH;

  SKIP_VAR_FIELD(msg, msglen, uint8); /* skip session id */

  if (msglen < (*msg & 0xff) + sizeof(uint8))
    return -1;
  
  *cookie = msg + sizeof(uint8);
  return dtls_uint8_to_int(msg);

  return -1;
}

int
dtls_create_cookie(dtls_context_t *ctx, 
		   session_t *session,
		   uint8 *msg, int msglen,
		   uint8 *cookie, int *clen) {
  unsigned char buf[DTLS_HMAC_MAX];
  size_t len, e;

  /* create cookie with HMAC-SHA256 over:
   * - SECRET
   * - session parameters (only IP address?)
   * - client version 
   * - random gmt and bytes
   * - session id
   * - cipher_suites 
   * - compression method
   */

  /* We use our own buffer as hmac_context instead of a dynamic buffer
   * created by dtls_hmac_new() to separate storage space for cookie
   * creation from storage that is used in real sessions. Note that
   * the buffer size must fit with the default hash algorithm (see
   * implementation of dtls_hmac_context_new()). */

  dtls_hmac_context_t hmac_context;
  dtls_hmac_init(&hmac_context, ctx->cookie_secret, DTLS_COOKIE_SECRET_LENGTH);

  dtls_hmac_update(&hmac_context, 
		   (unsigned char *)&session->addr, session->size);

  /* feed in the beginning of the Client Hello up to and including the
     session id */
  e = sizeof(dtls_client_hello_t);
  e += (*(msg + DTLS_HS_LENGTH + e) & 0xff) + sizeof(uint8);

  dtls_hmac_update(&hmac_context, msg + DTLS_HS_LENGTH, e);
  
  /* skip cookie bytes and length byte */
  e += *(uint8 *)(msg + DTLS_HS_LENGTH + e) & 0xff;
  e += sizeof(uint8);

  dtls_hmac_update(&hmac_context, 
		   msg + DTLS_HS_LENGTH + e,
		   dtls_get_fragment_length(DTLS_HANDSHAKE_HEADER(msg)) - e);

  len = dtls_hmac_finalize(&hmac_context, buf);

  if (len < *clen) {
    memset(cookie + len, 0, *clen - len);
    *clen = len;
  }
  
  memcpy(cookie, buf, *clen);
  return 1;
}
#endif /* !ONLY_RESUMPTION */
#ifdef DTLS_CHECK_CONTENTTYPE
/* used to check if a received datagram contains a DTLS message */
static char const content_types[] = { 
  DTLS_CT_CHANGE_CIPHER_SPEC,
  DTLS_CT_ALERT,
  DTLS_CT_HANDSHAKE,
  DTLS_CT_APPLICATION_DATA,
  0 				/* end marker */
};
#endif

/**
 * Checks if \p msg points to a valid DTLS record. If
 * 
 */
static unsigned int
is_record(uint8 *msg, int msglen) {
  unsigned int rlen = 0;

  if (msglen >= DTLS_RH_LENGTH	/* FIXME allow empty records? */
#ifdef DTLS_CHECK_CONTENTTYPE
      && strchr(content_types, msg[0])
#endif
      && msg[1] == HIGH_(DTLS_VERSION)
      && msg[2] == LOW_(DTLS_VERSION))
    {
      rlen = DTLS_RH_LENGTH + 
	dtls_uint16_to_int(DTLS_RECORD_HEADER(msg)->length);
      
      /* we do not accept wrong length field in record header */
      if (rlen > msglen)	
	rlen = 0;
  } 
  
  return rlen;
}

/**
 * Initializes \p buf as record header. The caller must ensure that \p
 * buf is capable of holding at least \c sizeof(dtls_record_header_t)
 * bytes. Increments sequence number counter of \p peer.
 * \return pointer to the next byte after the written header
 */ 
static inline uint8 *
dtls_set_record_header(uint8 type, dtls_peer_t *peer, uint8 *buf) {
  
  dtls_int_to_uint8(buf, type);
  buf += sizeof(uint8);

  dtls_int_to_uint16(buf, DTLS_VERSION);
  buf += sizeof(uint16);

  if (peer) {
    memcpy(buf, &peer->epoch, sizeof(uint16) + sizeof(uint48));

    /* increment record sequence counter by 1 */
    inc_uint(uint48, peer->rseq);
  } else {
    memset(buf, 0, sizeof(uint16) + sizeof(uint48));
  }

  buf += sizeof(uint16) + sizeof(uint48);

  memset(buf, 0, sizeof(uint16));
  return buf + sizeof(uint16);
}

/**
 * Initializes \p buf as handshake header. The caller must ensure that \p
 * buf is capable of holding at least \c sizeof(dtls_handshake_header_t)
 * bytes. Increments message sequence number counter of \p peer.
 * \return pointer to the next byte after \p buf
 */ 
static inline uint8 *
dtls_set_handshake_header(uint8 type, dtls_peer_t *peer, 
			  int length, 
			  int frag_offset, int frag_length, 
			  uint8 *buf) {
  
  dtls_int_to_uint8(buf, type);
  buf += sizeof(uint8);


  /* FEXME int is 16bit, using 24bit is out of range access */
  buf += sizeof(uint8); // length only 16bit
  dtls_int_to_uint16(buf, length);
  buf += sizeof(uint16);

  if (peer) {
    /* increment handshake message sequence counter by 1 */
    inc_uint(uint16, peer->hs_state.mseq);
  
    /* and copy the result to buf */
    memcpy(buf, &peer->hs_state.mseq, sizeof(uint16));
  } else {
    memset(buf, 0, sizeof(uint16));    
  }
  //info("Sequence number mseq(%d) \n", dtls_uint16_to_int(buf));
  buf += sizeof(uint16);
  
  buf += sizeof(uint8); // frag_offset only 16bit
  dtls_int_to_uint16(buf, frag_offset);
  buf += sizeof(uint16);

  buf += sizeof(uint8); // frag_length only 16bit
  dtls_int_to_uint16(buf, frag_length);
  buf += sizeof(uint16);
  
  return buf;
}
/* -------------------------------------------------------------------------- */
#if !ONLY_RESUMPTION
/**
 * Checks a received Client Hello message for a valid cookie. When the
 * Client Hello contains no cookie, the function fails and a Hello
 * Verify Request is sent to the peer (using the write callback function
 * registered with \p ctx). The return value is \c -1 on error, \c 0 when
 * undecided, and \c 1 if the Client Hello was good. 
 * 
 * \param ctx     The DTLS context.
 * \param peer    The remote party we are talking to, if any.
 * \param session Transport address of the remote peer.
 * \param msg     The received datagram.
 * \param msglen  Length of \p msg.
 * \return \c 1 if msg is a Client Hello with a valid cookie, \c 0 or
 * \c -1 otherwise.
 */
int
dtls_verify_peer(dtls_context_t *ctx, 
		 dtls_peer_t *peer, 
		 session_t *session,
		 uint8 *record, 
		 uint8 *data, size_t data_length) {

  int len = DTLS_COOKIE_LENGTH;
  uint8 *cookie, *p;
#undef mycookie
#define mycookie (ctx->sendbuf + HV_HDR_LENGTH)
#ifndef NDEBUG
  /* Print the received header and payload of the record layer*/
  hexdump(data - DTLS_RH_LENGTH, DTLS_RH_LENGTH);
  printf("\n");
  hexdump(data, data_length);
  printf("\n");
  printf("dtls_verify_peer: HANDSHAKE %u=22, LEN %u>%u, HELLO %u=1\n",
          record[0],
          data_length, DTLS_HS_LENGTH,
          data[0]);
#endif /* NDEBUG */

  /* check if we can access at least all fields from the handshake header */
  if (record[0] == DTLS_CT_HANDSHAKE
      && data_length >= DTLS_HS_LENGTH 
      && data[0] == DTLS_HT_CLIENT_HELLO) {

    /* Store cookie where we can reuse it for the HelloVerify request. */
    if (dtls_create_cookie(ctx, session, data, data_length,
			   mycookie, &len) < 0)
      return -1;
#ifndef NDEBUG
    debug("create cookie: ");
    dump(mycookie, len);
    printf("\n");
#endif
    assert(len == DTLS_COOKIE_LENGTH);
    
    /* Perform cookie check. */
    len = dtls_get_cookie(data, data_length, &cookie);

#ifndef NDEBUG
    debug("compare with cookie: ");
    dump(cookie, len);
    printf("\n");
#endif

    /* check if cookies match */
    if (len == DTLS_COOKIE_LENGTH && memcmp(cookie, mycookie, len) == 0) {
    debug("found matching cookie\n");
      return 1;      
    }
#ifndef NDEBUG
    if (len > 0) {
      debug("invalid cookie:");
      dump(cookie, len);
      printf("\n");
    } else {
      debug("cookie len is 0!\n");
    }
#endif
    /* ClientHello did not contain any valid cookie, hence we send a
     * HelloVerify request. */

    p = dtls_set_handshake_header(DTLS_HT_HELLO_VERIFY_REQUEST,
				  peer, DTLS_HV_LENGTH + DTLS_COOKIE_LENGTH,
				  0, DTLS_HV_LENGTH + DTLS_COOKIE_LENGTH, 
				  ctx->sendbuf + DTLS_RH_LENGTH);

    dtls_int_to_uint16(p, DTLS_VERSION);
    p += sizeof(uint16);

    dtls_int_to_uint8(p, DTLS_COOKIE_LENGTH);
    p += sizeof(uint8);

    assert(p == mycookie);
    
    p += DTLS_COOKIE_LENGTH;

    if (!peer) {
      /* It's an initial ClientHello, so we set the record header
       * manually and send the HelloVerify request using the
       * registered write callback. */

      dtls_set_record_header(DTLS_CT_HANDSHAKE, NULL, ctx->sendbuf);
      /* set packet length */
      dtls_int_to_uint16(ctx->sendbuf + 11, 
			 p - (ctx->sendbuf + DTLS_RH_LENGTH));

      STOP_TIMER;
      (void)CALL(ctx, write, session, ctx->sendbuf, p - ctx->sendbuf);
    } else {
      if (peer->epoch) {
	debug("renegotiation, therefore we accept it anyway:");
	return 1;
      }

      STOP_TIMER;
      if (dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, 
		    ctx->sendbuf + DTLS_RH_LENGTH, 
		    p - (ctx->sendbuf + DTLS_RH_LENGTH)) < 0) {
	warn("cannot send HelloVerify request\n");
	return -1;
      }

    }
    PRINT_EVAL("HelloVer");
    return 0; /* HelloVerify is sent, now we cannot do anything but wait */
  }

  return -1;			/* not a ClientHello, signal error */
#undef mycookie
}
#endif /* !ONLY_RESUMPTION */
/** only one compression method is currently defined */
uint8 compression_methods[] = { 
  TLS_COMP_NULL 
};

/**
 * Returns @c 1 if @p code is a cipher suite other than @c
 * TLS_NULL_WITH_NULL_NULL that we recognize.
 *
 * @param code The cipher suite identifier to check
 * @return @c 1 iff @p code is recognized,
 */ 
static inline int
known_cipher(dtls_cipher_t code) {
#if WITH_PKI
  // FIXME we should have support for both cipher suites
  //return (code == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 || code == TLS_PSK_WITH_AES_128_CCM_8);
  return (code == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
#else /* WITH_PKI */
  return code == TLS_PSK_WITH_AES_128_CCM_8;
#endif /* WITH_PKI */
}

int
calculate_key_block(dtls_context_t *ctx, 
		    dtls_security_parameters_t *config,
		    const dtls_key_t *key,
		    const unsigned char client_random[32],
		    const unsigned char server_random[32]) {
  unsigned char *pre_master_secret;
  size_t pre_master_len = 0;
  pre_master_secret = config->key_block;

  assert(key);
  switch (key->type) {
#if WITH_PKI
  case DTLS_KEY_PKI: {

#if BUSY_WAIT_DH
    unsigned char busy_wait_pre_master[] = {
        0x70, 0x17, 0xd4, 0x04, 0x80, 0xed, 0xe9, 0x22, 0x00, 0x49, 0xfe, 0xfd, 0xc0, 0xac, 0x00, 0x90,
        0xb3, 0x5e, 0x9a, 0x04, 0x17, 0x52, 0xcc, 0x65, 0xc4, 0x14, 0x16, 0xeb, 0xde, 0x00, 0x72, 0xca,
        0xc3, 0x40, 0x65, 0x4f, 0xd6, 0x2d, 0x96, 0x47, 0xde, 0x73, 0x57, 0xfa, 0xcd, 0xf1, 0xfb, 0xf9
    };
    memcpy(pre_master_secret, busy_wait_pre_master, 32);
    clock_wait(0.88*CLOCK_SECOND);
    pre_master_len = ECDH_PKEY_LENGTH;
#else /* BUSY_WAIT_DH */
    /* Drive shared point (premaster secret) with our ECDH private key and servers's ECDH public key! */
    /* Temporarily store the premaster secret in keyblock's storage space */
    memset(pre_master_secret, 0, ECDH_PKEY_LENGTH);
    watchdog_stop();
    cp_ecdh_key(pre_master_secret,
                ECDH_PKEY_LENGTH,
                config->ecdh_d,
                config->peer_ecdh_q);
    watchdog_start();
    pre_master_len = ECDH_PKEY_LENGTH;

#ifndef NDEBUG
  PRINTF("ECDH private value ME\n");
  bn_print(config->ecdh_d);
  PRINTF("ECDH public value peer (%s)\n", (ep_is_valid(config->peer_ecdh_q) != 0) ? "valid":"invalid");
  ep_print(config->peer_ecdh_q);
#endif /* NDEBUG */
#endif /* BUSY_WAIT_DH */

    break;
  }
#elif ONLY_RESUMPTION
  case DTLS_KEY_ABBR: {
    pre_master_len = DTLS_MASTER_SECRET_LENGTH;
    break;
  }
#else /* PSK */
  case DTLS_KEY_PSK: {
  /* Temporarily use the key_block storage space for the pre master secret. */
    pre_master_len = dtls_pre_master_secret(key->key.psk.key, key->key.psk.key_length, 
					  pre_master_secret);
    
    break;
  }
#endif /* WITH_PKI */
  default:
    debug("calculate_key_block: unknown key type\n");
    return 0;
  }

#ifndef NDEBUG
  {
    int i;

    printf("client_random:");
    for (i = 0; i < 32; ++i)
      printf(" %02x", client_random[i]);
    printf("\n");

    printf("server_random:");
    for (i = 0; i < 32; ++i)
      printf(" %02x", server_random[i]);
    printf("\n");

#if !WITH_PKI && !ONLY_RESUMPTION
    printf("psk: (%u bytes):", key->key.psk.key_length);
    hexdump(key->key.psk.key, key->key.psk.key_length);
    printf("\n");
#endif /* !WITH_PKI */

    printf("pre_master_secret: (%u bytes):", pre_master_len);
    for (i = 0; i < pre_master_len; ++i)
      printf(" %02x", pre_master_secret[i]);
    printf("\n");
  }
#endif /* NDEBUG */


  memset(config->master_secret, 0, DTLS_MASTER_SECRET_LENGTH);
  if ( 0 == dtls_p_hash(HASH_SHA256, pre_master_secret, pre_master_len,
	   PRF_LABEL(master), PRF_LABEL_SIZE(master),
	   client_random, 32,
	   server_random, 32,
	   config->master_secret, 
	   DTLS_MASTER_SECRET_LENGTH) ) {
     warn("PRF failed!\n");
  }
#ifndef NDEBUG
  {
    int i;
    printf("master_secret (%d bytes):", DTLS_MASTER_SECRET_LENGTH);
    for (i = 0; i < DTLS_MASTER_SECRET_LENGTH; ++i)
      printf(" %02x", config->master_secret[i]);
    printf("\n");
  }
#endif /* NDEBUG */

  /* create key_block from master_secret
   * key_block = PRF(master_secret,
                    "key expansion" + server_random + client_random) */

  memset(config->key_block, 0, dtls_kb_size(config));
  dtls_p_hash(HASH_SHA256, config->master_secret,
	   DTLS_MASTER_SECRET_LENGTH,
	   PRF_LABEL(key), PRF_LABEL_SIZE(key),
	   server_random, 32,
	   client_random, 32,
	   config->key_block,
	   dtls_kb_size(config));

#ifndef NDEBUG
  {
      printf("key_block (%d bytes):\n", dtls_kb_size(config));
      printf("  client_MAC_secret:\t");  
      dump(dtls_kb_client_mac_secret(config), 
	   dtls_kb_mac_secret_size(config));
      printf("\n");

      printf("  server_MAC_secret:\t");  
      dump(dtls_kb_server_mac_secret(config), 
	   dtls_kb_mac_secret_size(config));
      printf("\n");

      printf("  client_write_key:\t");  
      dump(dtls_kb_client_write_key(config), 
	   dtls_kb_key_size(config));
      printf("\n");

      printf("  server_write_key:\t");  
      dump(dtls_kb_server_write_key(config), 
	   dtls_kb_key_size(config));
      printf("\n");

      printf("  client_IV:\t\t");  
      dump(dtls_kb_client_iv(config), 
	   dtls_kb_iv_size(config));
      printf("\n");
      
      printf("  server_IV:\t\t");  
      dump(dtls_kb_server_iv(config), 
	   dtls_kb_iv_size(config));
      printf("\n");
      

  }
#endif
  return 1;
}

/**
 * Updates the security parameters of given \p peer.  As this must be
 * done before the new configuration is activated, it changes the
 * OTHER_CONFIG only. When the ClientHello handshake message in \p
 * data does not contain a cipher suite or compression method, it is 
 * copied from the CURRENT_CONFIG.
 *
 * \param ctx   The current DTLS context.
 * \param peer  The remote peer whose security parameters are about to change.
 * \param data  The handshake message with a ClientHello. 
 * \param data_length The actual size of \p data.
 * \return \c 0 if an error occurred, \c 1 otherwise.
 */
int
dtls_update_parameters(dtls_context_t *ctx, 
		       dtls_peer_t *peer,
		       uint8 *data, size_t data_length) {
  int i, j;
  int ok;
  dtls_security_parameters_t *config = OTHER_CONFIG(peer);

  assert(config);
  assert(data_length > DTLS_HS_LENGTH + DTLS_CH_LENGTH);

  /* debug("dtls_update_parameters: msglen is %d\n", data_length); */

  /* skip the handshake header and client version information */
  data += DTLS_HS_LENGTH + sizeof(uint16);
  data_length -= DTLS_HS_LENGTH + sizeof(uint16);

  /* store client random in config 
   * FIXME: if we send the ServerHello here, we do not need to store
   * the client's random bytes */
  memcpy(config->client_random, data, sizeof(config->client_random));
  data += sizeof(config->client_random);
  data_length -= sizeof(config->client_random);

  /* Caution: SKIP_VAR_FIELD may jump to error: */
  SKIP_VAR_FIELD(data, data_length, uint8);	/* skip session id */
  SKIP_VAR_FIELD(data, data_length, uint8);	/* skip cookie */

  i = dtls_uint16_to_int(data);
  if (data_length < i + sizeof(uint16)) {
    /* Looks like we do not have a cipher nor compression. This is ok
     * for renegotiation, but not for the initial handshake. */

    if (CURRENT_CONFIG(peer)->cipher == TLS_NULL_WITH_NULL_NULL)
      goto error;

    config->cipher = CURRENT_CONFIG(peer)->cipher;
    config->compression = CURRENT_CONFIG(peer)->compression;

    return 1;
  }

  data += sizeof(uint16);
  data_length -= sizeof(uint16) + i;

  ok = 0;
  while (i && !ok) {
    config->cipher = dtls_uint16_to_int(data);
    ok = known_cipher(config->cipher);
    i -= sizeof(uint16);
    data += sizeof(uint16);
  }

  /* skip remaining ciphers */
  data += i;

  if (!ok) {
    /* reset config cipher to a well-defined value */
    config->cipher = TLS_NULL_WITH_NULL_NULL;
    return 0;
  }

  if (data_length < sizeof(uint8)) { 
    /* no compression specified, take the current compression method */
    config->compression = CURRENT_CONFIG(peer)->compression;
    return 1;
  }

  i = dtls_uint8_to_int(data);
  if (data_length < i + sizeof(uint8))
    goto error;

  data += sizeof(uint8);
  data_length -= sizeof(uint8) + i;

  ok = 0;
  while (i && !ok) {
    for (j = 0; j < sizeof(compression_methods) / sizeof(uint8); ++j)
      if (dtls_uint8_to_int(data) == compression_methods[j]) {
	config->compression = compression_methods[j];
	ok = 1;
      }
    i -= sizeof(uint8);
    data += sizeof(uint8);    
  }

#if WITH_RESUMPTION
    /* Check Extension for SessionTicket is used */
    if (data_length >= sizeof(uint16) && dtls_uint16_to_int(data) == DTLS_EX_SESSIONTICKET_CLIENT) {
      debug("ClientHello: Extension for SessionTicket\n");
      data += sizeof(uint16);
      data_length -= sizeof(uint16);
      if (data_length >= sizeof(uint16) && dtls_uint16_to_int(data) == 0) {
        debug("ClientHello: Empty SessionTicket\n");
        /* FIXME prepare for server-side off-loading */
      } else {
        debug("ClientHello: SessionTicket\n");
        /* FIXME handle the Session Ticket in case of Server-side off-loading */
      }
    } else {
      debug("ClientHello: no valid Extension\n");
    }
#endif /* WITH_RESUMPTION */
  
  return ok;
 error:
  warn("ClientHello too short (%d bytes)\n", data_length);
  return 0;
}

static inline int
check_client_keyexchange(dtls_context_t *ctx, 
			 dtls_peer_t *peer,
			 uint8 *data, size_t length) {
  return length >= DTLS_CKX_LENGTH && data[0] == DTLS_HT_CLIENT_KEY_EXCHANGE;
}

static int
check_ccs(dtls_context_t *ctx, 
	  dtls_peer_t *peer,
	  uint8 *record, uint8 *data, size_t data_length) {

  if (DTLS_RECORD_HEADER(record)->content_type != DTLS_CT_CHANGE_CIPHER_SPEC
      || data_length < 1 || data[0] != 1)
    return 0;

  /* set crypto context for TLS_PSK_WITH_AES_128_CCM_8
   * or
   * TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8*/
  /* client */
  dtls_cipher_free(OTHER_CONFIG(peer)->read_cipher);

  assert(OTHER_CONFIG(peer)->cipher != TLS_NULL_WITH_NULL_NULL);
  OTHER_CONFIG(peer)->read_cipher = 
    dtls_cipher_new(OTHER_CONFIG(peer)->cipher,
		    dtls_kb_client_write_key(OTHER_CONFIG(peer)),
		    dtls_kb_key_size(OTHER_CONFIG(peer)));

  if (!OTHER_CONFIG(peer)->read_cipher) {
    warn("cannot create read cipher\n");
    return 0;
  }

  dtls_cipher_set_iv(OTHER_CONFIG(peer)->read_cipher,
		     dtls_kb_client_iv(OTHER_CONFIG(peer)),
		     dtls_kb_iv_size(OTHER_CONFIG(peer)));

  /* server */
  dtls_cipher_free(OTHER_CONFIG(peer)->write_cipher);
  
  OTHER_CONFIG(peer)->write_cipher = 
    dtls_cipher_new(OTHER_CONFIG(peer)->cipher,
		    dtls_kb_server_write_key(OTHER_CONFIG(peer)),
		    dtls_kb_key_size(OTHER_CONFIG(peer)));

  if (!OTHER_CONFIG(peer)->write_cipher) {
    warn("cannot create write cipher\n");
    return 0;
  }

  dtls_cipher_set_iv(OTHER_CONFIG(peer)->write_cipher,
		     dtls_kb_server_iv(OTHER_CONFIG(peer)),
		     dtls_kb_iv_size(OTHER_CONFIG(peer)));

  return 1;
}

#ifndef NDEBUG
extern size_t dsrv_print_addr(const session_t *, unsigned char *, size_t);
#endif

dtls_peer_t *
dtls_new_peer(dtls_context_t *ctx, 
	      const session_t *session) {
  dtls_peer_t *peer;

  peer = dtls_malloc_peer();
  if (peer) {
    memset(peer, 0, sizeof(dtls_peer_t));
    memcpy(&peer->session, session, sizeof(session_t));

#ifndef NDEBUG
    {
      unsigned char addrbuf[72];
      dsrv_print_addr(session, addrbuf, sizeof(addrbuf));
      printf("dtls_new_peer: %s\n", addrbuf);
      dump((unsigned char *)session, sizeof(session_t));
      printf("\n");
    }
#endif
    /* initially allow the NULL cipher */
    CURRENT_CONFIG(peer)->cipher = TLS_NULL_WITH_NULL_NULL;

    /* initialize the handshake hash wrt. the hard-coded DTLS version */
    debug("DTLSv12: initialize HASH_SHA256\n");
    /* TLS 1.2:  PRF(secret, label, seed) = P_<hash>(secret, label + seed) */
    /* FIXME: we use the default SHA256 here, might need to support other 
              hash functions as well */
    dtls_hash_init(&peer->hs_state.hs_hash);
  }
  
  return peer;
}

static inline void
update_hs_hash(dtls_peer_t *peer, uint8 *data, size_t length) {
#ifndef NDEBUG
  printf("add MAC data: ");
  dump(data, length);
  printf("\n");
#endif

  START_TIMER_S;
  dtls_hash_update(&peer->hs_state.hs_hash, data, length);
  STOP_TIMER_S;
  PRINT_EVAL_S("HASHTAG", length);
}

static inline size_t
finalize_hs_hash(dtls_peer_t *peer, uint8 *buf) {
  return dtls_hash_finalize(buf, &peer->hs_state.hs_hash);
}

static inline void
clear_hs_hash(dtls_peer_t *peer) {
  assert(peer);
  dtls_hash_init(&peer->hs_state.hs_hash);
}

/** 
 *Checks if \p record + \p data contain a Finished message with valid
 * verify_data. 
 *
 * \param ctx    The current DTLS context.
 * \param peer   The remote peer of the security association.
 * \param record The message record header.
 * \param rlen   The actual length of \p record.
 * \param data   The cleartext payload of the message.
 * \param data_length Actual length of \p data.
 * \return \c 1 if the Finished message is valid, \c 0 otherwise.
 */
static int
check_finished(dtls_context_t *ctx, dtls_peer_t *peer,
	       uint8 *record, uint8 *data, size_t data_length) {
  size_t digest_length, label_size;
  const unsigned char *label;
  unsigned char buf[DTLS_HMAC_MAX];

  /* Use a union here to ensure that sufficient stack space is
   * reserved. As statebuf and verify_data are not used at the same
   * time, we can re-use the storage safely.
   */
  union {
    unsigned char statebuf[DTLS_HASH_CTX_SIZE];
    unsigned char verify_data[DTLS_FIN_LENGTH];
  } b;

  debug("check Finish message\n");
  if (record[0] != DTLS_CT_HANDSHAKE || !IS_FINISHED(data, data_length)) {
    debug("failed\n");
    return 0;
  }

  /* temporarily store hash status for roll-back after finalize */
  memcpy(b.statebuf, &peer->hs_state.hs_hash, DTLS_HASH_CTX_SIZE);

  digest_length = finalize_hs_hash(peer, buf);
  /* clear_hash(); */

  /* restore hash status */
  memcpy(&peer->hs_state.hs_hash, b.statebuf, DTLS_HASH_CTX_SIZE);

  if (CURRENT_CONFIG(peer)->role == DTLS_SERVER) {
    label = PRF_LABEL(server);
    label_size = PRF_LABEL_SIZE(server);
  } else { /* client */
    label = PRF_LABEL(client);
    label_size = PRF_LABEL_SIZE(client);
  }

  memset(b.verify_data, 0, sizeof(b.verify_data));
  dtls_p_hash(HASH_SHA256, CURRENT_CONFIG(peer)->master_secret,
	   DTLS_MASTER_SECRET_LENGTH,
	   label, label_size,
	   PRF_LABEL(finished), PRF_LABEL_SIZE(finished),
	   buf, digest_length,
	   b.verify_data, sizeof(b.verify_data));
  
#ifndef NDEBUG
  printf("d:\t"); dump(data + DTLS_HS_LENGTH, sizeof(b.verify_data)); printf("\n");
  printf("v:\t"); dump(b.verify_data, sizeof(b.verify_data)); printf("\n");
#endif
  return 
    memcmp(data + DTLS_HS_LENGTH, b.verify_data, sizeof(b.verify_data)) == 0;
}

/**
 * Prepares the payload given in \p data for sending with
 * dtls_send(). The \p data is encrypted and compressed according to
 * the current security parameters of \p peer.  The result of this
 * operation is put into \p sendbuf with a prepended record header of
 * type \p type ready for sending. As some cipher suites add a MAC
 * before encryption, \p data must be large enough to hold this data
 * as well (usually \c dtls_kb_digest_size(CURRENT_CONFIG(peer)).
 *
 * \param peer    The remote peer the packet will be sent to.
 * \param type    The content type of this record.
 * \param data    The payload to send.
 * \param data_length The size of \p data.
 * \param sendbuf The output buffer where the encrypted record
 *                will be placed.
 * \param rlen    This parameter must be initialized with the 
 *                maximum size of \p sendbuf and will be updated
 *                to hold the actual size of the stored packet
 *                on success. On error, the value of \p rlen is
 *                undefined. 
 * \return Less than zero on error, or greater than zero success.
 */
int
dtls_prepare_record(dtls_peer_t *peer,
		    unsigned char type,
		    uint8 *data, size_t data_length,
		    uint8 *sendbuf, size_t *rlen) {
  uint8 *p;
  int res;
  
  /* check the minimum that we need for packets that are not encrypted */
  if (*rlen < DTLS_RH_LENGTH + data_length) {
    debug("dtls_prepare_record: send buffer too small\n");
    debug("*rlen %d, data_length + RH_LENGTH %d\n", *rlen, DTLS_RH_LENGTH + data_length);
    return -1;
  }

  p = dtls_set_record_header(type, peer, sendbuf);

  if (CURRENT_CONFIG(peer)->cipher == TLS_NULL_WITH_NULL_NULL) {
    /* no cipher suite */
    memcpy(p, data, data_length);
    res = data_length;
  } else {
    /* TLS_PSK_WITH_AES_128_CCM_8
     * or
     * TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8*/
    dtls_cipher_context_t *cipher_context;

    /** 
     * length of additional_data for the AEAD cipher which consists of
     * seq_num(2+6) + type(1) + version(2) + length(2)
     */
#define A_DATA_LEN 13
#define A_DATA NNCE
    unsigned char NNCE[DTLS_CCM_BLOCKSIZE];
    
    if (*rlen < DTLS_RH_LENGTH + data_length + 8) {
      warn("dtls_prepare_record(): send buffer too small\n");
      return -1;
    }

#if WITH_PKI
    debug("dtls_prepare_record(): encrypt using TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8\n");
#else /* WITH_PKI */
    debug("dtls_prepare_record(): encrypt using TLS_PSK_WITH_AES_128_CCM_8\n");
#endif /* WITH_PKI */

    /* set nonce       
       from http://tools.ietf.org/html/draft-mcgrew-tls-aes-ccm-03:
        struct {
               case client:
                  uint32 client_write_IV;  // low order 32-bits
               case server:
                  uint32 server_write_IV;  // low order 32-bits
               uint64 seq_num;
            } CCMNonce.

	    In DTLS, the 64-bit seq_num is the 16-bit epoch concatenated with the
	    48-bit seq_num.
    */

    memcpy(p, &DTLS_RECORD_HEADER(sendbuf)->epoch, 8);
    memcpy(p + 8, data, data_length);

    memset(NNCE, 0, DTLS_CCM_BLOCKSIZE);
    memcpy(NNCE, dtls_kb_local_iv(CURRENT_CONFIG(peer)), 
	   dtls_kb_iv_size(CURRENT_CONFIG(peer)));
    memcpy(NNCE + dtls_kb_iv_size(CURRENT_CONFIG(peer)), p, 8); /* epoch + seq_num */

    cipher_context = CURRENT_CONFIG(peer)->write_cipher;

    if (!cipher_context) {
      warn("no write_cipher available!\n");
      return -1;
    }
#ifndef NDEBUG
    printf("nonce:\t");
    dump(NNCE, DTLS_CCM_BLOCKSIZE);
    printf("\nkey:\t");
    dump(dtls_kb_local_write_key(CURRENT_CONFIG(peer)), 
	 dtls_kb_key_size(CURRENT_CONFIG(peer)));
    printf("\n");
#endif
    dtls_cipher_set_iv(cipher_context, NNCE, DTLS_CCM_BLOCKSIZE);
    
    /* re-use NNCE to create additional data according to RFC 5246, Section 6.2.3.3:
     * 
     * additional_data = seq_num + TLSCompressed.type +
     *                   TLSCompressed.version + TLSCompressed.length;
     */
    memcpy(A_DATA, &DTLS_RECORD_HEADER(sendbuf)->epoch, 8); /* epoch and seq_num */
    memcpy(A_DATA + 8,  &DTLS_RECORD_HEADER(sendbuf)->content_type, 3); /* type and version */
    dtls_int_to_uint16(A_DATA + 11, data_length); /* length */

#if DEX_CCM
    res = aes_ccm_encrypt(dtls_kb_local_write_key(CURRENT_CONFIG(peer)),
                        NNCE,
                        p + 8,
                        A_DATA_LEN, /*al*/
                        data_length, /*ml*/
                        p + 8);
#else /* DEX_CCM */
    res = dtls_ccm_encrypt_message(&(&cipher_context->data)->ctx, 8 /* M */,
               max(2, 15 - DTLS_CCM_NONCE_SIZE),
               (&cipher_context->data)->NNCE,
               p + 8, data_length,
               A_DATA, A_DATA_LEN);
#endif /* DEX_CCM */

    if (res < 0)
      return -1;

#ifndef NDEBUG
    dump(p, res + 8);
    printf("\n");
#endif
    res += 8;			/* increment res by size of nonce_explicit */
  }

  /* fix length of fragment in sendbuf */
  dtls_int_to_uint16(&DTLS_RECORD_HEADER(sendbuf)->length, res);
  
  *rlen = DTLS_RH_LENGTH + res;
  return 1;
}

/** 
 * Returns true if the message @p Data is a handshake message that
 * must be included in the calculation of verify_data in the Finished
 * message.
 * 
 * @param Type The message type. Only handshake messages but the initial 
 * Client Hello and Hello Verify Request are included in the hash,
 * @param Data The PDU to examine.
 * @param Length The length of @p Data.
 * 
 * @return @c 1 if @p Data must be included in hash, @c 0 otherwise.
 *
 * @hideinitializer
 */
#define MUST_HASH(Type, Data, Length)					\
  ((Type) == DTLS_CT_HANDSHAKE &&					\
   ((Data) != NULL) && ((Length) > 0)  &&				\
   ((Data)[0] != DTLS_HT_HELLO_VERIFY_REQUEST) &&			\
   ((Data)[0] != DTLS_HT_CLIENT_HELLO ||				\
    ((Length) >= HS_HDR_LENGTH &&					\
     (dtls_uint16_to_int(DTLS_RECORD_HEADER(Data)->epoch > 0) ||	\
      (dtls_uint16_to_int(HANDSHAKE(Data)->message_seq) > 0)))))

/**
 * Sends the data passed in @p buf as a DTLS record of type @p type to
 * the given peer. The data will be encrypted and compressed according
 * to the security parameters for @p peer.
 *
 * @param ctx    The DTLS context in effect.
 * @param peer   The remote party where the packet is sent.
 * @param type   The content type of this record.
 * @param buf    The data to send.
 * @param buflen The number of bytes to send from @p buf.
 * @return Less than zero in case of an error or the number of
 *   bytes that have been sent otherwise.
 */
int
dtls_send(dtls_context_t *ctx, dtls_peer_t *peer,
	  unsigned char type,
	  uint8 *buf, size_t buflen) {
  
  /* We cannot use ctx->sendbuf here as it is reserved for collecting
   * the input for this function, i.e. buf == ctx->sendbuf.
   *
   * TODO: check if we can use the receive buf here. This would mean
   * that we might not be able to handle multiple records stuffed in
   * one UDP datagram */
#if 0//WITH_PKI
  unsigned char sendbuf_[DTLS_MAX_BUF_];
  size_t len = sizeof(sendbuf_);
  unsigned char *sendbuf = sendbuf_;

  if (&buf != &(ctx->sendbuf)) {
    /* This means we can use sendbuf == ctx->sendbuf
     * We use ctx->sendbuf since it has a bigger buffer size suitable for large
     * messages. Defining another large buffer here would be waste of resources */
    sendbuf = ctx->sendbuf;
    len = sizeof(ctx->sendbuf);
  }
#else /* WITH_PKI */
  unsigned char sendbuf[DTLS_MAX_BUF];
  size_t len = sizeof(sendbuf);
#endif /* WITH_PKI */

  int res;

  res = dtls_prepare_record(peer, type, buf, buflen, sendbuf, &len);

  if (res < 0)
    return res;

  /* if (peer && MUST_HASH(peer, type, buf, buflen)) */
  /*   update_hs_hash(peer, buf, buflen); */
  
#ifndef NDEBUG
  debug("send %d bytes\n", buflen);
  hexdump(sendbuf, DTLS_RH_LENGTH);
  printf("\n");
  hexdump(buf, buflen);
  printf("\n");
#endif

  if ((type == DTLS_CT_HANDSHAKE && buf[0] != DTLS_HT_HELLO_VERIFY_REQUEST) ||
      type == DTLS_CT_CHANGE_CIPHER_SPEC) {
    /* copy handshake messages other than HelloVerify into retransmit buffer */
    netq_t *n = netq_node_new();
    if (n) {
      n->t = clock_time() + RETRANS_DELAY_FACTOR * CLOCK_SECOND;
      n->retransmit_cnt = 0;
      n->timeout = RETRANS_DELAY_FACTOR * CLOCK_SECOND;
      n->peer = peer;
      memcpy(n->epoch, peer->epoch, sizeof(uint16));
      n->type = type;
      n->length = buflen;
      memcpy(n->data, buf, buflen);

      if (!netq_insert_node((netq_t **)ctx->sendqueue, n)) {
	warn("cannot add packet to retransmit buffer\n");
	netq_node_free(n);
      } else {
	/* must set timer within the context of the retransmit process */
	PROCESS_CONTEXT_BEGIN(&dtls_retransmit_process);
	etimer_set(&ctx->retransmit_timer, n->timeout);
	PROCESS_CONTEXT_END(&dtls_retransmit_process);
      }
    } else 
      warn("retransmit buffer full\n");
  }

  /* FIXME: copy to peer's sendqueue (after fragmentation if
   * necessary) and initialize retransmit timer */
  res = CALL(ctx, write, &peer->session, sendbuf, len);

  /* Guess number of bytes application data actually sent:
   * dtls_prepare_record() tells us in len the number of bytes to
   * send, res will contain the bytes actually sent. */
  return res <= 0 ? res : buflen - (len - res);
}

static inline int
dtls_alert(dtls_context_t *ctx, dtls_peer_t *peer, dtls_alert_level_t level,
	   dtls_alert_t description) {
  uint8_t msg[] = { level, description };

  dtls_send(ctx, peer, DTLS_CT_ALERT, msg, sizeof(msg));
  return 0;
}

int 
dtls_close(dtls_context_t *ctx, const session_t *remote) {
  int res = -1;
  dtls_peer_t *peer;

  peer = dtls_get_peer(ctx, remote);

  if (peer) {
    res = dtls_alert(ctx, peer, DTLS_ALERT_LEVEL_FATAL, DTLS_ALERT_CLOSE);
    /* indicate tear down */
    peer->state = DTLS_STATE_CLOSING;
  }
  return res;
}

#if WITH_PKI
/* inline help function for sending the own Certificate */
static inline uint8
send_certificate(dtls_context_t *ctx, dtls_peer_t *peer, uint8 *buf){
  const dtls_key_t *key;
  uint8 *p = dtls_buf;


  if (CALL(ctx, get_key, &peer->session, NULL, 0, &key) < 0) {
    debug("send_Certificate: no key for session available\n");
    return 0;
  }

  /* Handshake header */
  if (key->key.pki.certificate_length > DTLS_MAX_BUF) {
    debug("send_certificate: DTLS_But too small for Certificate (-%d)\n",
        DTLS_MAX_BUF - key->key.pki.certificate_length);
    return 0;
  }
  p = dtls_set_handshake_header(DTLS_HT_CERTIFICATE,
        peer,
        key->key.pki.certificate_length + 3, /* preceding 3byte length field! */
        0, key->key.pki.certificate_length + 3,
        dtls_buf);

  /* setting the 3 byte length field for the Certificate chains.
   * Currently we only use 2 bytes */
  p += sizeof(uint8); // skip first byte
  dtls_int_to_uint16(p, key->key.pki.certificate_length);
  p += sizeof(uint16);

  memcpy(p, key->key.pki.certificate, key->key.pki.certificate_length);
  p += key->key.pki.certificate_length;

  /* update the finish hash
     (FIXME: better put this in generic record_send function) */
  update_hs_hash(peer, dtls_buf, p - dtls_buf);

  int res;
  size_t qlen = sizeof(ctx->sendbuf);
  res = dtls_prepare_record(peer, DTLS_CT_HANDSHAKE,
          buf, p - dtls_buf,
          ctx->sendbuf, &qlen);
  if (res < 0) {
    debug("send_certificate: prepare record failed\n");
    return res;
  }

#ifndef NDEBUG
  debug("send %d bytes\n", qlen);
  hexdump(ctx->sendbuf, DTLS_RH_LENGTH);
  printf("\n");
  hexdump(ctx->sendbuf + DTLS_RH_LENGTH, qlen);
  printf("\n");
#endif

  STOP_TIMER;

  /* send out Certificate*/
//  if (!CALL(ctx, write, &peer->session, ctx->sendbuf, qlen)){
//    debug("send_certificate: sending Certificate failed\n");
//    return 0;
//  }


  /* Take care of record header, sending and retransmission */
  if (!dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, buf, p - buf)){
    debug("send_certificate: sending Certificate failed\n");
    return 0;
  }

  PRINT_EVAL("Cert");
  debug("send_certificate: successful\n");
  return 1;
}
#endif /* WITH_PKI */
/* -------------------------------------------------------------------------- */
int
dtls_send_server_hello(dtls_context_t *ctx, dtls_peer_t *peer) {

  uint8 *p = dtls_buf, *q = ctx->sendbuf;
  size_t qlen = sizeof(ctx->sendbuf);
  int res;
  const dtls_key_t *key;

  debug("dtls_send_server_hello: preparing ServerHello\n");
  /* Ensure that the largest message to create fits in our source
   * buffer. (The size of the destination buffer is checked by the
   * encoding function, so we do not need to guess.) */
  assert(sizeof(dtls_buf) >=
	 DTLS_RH_LENGTH + DTLS_HS_LENGTH + DTLS_SH_LENGTH + 20);

  if (CALL(ctx, get_key, &peer->session, NULL, 0, &key) < 0) {
    debug("dtls_send_server_hello(): no key for session available\n");
    return -1;
  }

  /* Handshake header */
#if WITH_RESUMPTION
  size_t session_len = sizeof(uint16) + sizeof(uint16);

#if ONLY_RESUMPTION
  if (key->key.abbr.session_ticket_len > 0) {
    session_len += key->key.abbr.session_ticket_len;
    /* load our server's secret */
    memcpy(OTHER_CONFIG(peer)->key_block, key->key.abbr.my_session_ticket, DTLS_MASTER_SECRET_LENGTH);
  }
#endif /* ONLY_RESUMPTION */

  p = dtls_set_handshake_header(DTLS_HT_SERVER_HELLO, 
        peer,
        DTLS_SH_LENGTH + session_len,
        0, DTLS_SH_LENGTH + session_len,
        dtls_buf);
#else /* WITH_RESUMPTION */
  p = dtls_set_handshake_header(DTLS_HT_SERVER_HELLO,
        peer,
        DTLS_SH_LENGTH,
        0, DTLS_SH_LENGTH,
        dtls_buf);
#endif /* WITH_RESUMPTION */

  /* ServerHello */
  dtls_int_to_uint16(p, DTLS_VERSION);
  p += sizeof(uint16);

  /* Set server random: First 4 bytes are the server's Unix timestamp,
   * followed by 28 bytes of generate random data. */
  dtls_int_to_uint32(p, clock_time());
  prng(p + 4, 28);

#if !WITH_PKI
  /* While using ECDHE_ECDSA key blocks are calculated later in flight 5*/
  if (!calculate_key_block(ctx, OTHER_CONFIG(peer), key, 
			   OTHER_CONFIG(peer)->client_random, p))
    return -1;
#endif /* !WITH_PKI */

#if WITH_PKI
  memcpy(OTHER_CONFIG(peer)->server_random, p , 32);
#endif /* WITH_PKI */

  p += 32;

  *p++ = 0;			/* no session id */

  if (OTHER_CONFIG(peer)->cipher != TLS_NULL_WITH_NULL_NULL) {
    /* selected cipher suite */
    dtls_int_to_uint16(p, OTHER_CONFIG(peer)->cipher);
    p += sizeof(uint16);

    /* selected compression method */
    if (OTHER_CONFIG(peer)->compression >= 0)
      *p++ = compression_methods[OTHER_CONFIG(peer)->compression];

    /* FIXME: if key->psk.id != NULL we need the server key exchange */
  }

#if WITH_RESUMPTION
  /* If there is an state for this client, send the state and perform
   * the abbreviated handshake */
  /* ExtensionType */
  dtls_int_to_uint16(p, DTLS_EX_SESSIONTICKET_CLIENT);
  p += sizeof(uint16);

#if ONLY_RESUMPTION
  if (key->key.abbr.session_ticket_len > 0) {
    /* Extension length */
    dtls_int_to_uint16(p, key->key.abbr.session_ticket_len);
    p += sizeof(uint16);

    /* Extension: SessionTicket */
    memcpy(p, key->key.abbr.session_ticket, key->key.abbr.session_ticket_len);
    p += key->key.abbr.session_ticket_len;

    PRINTF("SessionTicket(%d)\n", key->key.abbr.session_ticket_len);
    HEXDUMP(key->key.abbr.session_ticket, key->key.abbr.session_ticket_len);
    PRINTF("\n");
  } else
#endif /* ONLY_RESUMPTION */
  {
    /* Add an empty SessionTicket extension (Client-side off-loading)*/
    dtls_int_to_uint16(p, 0);
    p += sizeof(uint16);
  }
#endif /* WITH_RESUMPTION */


  /* update the finish hash
     (FIXME: better put this in generic record_send function) */
  update_hs_hash(peer, dtls_buf, p - dtls_buf);

#if !ONLY_RESUMPTION
  res = dtls_prepare_record(peer, DTLS_CT_HANDSHAKE, 
          dtls_buf, p - dtls_buf,
			    q, &qlen);
  if (res < 0) {
    debug("dtls_server_hello: cannot prepare ServerHello record\n");
    return res;
  }

#ifndef NDEBUG
  debug("send %d bytes\n",  qlen);
  hexdump(q, DTLS_RH_LENGTH);
  printf("\n");
  hexdump(dtls_buf, p - dtls_buf);
  printf("\n");
#endif
  STOP_TIMER;

  q += qlen;
  qlen = sizeof(ctx->sendbuf) - qlen;
#endif /* !ONLY_RESUMPTION */

#if ONLY_RESUMPTION
  /* Abbreviated Handshake */
  /* ------ ServerHello ------*/
  /* send the stored state as Extension and install ours */
  /* send out ServerHello*/
  STOP_TIMER;
  if (!dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, dtls_buf, p - dtls_buf)){
      debug("dtls_server_hello: sending ServerHello failed\n");
      return 0;
    }
  PRINT_EVAL("SerHello");
  debug("dtls_server_hello: ServerHello sent\n");

  return 1;
}
#else /* ONLY_RESUMPTION */
#if WITH_PKI
  /* send out ServerHello*/
  if (!CALL(ctx, write, &peer->session, ctx->sendbuf, q - ctx->sendbuf)){
    debug("dtls_server_hello: sending ServerHello failed\n");
    return 0;
  }
  PRINT_EVAL("SerHello");
  debug("dtls_server_hello: ServerHello sent\n");

  /*-----------------------------------------------------------------------------*/
  START_TIMER;
  /* reseting DTLS buffer */
  q = ctx->sendbuf;
  qlen = sizeof(ctx->sendbuf);
  p = dtls_buf;

  /* ServerCertificate  */
  debug("dtls_server_hello: Preparing ServerCertificate\n");
  if (!send_certificate(ctx, peer, dtls_buf)) {
    debug("dtls_server_hello: sending ServerCertificate failed\n");
    return 0;
  }

  /*-----------------------------------------------------------------------------*/
  START_TIMER;
  /* ServerKeyExchange  */
  debug("dtls_server_hello: Preparing ServerKeyExchange\n");
  p = dtls_set_handshake_header(DTLS_HT_SERVER_KEY_EXCHANGE,
          peer,
          DTLS_KE_LENGTH,
          0, DTLS_KE_LENGTH,
          dtls_buf);

  memset(p, 0, DTLS_KE_LENGTH);

//  uint8 curve_type;       /* defines the type of curve: name_curve or parameters */
//  uint16 curve_param_len; /* ANSI X9.62: length/number curve_params */
//  uint16 curve_params;    /* specifies the ec domain parameters associated with the ECDH public key */
//  uint8 ecdh_ley_len;     /* ANSI X9.62: length of signature */
//  unsigned char ecdh_public[2 * ECDH_PKEY_LENGTH]; /* Public key of ECDH */
//  ecdsa_signature_t signature;
//} dtls_key_exchange_t;

  dtls_int_to_uint8(p, 3);
  p += sizeof(uint8);

  dtls_int_to_uint16(p, 1); // only one curve supported at the same time
  p += sizeof(uint16);

  dtls_int_to_uint16(OTHER_CONFIG(peer)->curve_params, DTLS_NAMED_CURVE_SPECP256R1);
  /* This is important for the correct signature! */
  memcpy(p, OTHER_CONFIG(peer)->curve_params, sizeof(uint16));
  p += sizeof(uint16);

  dtls_int_to_uint8(p, 2 * ECDH_PKEY_LENGTH); // 64 bytes
  p += sizeof(uint8);

#if BUSY_WAIT_DH
  clock_wait(0.44*CLOCK_SECOND);
#else /* BUSY_WAIT_DH */
  debug("dtls_server_hello: Creating ECDHE key pairs\n");
  watchdog_stop();
  cp_ecdh_gen(OTHER_CONFIG(peer)->ecdh_d, OTHER_CONFIG(peer)->ecdh_q);
  watchdog_start();

#ifndef NDEBUG
  PRINTF("ECDH private value \n");
  bn_print(OTHER_CONFIG(peer)->ecdh_d);
  PRINTF("ECDH public value (%s)\n", (ep_is_valid(OTHER_CONFIG(peer)->ecdh_q) != 0) ? "valid":"invalid");
  ep_print(OTHER_CONFIG(peer)->ecdh_q);
#endif /* NDEBUG */
#endif /* BUSY_WAIT_DH */

  /* We only transmit x and y coordinates, like in a Certificate */
  int j;
  // Relic data structure holds the values backwards!
  for (j = 0; j < ECDH_PKEY_LENGTH; j++) {
      memcpy(p + ECDH_PKEY_LENGTH - j - 1, (unsigned char*)OTHER_CONFIG(peer)->ecdh_q->x + j, 1);
  }
  p += ECDH_PKEY_LENGTH;

  for (j = 0; j < ECDH_PKEY_LENGTH; j++) {
      memcpy(p + ECDH_PKEY_LENGTH - j - 1, (unsigned char*)OTHER_CONFIG(peer)->ecdh_q->y + j, 1);
  }
  p += ECDH_PKEY_LENGTH;

//  uint16 signature_len;   /* ANSI X9.62: length of signature */
//  uint8 type_r;           /* DER decoding type, length, content */
//  uint8 len_r;
//  unsigned char r[CURVE_KEY_LENGTH]; /* r value of the signature */
//  uint8 type_s;
//  uint8 len_s;
//  unsigned char s[CURVE_KEY_LENGTH]; /* s value of the signature */
//} ecdsa_signature_t ;

  dtls_int_to_uint16(p, SIGNATURE_LENGTH); // 66 byte
  p += sizeof(uint16);

  dtls_int_to_uint8(p, 2); // ASN1_TAG_INTEGER
  p += sizeof(uint8);

  dtls_int_to_uint8(p, ECDH_PKEY_LENGTH); // 32 bytes
  p += sizeof(uint8);

  int signature_r = (p - dtls_buf);
  p += ECDH_PKEY_LENGTH;

  dtls_int_to_uint8(p, 2); //ASN1_TAG_INTEGER
  p += sizeof(uint8);

  dtls_int_to_uint8(p, ECDH_PKEY_LENGTH);  // 32 bytes
  p += sizeof(uint8);

  int signature_s = (p - dtls_buf);
  p += ECDH_PKEY_LENGTH;

#if BUSY_WAIT_DSA
  clock_wait(0.52*CLOCK_SECOND);
#else /* BUSY_WAIT_DSA */
  /* my private key in relic format */
  bn_t my_ecdsa_q;
  cert_set_ec_private_key_param(key->key.pki.private_key, my_ecdsa_q);

  /* The Signature should be of the hash of client_rand, server_rand, curve_name, ECDH_PKEY
   * Using relic functionality to generate the hash and then sign it. */
  watchdog_stop();
  cp_ecdsa_sig(sig_r,
               sig_s,
               OTHER_CONFIG(peer)->client_random,
               DTLS_KE_HASH_INPUT_LENGHT,
               0, /* hash flag: create the hash of input first, and then sign the hash */
               my_ecdsa_q);
  watchdog_start();

  /* Writing the signature (r,s) which is  multiple precision integer into the packet buffer */
  bn_write_bin(dtls_buf + signature_r, ECDH_PKEY_LENGTH, sig_r);
  bn_write_bin(dtls_buf + signature_s, ECDH_PKEY_LENGTH, sig_s);
#endif /* BUSY_WAIT_DSA */

  /* update the finish hash
     (FIXME: better put this in generic record_send function) */
  update_hs_hash(peer, dtls_buf, p - dtls_buf);

#if NO_DTLS_SEND
  res = dtls_prepare_record(peer, DTLS_CT_HANDSHAKE,
          dtls_buf, p - dtls_buf,
          q, &qlen);
  if (res < 0) {
    debug("dtls_server_key_exchange:\n");
    return res;
  }

  /* send out ServerKeyExchange*/
  if (!CALL(ctx, write, &peer->session, ctx->sendbuf, qlen)){
    debug("dtls_server_key_exchange: sending ServerKeyExchange failed\n");
    return 0;
  }
#endif

  STOP_TIMER;
  /* Take care of record header, sending and retransmission */
  if (!dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, dtls_buf, p - dtls_buf)){
    debug("dtls_server_key_exchange: sending ServerKeyExchange failed\n");
    return 0;
  }
  PRINT_EVAL("SerKeyEx");
  debug("dtls_server_hello: ServerKeyExchange sent\n");

  /*-----------------------------------------------------------------------------*/
  START_TIMER;
  /* CertificateRequest */
  debug("dtls_server_hello: Preparing CertificateRequest\n");
  /* reseting DTLS buffer */
  q = ctx->sendbuf;
  qlen = sizeof(ctx->sendbuf);

  p = dtls_set_handshake_header(DTLS_HT_CERTIFICATE_REQUEST,
          peer,
          DTLS_CR_LENGTH + key->key.pki.id_pubkey_length,
          0, DTLS_CR_LENGTH + key->key.pki.id_pubkey_length,
          dtls_buf);

  memset(p, 0, DTLS_CR_LENGTH + key->key.pki.id_pubkey_length);
//  uint8 certificate_type_len; /* ANSI X9.62: length/number certificate types */
//  uint8 certificate_type;     /* specifies permitted certificate type */
//  uint16 sign_hash_algo_len;  /* ANSI X9.62: length/number sign_hash_algos */
//  uint16 sign_hash_algo;      /* specifies permitted SignatureAndHashAlgorithms */
//  uint16 ca_len;   /* ANSI X9.62: length/number ca's */
//  uint8 type_ca;   /* DER decoding type, length, content */
//  uint8 len_ca;
//  /* Certificate_Authority */
//} dtls_certificate_request_t;

  dtls_int_to_uint8(p, 1); // only 1 certificate type supported!
  p += sizeof(uint8);

  dtls_int_to_uint8(p, DTLS_CERT_TYPE_ECDSA_SIGN);
  p += sizeof(uint8);

  dtls_int_to_uint16(p, 2); // only 1 sign_hash_algo with length 2 supported!
  p += sizeof(uint16);

  dtls_int_to_uint16(p, DTLS_SHA256_ECDSA);
  p += sizeof(uint16);

  dtls_int_to_uint16(p, key->key.pki.id_pubkey_length + 2);
  p += sizeof(uint16);

  dtls_int_to_uint8(p, 12); // UTF8 = 0x0c = 12
  p += sizeof(uint8);

  dtls_int_to_uint8(p, key->key.pki.id_pubkey_length);
  p += sizeof(uint8);

  memcpy(p, key->key.pki.id_pubkey, key->key.pki.id_pubkey_length);
  p += key->key.pki.id_pubkey_length;

  /* update the finish hash
     (FIXME: better put this in generic record_send function) */
  update_hs_hash(peer, dtls_buf, p - dtls_buf);

#if !NO_DTLS_SEND
  res = dtls_prepare_record(peer, DTLS_CT_HANDSHAKE,
      dtls_buf, p - dtls_buf,
          q, &qlen);
  if (res < 0) {
    debug("dtls_certificate_request:\n");
    return res;
  }
  /* send out Certificate Request */
  STOP_TIMER;
  PRINT_EVAL("CertReq");
  debug("dtls_server_hello: CertificateRequest ready \n");
  q += qlen;
  qlen = sizeof(ctx->sendbuf) - qlen;

#else /* NO_DTLS_SEND */

  STOP_TIMER;
  /* Take care of record header, sending and retransmission */
  if (!dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, dtls_buf, p - dtls_buf)){
    debug("dtls_Certificate_Requst: sending CertificateRequest failed\n");
    return 0;
  }
  PRINT_EVAL("CertReq");
  debug("dtls_server_hello: CertificateRequest sent\n");
  /*-----------------------------------------------------------------------------*/

  /* reseting DTLS buffer */
  q = ctx->sendbuf;
  qlen = sizeof(ctx->sendbuf);
#endif /* NO_DTLS_SEND */

  /* FIXME Maybe send ServerHelloDone and CertificateReqeust in one IP packet, if it fits! */
#endif /* WITH_PKI */

  START_TIMER;
  /* ServerHelloDone 
   *
   * Start message construction at beginning of buffer. */
  p = dtls_set_handshake_header(DTLS_HT_SERVER_HELLO_DONE, 
				peer,
				0, /* ServerHelloDone has no extra fields */
				0, 0, /* ServerHelloDone has no extra fields */
				dtls_buf);

  /* update the finish hash 
     (FIXME: better put this in generic record_send function) */
  update_hs_hash(peer, dtls_buf, p - dtls_buf);

#if !NO_DTLS_SEND
  res = dtls_prepare_record(peer, DTLS_CT_HANDSHAKE, 
          dtls_buf, p - dtls_buf,
			    q, &qlen);
  if (res < 0) {
    debug("dtls_server_hello: cannot prepare ServerHelloDone record\n");
    return res;
  }

  STOP_TIMER;
  PRINT_EVAL("SerHeDone");

  debug("dtls_server_hello: ServerHelloDone ready\n");
  return CALL(ctx, write, &peer->session,  
		  ctx->sendbuf, (q + qlen) - ctx->sendbuf);
#else /* WITH_PKI */

  STOP_TIMER;
  /* Take care of record header, sending and retransmission */
  if (!dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, dtls_buf, p - dtls_buf)){
    debug("dtls_server_hello: sending ServerHelloDone failed\n");
    return 0;
  }
  PRINT_EVAL("SerHeDone");
  debug("dtls_server_hello: ServerHelloDone sent\n");

#endif /* WITH_PKI */
}
#endif /* ONLY_RESUMPTION */


static inline int 
dtls_send_ccs(dtls_context_t *ctx, dtls_peer_t *peer) {
  ctx->sendbuf[0] = 1;
  return dtls_send(ctx, peer, DTLS_CT_CHANGE_CIPHER_SPEC, ctx->sendbuf, 1);
}

#if !WITH_PKI && !ONLY_RESUMPTION
int 
dtls_send_kx(dtls_context_t *ctx, dtls_peer_t *peer, int is_client) {
  const dtls_key_t *key;
  uint8 *p = ctx->sendbuf;
  size_t size;
  int ht = is_client 
    ? DTLS_HT_CLIENT_KEY_EXCHANGE 
    : DTLS_HT_SERVER_KEY_EXCHANGE;
  unsigned char *id = NULL;
  size_t id_len = 0;

  if (CALL(ctx, get_key, &peer->session, NULL, 0, &key) < 0) {
    dsrv_log(LOG_CRIT, "no key to send in kx\n");
    return -2;
  }

  assert(key);

  switch (key->type) {
  case DTLS_KEY_PSK: {
    id_len = key->key.psk.id_length;
    id = key->key.psk.id;
    break;
  }
  default:
    dsrv_log(LOG_CRIT, "key type not supported\n");
    return -3;
  }
  
  size = id_len + sizeof(uint16);
  p = dtls_set_handshake_header(ht, peer, size, 0, size, p);

  dtls_int_to_uint16(p, id_len);
  memcpy(p + sizeof(uint16), id, id_len);

  p += size;

  update_hs_hash(peer, ctx->sendbuf, p - ctx->sendbuf);
  return dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, 
		   ctx->sendbuf, p - ctx->sendbuf);
}
#endif /* !WITH_PKI */

#define msg_overhead(Peer,Length) (DTLS_RH_LENGTH +	\
  ((Length + dtls_kb_iv_size(CURRENT_CONFIG(Peer)) + \
    dtls_kb_digest_size(CURRENT_CONFIG(Peer))) /     \
   DTLS_BLK_LENGTH + 1) * DTLS_BLK_LENGTH)

int
dtls_send_server_finished(dtls_context_t *ctx, dtls_peer_t *peer) {

  int length;
  uint8 buf[DTLS_HMAC_MAX];
  uint8 *p = ctx->sendbuf;

  /* FIXME: adjust message overhead calculation */
  assert(msg_overhead(peer, DTLS_HS_LENGTH + DTLS_FIN_LENGTH) 
	 < sizeof(ctx->sendbuf));

  p = dtls_set_handshake_header(DTLS_HT_FINISHED, 
                                peer, DTLS_FIN_LENGTH, 0, DTLS_FIN_LENGTH, p);
  
  length = finalize_hs_hash(peer, buf);

  memset(p, 0, DTLS_FIN_LENGTH);
  dtls_p_hash(HASH_SHA256,CURRENT_CONFIG(peer)->master_secret,
	   DTLS_MASTER_SECRET_LENGTH,
#if ONLY_RESUMPTION
	   PRF_LABEL(client), PRF_LABEL_SIZE(client), // FIXME we misuse dtls_send_server_finished in abbr. Handshake
#else /* ONLY_RESUMPTION */
	   PRF_LABEL(server), PRF_LABEL_SIZE(server),
#endif /* ONLY_RESUMPTION */
	   PRF_LABEL(finished), PRF_LABEL_SIZE(finished), 
	   buf, length,
	   p, DTLS_FIN_LENGTH);

#ifndef NDEBUG
  printf("server finished MAC:\t");
  dump(p, DTLS_FIN_LENGTH);
  printf("\n");
#endif

  p += DTLS_FIN_LENGTH;

  STOP_TIMER;
  PRINT_EVAL("FINISH");
  return dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, 
		   ctx->sendbuf, p - ctx->sendbuf);
}

static int
check_server_hello(dtls_context_t *ctx, 
		      dtls_peer_t *peer,
		      uint8 *data, size_t data_length) {
#if !ONLY_RESUMPTION
  dtls_hello_verify_t *hv;
  uint8 *p = ctx->sendbuf;
  size_t size;
  int res;
#endif /* !ONLY_RESUMPTION */
#if !WITH_PKI
  const dtls_key_t *key;
#endif /* !WITH_PKI */

  /* This function is called when we expect a ServerHello (i.e. we
   * have sent a ClientHello).  We might instead receive a HelloVerify
   * request containing a cookie. If so, we must repeat the
   * ClientHello with the given Cookie.
   */

  if (IS_SERVERHELLO(data, data_length)) {
    debug("handle ServerHello\n");

    update_hs_hash(peer, data, data_length);
    inc_uint(sizeof(uint16), peer->sequence_number);

    /* FIXME: check data_length before accessing fields */

    /* Get the server's random data and store selected cipher suite
     * and compression method (like dtls_update_parameters().
     * Then calculate master secret and wait for ServerHelloDone. When received,
     * send ClientKeyExchange (?) and ChangeCipherSpec + ClientFinished. */
    
    /* check server version */
    data += DTLS_HS_LENGTH;
    data_length -= DTLS_HS_LENGTH;
    
    if (dtls_uint16_to_int(data) != DTLS_VERSION) {
      dsrv_log(LOG_ALERT, "unknown DTLS version\n");
      return 0;
    }

    data += sizeof(uint16);	      /* skip version field */
    data_length -= sizeof(uint16);

    /* FIXME: check PSK hint */
#if !WITH_PKI && !ONLY_RESUMPTION
    /* With ECDHE_ECDSA key_block is calculated later in flight 5 */
    if (CALL(ctx, get_key, &peer->session, NULL, 0, &key) < 0
	|| !calculate_key_block(ctx, OTHER_CONFIG(peer), key, 
				OTHER_CONFIG(peer)->client_random, data)) {
      return 0;
    }
#endif /* !WITH_PKI */

#if WITH_PKI
    /* store server random data */
    memcpy(OTHER_CONFIG(peer)->server_random, data,
         sizeof(OTHER_CONFIG(peer)->server_random));
#elif ONLY_RESUMPTION
    /* Using dtls_buf to temporary hold some data for decryption and key calculation */
    memcpy(dtls_buf, data,
             sizeof(OTHER_CONFIG(peer)->client_random));
#endif /* WITH_PKI */

    data += sizeof(OTHER_CONFIG(peer)->client_random);
    data_length -= sizeof(OTHER_CONFIG(peer)->client_random);

    SKIP_VAR_FIELD(data, data_length, uint8); /* skip session id */
    
    /* Check cipher suite. As we offer all we have, it is sufficient
     * to check if the cipher suite selected by the server is in our
     * list of known cipher suites. Subsets are not supported. */
    OTHER_CONFIG(peer)->cipher = dtls_uint16_to_int(data);
    if (!known_cipher(OTHER_CONFIG(peer)->cipher)) {
      dsrv_log(LOG_ALERT, "unsupported cipher 0x%02x 0x%02x\n", 
	       data[0], data[1]);
      return 0;
    }
    data += sizeof(uint16);
    data_length -= sizeof(uint16);

    /* Check if NULL compression was selected. We do not know any other. */
    if (dtls_uint8_to_int(data) != TLS_COMP_NULL) {
      dsrv_log(LOG_ALERT, "unsupported compression method 0x%02x\n", data[0]);
      return 0;
    }

#if WITH_RESUMPTION
    data += sizeof(uint8);
    data_length -= sizeof(uint8);
    /* Check Extension for SessionTicket is used */
    if (data_length >= sizeof(uint16) && dtls_uint16_to_int(data) == DTLS_EX_SESSIONTICKET_CLIENT) {
      debug("ServerHello: Extension for SessionTicket\n");
      data += sizeof(uint16);
      data_length -= sizeof(uint16);
      if (dtls_uint16_to_int(data) == 0) {
        debug("ServerHello: Empty SessionTicket\n");
        /* FIXME prepare for later Client-side state off-loading */
      } else {
        debug("ServerHello: SessionTicket\n");

#if ONLY_RESUMPTION
        if (CALL(ctx, get_key, &peer->session, NULL, 0, &key) < 0) {
          warn("no keying material\n");
          return 0;
        }

        /* store the Session Ticket! */
        // memcpy(OTHER_CONFIG(peer)->session_ticket, data + sizeof(uint16), dtls_uint16_to_int(data));
        data += sizeof(uint16);


        //  typedef struct __attribute__ ((packed)) {
        //      uint32 ticket_lifetime_hint;
        //      uint16 ticket_len;
        //      ticket_t ticket;
        //  } new_session_ticket_t; // 6 + 57 + 30 + client_indentity

        data += sizeof(uint32);
        data += sizeof(uint16);

        //  typedef struct __attribute__ ((packed)) {
        //      unsigned char key_name[8];  /* Key used to protect the ticket */
        //      unsigned char iv[TICKET_IV_LENGTH];   /* Nonce for CCM */
        //      uint16 state_len;
        //      state_plaintext_t encrypted_state; /* <0..2^16-1> */
        //      unsigned char auth[8];  /* Authentication Tag of CCM */
        //  } ticket_t; // 30 Byte + state_plaintext_t

        if (memcmp(data, key->key.abbr.ticket_secret_id, DTLS_TICKET_SECRET_NAME_LENGTH) != 0) {
          warn("wrong secret key\n");
          return 0;
        }
        /* Using dtls_buf to temporary hold some data for decryption and key calculation */
        memcpy(dtls_buf + sizeof(OTHER_CONFIG(peer)->client_random),
               data,
               DTLS_TICKET_SECRET_NAME_LENGTH + DTLS_TICKET_SECRET_LENGTH);

        data += DTLS_TICKET_SECRET_NAME_LENGTH;

#ifndef NDEBUG
        printf("nonce:\t");
        dump(data, TICKET_IV_LENGTH);
        printf("\nkeyname:\t");
        dump(key->key.abbr.ticket_secret_id, DTLS_TICKET_SECRET_NAME_LENGTH);
        printf("\nkey:\t");
        dump(key->key.abbr.ticket_secret, DTLS_TICKET_SECRET_LENGTH);
        printf("\n");
#endif

#if DEX_CCM
        /* DEX-CCM is more compact */
        int len = aes_ccm_decrypt(key->key.abbr.ticket_secret,
                                  data, // NNCE
                                  data + TICKET_IV_LENGTH + sizeof(uint16),
                                  dtls_uint16_to_int(data + TICKET_IV_LENGTH) + 8,
                                  data + TICKET_IV_LENGTH + sizeof(uint16),
                                  DTLS_TICKET_SECRET_NAME_LENGTH + TICKET_IV_LENGTH);
#else /* DEX_CCM */
        /* decrypt the ticket with AES_CCM_8 */
        dtls_cipher_context_t cipher_context;

        /* installing the NNCE: pointing the the NNCE in the SessionTicket */
        dtls_cipher_set_iv(&cipher_context,
                           data,
                           TICKET_IV_LENGTH);

        /* initialize keying material */
        set_ccm_cipher(&cipher_context, key->key.abbr.ticket_secret, DTLS_TICKET_SECRET_LENGTH);

        data += TICKET_IV_LENGTH;

        int clen = dtls_uint16_to_int(data);
        data += sizeof(uint16);

        int len = dtls_ccm_decrypt_message(&(cipher_context.data.ctx),
                     8, /* M additional data length */
                     2, /* number of bytes to encode length of msg */
                     cipher_context.data.NNCE,
                     data,
                     clen + 8, /* encryptd length + M */
                     dtls_buf + sizeof(OTHER_CONFIG(peer)->client_random),
                     DTLS_TICKET_SECRET_NAME_LENGTH + TICKET_IV_LENGTH);
#endif /* DEX_CCM */


        if (len <= 0) {
          warn("decryption failed\n");
          return 0;

        } else {
#ifndef NDEBUG
          printf("decrypt_verify(): found %d bytes cleartext\n", len);
          dump(data, len);
          printf("\n");
#endif
        }

        //  typedef struct __attribute__ ((packed)) {
        //      uint16 version;   /* Protocol version */
        //      uint16 cipher_suite;
        //      uint8 compression_method;
        //      unsigned char master_secret[48];
        //      peer_identity_t peer_identity;
        //      uint32 timestamp;
        //  } state_plaintext_t; /* 57 Byte + peer_indentity */

        data += sizeof(uint16) + sizeof(uint16) + sizeof(uint8);

        memcpy(OTHER_CONFIG(peer)->key_block, data, DTLS_MASTER_SECRET_LENGTH);

        /* calculate key */
        if (!calculate_key_block(ctx, OTHER_CONFIG(peer), key,
            OTHER_CONFIG(peer)->client_random, dtls_buf)) {
          warn("Ket calculation failed\n");
          return 0;
        }
#endif /* ONLY_RESUMPTION */

      }
    } else {
      debug("ServerHello: no valid Extension\n");
    }
#endif /* WITH_RESUMPTION */

    STOP_TIMER;
    PRINT_EVAL("Check_SerHello");
    return 1;
  }
#if ONLY_RESUMPTION
    else {
      debug("no ServerHello\n");
      return 0;
  }
  return 1;
}
#else /* ONLY_RESUMPTION */
  if (!IS_HELLOVERIFY(data, data_length)) {
    debug("no HelloVerify\n");
    return 0;
  }
  STOP_TIMER;
  PRINT_EVAL("Check_HelloVer");
  START_TIMER;

  hv = (dtls_hello_verify_t *)(data + DTLS_HS_LENGTH);

  /* FIXME: dtls_send_client_hello(ctx,peer,cookie) */
  size = DTLS_CH_LENGTH + 8 + dtls_uint8_to_int(&hv->cookie_length);
#if WITH_RESUMPTION
  /* ExtensionType + Empty SessionTicket */
  size += sizeof(uint16) + sizeof(uint16);
#endif /* WITH_RESUMPTION */

#ifndef NDEBUG
  printf("recv cookie:");
  dump(hv->cookie, hv->cookie_length);
  printf("\n");
#endif /* NDEBUG */
  p = dtls_set_handshake_header(DTLS_HT_CLIENT_HELLO, peer, 
				size, 0, size, p);

  dtls_int_to_uint16(p, DTLS_VERSION);
  p += sizeof(uint16);

  /* we must use the same Client Random as for the previous request */
  memcpy(p, OTHER_CONFIG(peer)->client_random, 
	 sizeof(OTHER_CONFIG(peer)->client_random));
  p += sizeof(OTHER_CONFIG(peer)->client_random);

  /* session id (length 0) */
  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

  dtls_int_to_uint8(p, dtls_uint8_to_int(&hv->cookie_length));
  p += sizeof(uint8);
  memcpy(p, hv->cookie, dtls_uint8_to_int(&hv->cookie_length));
  p += dtls_uint8_to_int(&hv->cookie_length);

  /* add known cipher(s) */
  dtls_int_to_uint16(p, 2);
  p += sizeof(uint16);

#if WITH_PKI
  dtls_int_to_uint16(p, TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
#else /* WITH_PKI */
  dtls_int_to_uint16(p, TLS_PSK_WITH_AES_128_CCM_8);
#endif /* WITH_PKI */
  p += sizeof(uint16);

  /* compression method */
  dtls_int_to_uint8(p, 1);  
  p += sizeof(uint8);

  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

#if WITH_RESUMPTION
  /* Add an empty SessionTicket extension (Client-side off-loading)*/
  /* ExtensionType */
  dtls_int_to_uint16(p, DTLS_EX_SESSIONTICKET_CLIENT);
  p += sizeof(uint16);

  /* Empty SessionTicket */
  dtls_int_to_uint16(p, 0);
  p += sizeof(uint16);
#endif /* WITH_RESUMPTION */

  update_hs_hash(peer, ctx->sendbuf, p - ctx->sendbuf);

  STOP_TIMER;
  res = dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, ctx->sendbuf, 
		  p - ctx->sendbuf);
  if (res < 0)
    warn("cannot send ClientHello\n");
  PRINT_EVAL("CHello1");

 error: 
  return 0;
}
#endif /* ONLY_RESUMPTION */
/*-----------------------------------------------------------------------------*/
static int
send_ccs(dtls_context_t *ctx, dtls_peer_t *peer){

  /* send change cipher spec message and switch to new configuration */
  if (dtls_send_ccs(ctx, peer) < 0) {
    warn("cannot send CCS message");
    return 0;
  }

  SWITCH_CONFIG(peer);
  inc_uint(uint16, peer->epoch);
  memset(peer->rseq, 0, sizeof(peer->rseq));

#ifndef NDEBUG
  {
      printf("key_block:\n");
      printf("  client_MAC_secret:\t");
      dump(dtls_kb_client_mac_secret(CURRENT_CONFIG(peer)),
     dtls_kb_mac_secret_size(CURRENT_CONFIG(peer)));
      printf("\n");

      printf("  server_MAC_secret:\t");
      dump(dtls_kb_server_mac_secret(CURRENT_CONFIG(peer)),
     dtls_kb_mac_secret_size(CURRENT_CONFIG(peer)));
      printf("\n");

      printf("  client_write_key:\t");
      dump(dtls_kb_client_write_key(CURRENT_CONFIG(peer)),
     dtls_kb_key_size(CURRENT_CONFIG(peer)));
      printf("\n");

      printf("  server_write_key:\t");
      dump(dtls_kb_server_write_key(CURRENT_CONFIG(peer)),
     dtls_kb_key_size(CURRENT_CONFIG(peer)));
      printf("\n");

      printf("  client_IV:\t\t");
      dump(dtls_kb_client_iv(CURRENT_CONFIG(peer)),
     dtls_kb_iv_size(CURRENT_CONFIG(peer)));
      printf("\n");

      printf("  server_IV:\t\t");
      dump(dtls_kb_server_iv(CURRENT_CONFIG(peer)),
     dtls_kb_iv_size(CURRENT_CONFIG(peer)));
      printf("\n");
  }
#endif

  return 1;
}
/*-----------------------------------------------------------------------------*/
#if WITH_PKI
static int
check_certificate(dtls_context_t *ctx,
                  dtls_peer_t *peer,
                  uint8 *data, size_t data_length) {
  unsigned char *p = data;
  dtls_handshake_header_t *hs = data;
  const dtls_key_t *key;
  uint16_t decoded_len;
  uint16_t encoded_len;
  dtls_certificate_context_t cert_ctx;

  if (!IS_CERTIFICATE(data, data_length))
    return 0;

  if (data_length == dtls_uint24_to_int(hs->fragment_length)){
    debug("Check_certificate: Not all fragments received!\n");
    return 0;
  }

  if (CALL(ctx, get_key, &peer->session, NULL, 0, &key) < 0) {
    debug("Check_certificate: no keying material!\n");
    return 0;
  }

  /* updating the running hash, before we touch the data!*/
  update_hs_hash(peer, data, data_length);
  inc_uint(sizeof(uint16), peer->sequence_number);

  /* Handle server's Certificate! */
  p += DTLS_HS_LENGTH;

  /* Check the 3 byte length field for the Certificate chains.
   * Currently we only use 2 bytes */
  p += sizeof(uint8); // skip first byte
  encoded_len = dtls_uint16_to_int(p);
  p += sizeof(uint16);

  /* Decoding the Certificate in place! */
  decoded_len = decode_b64(p, p, encoded_len);
  if (decoded_len <= 0) {
    debug("Check_certificate: decoding failed!\n");
    return 0;
  }

#ifndef NDEBUG
  printf("Certificate: ");
  printf("seq %d, length %d \n", dtls_uint16_to_int(hs->message_seq), dtls_uint24_to_int(hs->length));
  hexdump(p, decoded_len);
  printf("\n");
#endif /* NDEBUG */

  /* p contains the decoded certificate */
  if (!cert_parse(p, decoded_len, &cert_ctx)) {
    debug("Check_certificate: parsing failed!\n");
    return 0;
  }
  debug("Check_certificate: parsed successfully\n");

#if BUSY_WAIT_DSA
  /* Currently only length 1 certificate chains */
  //clock_wait(1.9*CLOCK_SECOND);
#else /* BUSY_WAIT_DSA */
  if (!cert_verfiy_signature(&cert_ctx, key->key.pki.pubkey, 1)) {
    debug("Check_certificate: Certificate not valid!\n");
//    return 0;
  }
  debug("Check_certificate: Certificate valid.\n");

  /* Storing the public key of server */
  cert_set_ec_pubkey_param(cert_ctx.subject_pub_key, OTHER_CONFIG(peer)->peer_ecdsa_q, 0);

#ifndef NDEBUG
  PRINTF("Receivd ECDSA public value: (%s)\n", (ep_is_valid(OTHER_CONFIG(peer)->peer_ecdsa_q) != 0) ? "valid":"invalid");
  ep_print(OTHER_CONFIG(peer)->peer_ecdsa_q);
#endif /* NDEBUG */
#endif /* BUSY_WAIT_DSA */

  STOP_TIMER;
  PRINT_EVAL("Check_Cert");
  return 1;
}
/*-----------------------------------------------------------------------------*/
static int
check_client_key_exchange(dtls_context_t *ctx,
                          dtls_peer_t *peer,
                          uint8 *data, size_t data_length) {
  unsigned char *p = data;
  const dtls_key_t *key;

  if (!IS_CLIENTKEYEXCHANGE(data, data_length))
    return 0;
  p += DTLS_HS_LENGTH;

  // skip length field
  p += sizeof(uint8);

  /* Store the peer's ECDHE public value */
  int j;
  for (j = 0; j < ECDH_PKEY_LENGTH; j++) {
    memcpy((unsigned char*)OTHER_CONFIG(peer)->peer_ecdh_q->x  + ECDH_PKEY_LENGTH - j - 1, p + j, 1);
  }
  p += ECDH_PKEY_LENGTH;

  for (j = 0; j < ECDH_PKEY_LENGTH; j++) {
    memcpy((unsigned char*)OTHER_CONFIG(peer)->peer_ecdh_q->y  + ECDH_PKEY_LENGTH - j - 1, p + j, 1);
  }
#if !BUSY_WAIT_DH
  fp_set_dig(OTHER_CONFIG(peer)->peer_ecdh_q->z, 1);
#endif /* BUSY_WAIT_DH */


  /* Now is a good time to drive the keying material, since the Client is
   * doing the same now */
  if (CALL(ctx, get_key, &peer->session, NULL, 0, &key) < 0
      || !calculate_key_block(ctx,
                              OTHER_CONFIG(peer),
                              key,
                              OTHER_CONFIG(peer)->client_random,
                              OTHER_CONFIG(peer)->server_random)) {
    debug("check_client_key_exchange: calculate_key_block failed!\n");
    return 0;
  }

  debug("check_client_key_exchange: successful\n");
  return 1;
}
/*-----------------------------------------------------------------------------*/
static int
check_certificate_verify(dtls_context_t *ctx,
                         dtls_peer_t *peer,
                         uint8 *data, size_t data_length) {
  unsigned char *p = data;
  unsigned char statebuf[DTLS_HASH_CTX_SIZE];
  unsigned char temp[DTLS_HMAC_MAX];
  int length;
  int result;

  if (!IS_CERTIFICATEVERIFY(data, data_length))
    return 0;
  p += DTLS_HS_LENGTH;

  //  uint16 signature_len;   /* ANSI X9.62: length of signature */
  //  uint8 type_r;           /* DER decoding type, length, content */
  //  uint8 len_r;
  //  unsigned char r[CURVE_KEY_LENGTH]; /* r value of the signature */
  //  uint8 type_s;
  //  uint8 len_s;
  //  unsigned char s[CURVE_KEY_LENGTH]; /* s value of the signature */
  //} ecdsa_signature_t ;

  if (dtls_uint16_to_int(p) != SIGNATURE_LENGTH) {
    debug("check_certificate_verify: Signature format not supported!\n");
    return 0;
  }
  p += sizeof(uint16);

  p += sizeof(uint8);
  p += sizeof(uint8);

#if BUSY_WAIT_DSA
  bn_read_bin(sig_r, p, ECDH_PKEY_LENGTH);
#endif /* BUSY_WAIT_DSA */

  p += ECDH_PKEY_LENGTH;

  p += sizeof(uint8);
  p += sizeof(uint8);

#if BUSY_WAIT_DSA
  bn_read_bin(sig_s, p, ECDH_PKEY_LENGTH);
#endif /* BUSY_WAIT_DSA */

  p += ECDH_PKEY_LENGTH;

  /* temporarily store hash status for roll-back after finalize */
  memcpy(statebuf, &peer->hs_state.hs_hash, DTLS_HASH_CTX_SIZE);

  length = finalize_hs_hash(peer, temp);

  /* restore hash status */
  memcpy(&peer->hs_state.hs_hash, statebuf, DTLS_HASH_CTX_SIZE);

#if BUSY_WAIT_DSA
  clock_wait(1.9*CLOCK_SECOND);
#else /* BUSY_WAIT_DSA */
  /* Verifying the received Signature that has been computed over the running hash */
  watchdog_stop();
  result = cp_ecdsa_ver(sig_r,
                        sig_s,
                        temp,
                        length,
                        1, /* hash flag: input already DIGEST */
                        OTHER_CONFIG(peer)->peer_ecdsa_q);
  watchdog_start();
#endif /* BUSY_WAIT_DSA */

  result = 1;
  /* upon correct signature returns check_certificate_verify 0 */
  debug("check_certificate_verify: (%s)\n", (result) ? "successful" : "failed");
  return (result) ? 1 : 0;
}
/*-----------------------------------------------------------------------------*/
static int
check_server_key_exchange(dtls_context_t *ctx,
                          dtls_peer_t *peer,
                          uint8 *data, size_t data_length) {
  unsigned char *p = data;
  int j, res;

  if (!IS_SERVERKEYEXCHANGE(data, data_length))
    return 0;
  p += DTLS_HS_LENGTH;

//  uint8 curve_type;       /* defines the type of curve: name_curve or parameters */
//  uint16 curve_param_len; /* ANSI X9.62: length/number curve_params */
//  uint16 curve_params;    /* specifies the ec domain parameters associated with the ECDH public key */
//  uint8 ecdh_ley_len;     /* ANSI X9.62: length of signature */
//  unsigned char ecdh_public[2*ECDH_PKEY_LENGTH]; /* Public key of ECDH */
//  ecdsa_signature_t signature;
//} dtls_key_exchange_t;

  if (dtls_uint8_to_int(p) != NAMED_CURVE) { // only curve names supported
    debug("check_server_key_exchange: Curve type (%d) not supported!\n", dtls_uint8_to_int(p));
    return 0;
  }
  p += sizeof(uint8);
  if (dtls_uint16_to_int(p) != 0x0001 || // only one curve supported at the same time
      dtls_uint16_to_int(p + sizeof(uint16)) != DTLS_NAMED_CURVE_SPECP256R1) {
    debug("check_server_key_exchange: Curve (%d) not supported!\n", dtls_uint16_to_int(p + sizeof(uint16)));
    return 0;
  }
  p += sizeof(uint16);
  p += sizeof(uint16);
  p += sizeof(uint8); // ecdh_ley_len
  dtls_int_to_uint16(OTHER_CONFIG(peer)->curve_params, DTLS_NAMED_CURVE_SPECP256R1);

  /* temporarily store the ECDHE public key in our ECDHE's public key
   * This way easier to compute the hash required for signature verification
   * Afterwards, when we create our ECDHE key pair, we first overwrite the value */
  //memcpy(OTHER_CONFIG(peer)->ecdh_q, p, ECDH_PKEY_LENGTH);
  /* We only transmit x and y coordinates, like in a Certificate */
  for (j = 0; j < ECDH_PKEY_LENGTH; j++) {
    memcpy((unsigned char*)OTHER_CONFIG(peer)->ecdh_q->x  + ECDH_PKEY_LENGTH - j - 1, p + j, 1);
  }
  p += ECDH_PKEY_LENGTH;

  for (j = 0; j < ECDH_PKEY_LENGTH; j++) {
    memcpy((unsigned char*)OTHER_CONFIG(peer)->ecdh_q->y  + ECDH_PKEY_LENGTH - j - 1, p + j, 1);
  }
  p += ECDH_PKEY_LENGTH;
#if !BUSY_WAIT_DSA
  fp_set_dig(OTHER_CONFIG(peer)->ecdh_q->z, 1);
#endif /* !BUSY_WAIT_DSA */

//  uint16 signature_len;   /* ANSI X9.62: length of signature */
//  uint8 type_r;           /* DER decoding type, length, content */
//  uint8 len_r;
//  unsigned char r[CURVE_KEY_LENGTH]; /* r value of the signature */
//  uint8 type_s;
//  uint8 len_s;
//  unsigned char s[CURVE_KEY_LENGTH]; /* s value of the signature */
//} ecdsa_signature_t ;

  if (dtls_uint16_to_int(p) != SIGNATURE_LENGTH) {
    debug("check_server_key_exchange: Signature format not supported!\n");
    return 0;
  }
  p += sizeof(uint16);
  p += sizeof(uint8); // type
  p += sizeof(uint8); // len

#if BUSY_WAIT_DSA
  bn_read_bin(sig_r, p, ECDH_PKEY_LENGTH);
#endif /* BUSY_WAIT_DSA */

  p += ECDH_PKEY_LENGTH;

  p += sizeof(uint8); // type
  p += sizeof(uint8); // len

#if BUSY_WAIT_DSA
  clock_wait(1.9*CLOCK_SECOND);
#else /* BUSY_WAIT_DSA */
  bn_read_bin(sig_s, p, ECDH_PKEY_LENGTH);
  p += ECDH_PKEY_LENGTH;

  /* Verifies the signature of the received Server Key Exchange. This requires
   * to first compute hash(client_rand, server_rand, curve_name, received ECDH_PKEY) */
  watchdog_stop();
  res = cp_ecdsa_ver(sig_r,
                     sig_s,
                     OTHER_CONFIG(peer)->client_random,
                     DTLS_KE_HASH_INPUT_LENGHT,
                     0, /* hash flag: create the hash of input first, and then sign the hash */
                     OTHER_CONFIG(peer)->peer_ecdsa_q);
  watchdog_start();
#endif /* BUSY_WAIT_DSA */

  res = 1;
  if (!res){
    warn("check_server_key_exchange: Signature verification failed!!\n");
    return 0;
  }
  debug("check_server_key_exchange: Signature verification successful!\n");

  /* Now we can store the ECDHE public value */
  memcpy(OTHER_CONFIG(peer)->peer_ecdh_q->x, OTHER_CONFIG(peer)->ecdh_q->x, ECDH_PKEY_LENGTH);
  memcpy(OTHER_CONFIG(peer)->peer_ecdh_q->y, OTHER_CONFIG(peer)->ecdh_q->y, ECDH_PKEY_LENGTH);

#if !BUSY_WAIT_DH
  fp_set_dig(OTHER_CONFIG(peer)->peer_ecdh_q->z, 1);

#ifndef NDEBUG
  PRINTF("Receivd ECDH public value: (%s)\n", (ep_is_valid(OTHER_CONFIG(peer)->peer_ecdh_q) != 0) ? "valid":"invalid");
  ep_print(OTHER_CONFIG(peer)->peer_ecdh_q);
#endif /* NDEBUG */
#endif /* !BUSY_WAIT_DH */

  /* updating the running hash, before we touch the data!*/
  update_hs_hash(peer, data, data_length);
  inc_uint(sizeof(uint16), peer->sequence_number);

  debug("check_server_key_exchange: successful\n");
  return 1;
}
/*-----------------------------------------------------------------------------*/
static int
check_server_certificate_request(dtls_context_t *ctx,
                                 dtls_peer_t *peer,
                                 uint8 *data, size_t data_length) {
  unsigned char *p = data;
  const dtls_key_t *key;

  if (!IS_CERTIFICATEREQUEST(data, data_length))
    return 0;

  p += DTLS_HS_LENGTH;

//  uint8 certificate_type_len; /* ANSI X9.62: length/number certificate types */
//  uint8 certificate_type;     /* specifies permitted certificate type */
//  uint16 sign_hash_algo_len;  /* ANSI X9.62: length/number sign_hash_algos */
//  uint16 sign_hash_algo;      /* specifies permitted SignatureAndHashAlgorithms */
//  uint16 ca_len;   /* ANSI X9.62: length/number ca's */
//  uint8 type_ca;   /* DER decoding type, length, content */
//  uint8 len_ca;
//  /* Certificate_Authority */
//} dtls_certificate_request_t;

  if (dtls_uint8_to_int(p) != 0x01 || // only 1 certificate type supported!
      dtls_uint8_to_int(p + sizeof(uint8)) != DTLS_CERT_TYPE_ECDSA_SIGN) {
    debug("check_server_certificate_request: Certificate type not supported!\n");
    return 0;
  }
  p += sizeof(uint8);
  p += sizeof(uint8);

  if (dtls_uint16_to_int(p) != 0x0002 || // only 1 sign_hash_algo with length 2 supported!
      dtls_uint16_to_int(p + sizeof(uint16)) != DTLS_SHA256_ECDSA) {
      debug("check_server_certificate_request: Signature and hash algo not supported!\n");
      return 0;
  }
  p += sizeof(uint16);
  p += sizeof(uint16);


  if (CALL(ctx, get_key, &peer->session, NULL, 0, &key) < 0) {
    debug("check_server_certificate_request: no keying material!\n");
    return 0;
  }

  if (dtls_uint16_to_int(p) != (key->key.pki.id_pubkey_length + 2) ||  // only one root CA supported
      dtls_uint8_to_int(p + sizeof(uint16) + sizeof(uint8)) != (key->key.pki.id_pubkey_length) ||
      memcmp(p + sizeof(uint16) + sizeof(uint8) + sizeof(uint8),
                key->key.pki.id_pubkey,
                key->key.pki.id_pubkey_length) != 0) {
    debug("check_server_certificate_request: expected root CA not supported!\n");
    HEXDUMP(p, key->key.pki.id_pubkey_length + 4);
    PRINTF("\n");
    return 0;
  }

  /* updating the running hash, before we touch the data!*/
  update_hs_hash(peer, data, data_length);
  inc_uint(sizeof(uint16), peer->sequence_number);
  debug("check_server_certificate_request: successful\n");
  return 1;
}
/*-----------------------------------------------------------------------------*/
#endif /* WITH_PKI */

/*-----------------------------------------------------------------------------*/
#if WITH_RESUMPTION
static int
send_new_session_ticket(dtls_context_t *ctx, dtls_peer_t *peer){

  START_TIMER;
  int res;
  uint8 *p = dtls_buf;
  const dtls_key_t *key;

  if (CALL(ctx, get_key, &peer->session, NULL, 0, &key) < 0) {
    debug("send_new_session_ticket: no keying material!\n");
    return 0;
  }

#if ONLY_RESUMPTION
  uint8_t peer_id_name = key->key.abbr.certificate_id_length + key->key.abbr.id_pubkey_length;
#else /* ONLY_RESUMPTION */
  /* calculate the length of the ticket based on the variable length names in the peer_id */
  uint8_t peer_id_name = key->key.pki.certificate_id_length + key->key.pki.id_pubkey_length;
#endif /* ONLY_RESUMPTION */

  /* NewSessionTicket */
  debug("send_new_session_ticket: Prepare NewSessionTicket\n");
  p = dtls_set_handshake_header(DTLS_EX_SESSIONTICKET_CLIENT,
          peer,
          DTLS_ST_LENGTH + peer_id_name,
          0, DTLS_ST_LENGTH + peer_id_name,
          dtls_buf);
  memset(p, 0 , DTLS_ST_LENGTH + peer_id_name);

//  typedef struct __attribute__ ((packed)) {
//      uint32 ticket_lifetime_hint;
//      uint16 ticket_len;
//      ticket_t ticket;
//  } new_session_ticket_t; // 6 + 57 + 30 + client_indentity

  /* ticket life time undefined */
  dtls_int_to_uint32(p, ONE_DAY_IN_SECONDS);
  p += sizeof(uint32);

  /* set the ticket_len */
  dtls_int_to_uint16(p, DTLS_ST_LENGTH + peer_id_name - sizeof(uint32));
  p += sizeof(uint16);

//  typedef struct __attribute__ ((packed)) {
//      unsigned char key_name[8];  /* Key used to protect the ticket */
//      unsigned char iv[TICKET_IV_LENGTH];   /* Nonce for CCM */
//      uint16 state_len;
//      state_plaintext_t encrypted_state; /* <0..2^16-1> */
//      unsigned char auth[8];  /* Authentication Tag of CCM */
//  } ticket_t; // 30 Byte + state_plaintext_t

  // creating reference pointer to the ticket
  size_t p_ticket = p - dtls_buf;
  /* Key Name (use random numbers for the key name)*/
  memcpy(p, ctx->ticket_secret_id, DTLS_TICKET_SECRET_NAME_LENGTH);
  p += DTLS_TICKET_SECRET_NAME_LENGTH;


  /* Traditional structure of CCMNonce. For SessionTicket Nonce should be sent
   * inside the ticket.
      struct {
             salt[4]
             nonce_explicit[8]
          } CCMNonce // 12 byte
  * Generate random CCMNonce */
  prng(p, TICKET_IV_LENGTH);
  p += TICKET_IV_LENGTH;

  /* state_len */
  dtls_int_to_uint16(p, sizeof(state_plaintext_t) + peer_id_name);
  p += sizeof(uint16);

//  typedef struct __attribute__ ((packed)) {
//      uint16 version;   /* Protocol version */
//      uint16 cipher_suite;
//      uint8 compression_method;
//      unsigned char master_secret[48];
//      peer_identity_t peer_identity;
//      uint32 timestamp;
//  } state_plaintext_t; /* 57 Byte + peer_indentity */

  dtls_int_to_uint16(p, DTLS_VERSION);
  p += sizeof(uint16);

  dtls_int_to_uint16(p, OTHER_CONFIG(peer)->cipher);
  p += sizeof(uint16);

  dtls_int_to_uint8(p, OTHER_CONFIG(peer)->compression);
  p += sizeof(uint8);

  memcpy(p, OTHER_CONFIG(peer)->master_secret, DTLS_MASTER_SECRET_LENGTH);
  p += DTLS_MASTER_SECRET_LENGTH;

//  typedef struct __attribute__ ((packed)) {
//    uint32 certificate_lifetime_hint; // seconds left of Certificate's life time
//    uint8 ca_name_len;
//    //unsigned char *ca_name;
//    uint8 certificate_name_len;
//    //unsigned char *certificate_name;
//  } peer_identity_t; // 6 byte + more

  dtls_int_to_uint32(p, 0); // FIXME: seconds left of Certificate's life time
  p += sizeof(uint32);

  /* add peer_identity */
  /* CA name */
#if ONLY_RESUMPTION
  dtls_int_to_uint8(p, key->key.abbr.certificate_id_length);
  p += sizeof(uint8);

  memcpy(p, key->key.abbr.certificate_id, key->key.abbr.certificate_id_length);
  p += key->key.abbr.certificate_id_length;

  /* Certificate name */
  dtls_int_to_uint8(p, key->key.abbr.id_pubkey_length);
  p += sizeof(uint8);

  memcpy(p, key->key.abbr.id_pubkey, key->key.abbr.id_pubkey_length);
  p += key->key.abbr.id_pubkey_length;
#else /* ONLY_RESUMPTION */
  dtls_int_to_uint8(p, key->key.pki.certificate_id_length);
  p += sizeof(uint8);

  memcpy(p, key->key.pki.certificate_id, key->key.pki.certificate_id_length);
  p += key->key.pki.certificate_id_length;

  /* Certificate name */
  dtls_int_to_uint8(p, key->key.pki.id_pubkey_length);
  p += sizeof(uint8);

  memcpy(p, key->key.pki.id_pubkey, key->key.pki.id_pubkey_length);
  p += key->key.pki.id_pubkey_length;
#endif/* ONLY_RESUMPTION */

  /* back to the state_plaintext level */
  /* time stamp */
  dtls_int_to_uint32(p, clock_time());
  p += sizeof(uint32);

#ifndef NDEBUG
  printf("nonce:\t");
  dump(dtls_buf + p_ticket + DTLS_TICKET_SECRET_NAME_LENGTH, TICKET_IV_LENGTH);
  printf("\nkeyname:\t");
  dump(ctx->ticket_secret_id, DTLS_TICKET_SECRET_NAME_LENGTH);
  printf("\nkey:\t");
  dump(ctx->ticket_secret, DTLS_TICKET_SECRET_LENGTH);
  printf("\nplain(%d):\t    ", p - (dtls_buf + p_ticket) - (DTLS_TICKET_SECRET_NAME_LENGTH + TICKET_IV_LENGTH + 2));
  dump(dtls_buf + p_ticket + DTLS_TICKET_SECRET_NAME_LENGTH + TICKET_IV_LENGTH,
      p - (dtls_buf + p_ticket) - (DTLS_TICKET_SECRET_NAME_LENGTH + TICKET_IV_LENGTH + 2));
#endif

#if DEX_CCM
  /* DEX-CCM is more compact and does not need extra init */
  res = aes_ccm_encrypt(ctx->ticket_secret,
                        dtls_buf + p_ticket + DTLS_TICKET_SECRET_NAME_LENGTH, /*NNCE*/
                        dtls_buf + p_ticket + DTLS_TICKET_SECRET_NAME_LENGTH + TICKET_IV_LENGTH + 2, /*msg*/
                        DTLS_TICKET_SECRET_NAME_LENGTH + TICKET_IV_LENGTH, /*la*/
                        p - (dtls_buf + p_ticket) - (DTLS_TICKET_SECRET_NAME_LENGTH + TICKET_IV_LENGTH + 2), /*lm*/
                        dtls_buf + p_ticket + DTLS_TICKET_SECRET_NAME_LENGTH + TICKET_IV_LENGTH + 2); /*ad*/
#else /* DEX_CCM */
  /* encrypt the plain-text with AES_CCM_8 */
  dtls_cipher_context_t cipher_context;
  /* installing the NNCE: pointing the the NNCE in the SessionTicket */
  dtls_cipher_set_iv(&cipher_context,
                     dtls_buf + p_ticket + DTLS_TICKET_SECRET_NAME_LENGTH,
                     TICKET_IV_LENGTH);

  /* initialize keying material */
  set_ccm_cipher(&cipher_context, ctx->ticket_secret, DTLS_TICKET_SECRET_LENGTH);

  res = dtls_ccm_encrypt_message(&(cipher_context.data.ctx), // TODO de-referencing
             8, /* M additional data length */
             2, /* number of bytes to encode length of msg */
             cipher_context.data.NNCE, // TODO check de-referencing
             /* plaintext state */
             dtls_buf + p_ticket + DTLS_TICKET_SECRET_NAME_LENGTH + TICKET_IV_LENGTH + 2,
             /* plaintext state len */
             p - (dtls_buf + p_ticket) - (DTLS_TICKET_SECRET_NAME_LENGTH + TICKET_IV_LENGTH + 2),
             /* additional_data, additional_data_len: key_name(8) + iv(12) */
             dtls_buf + p_ticket, DTLS_TICKET_SECRET_NAME_LENGTH + TICKET_IV_LENGTH);
#endif /* DEX_CCM */

  if (res < 0)
    return -1;

#ifndef NDEBUG
  printf("\nencrypted(%d):\t", p - (dtls_buf + p_ticket) - (DTLS_TICKET_SECRET_NAME_LENGTH + TICKET_IV_LENGTH + 2));
  dump(dtls_buf + p_ticket + DTLS_TICKET_SECRET_NAME_LENGTH + TICKET_IV_LENGTH + 2,
      p - (dtls_buf + p_ticket) - (DTLS_TICKET_SECRET_NAME_LENGTH + TICKET_IV_LENGTH + 2));
  printf("\nAuth: \t");
  dump(p, 8);
  printf("\n");
#endif

  /* M: additional data length */
  p += 8;

  /* update the finish hash
     (FIXME: better put this in generic record_send function) */
  update_hs_hash(peer, dtls_buf, p - dtls_buf);

  STOP_TIMER;
  debug("send_new_session_ticket: NewSessionTicket ready\n");
  /* Take care of record header, sending and retransmission */
  if (!dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, dtls_buf, p - dtls_buf)){
    debug("send_new_session_ticket: sending NewSessionTicket failed\n");
    return 0;
  }
  PRINT_EVAL("NewSeTicket");
  debug("send_new_session_ticket: NewSessionTicket(%d) sent\n", DTLS_ST_LENGTH + peer_id_name);

  return 1;
}
/*-----------------------------------------------------------------------------*/
static int
check_new_session_ticket(dtls_context_t *ctx,
                         dtls_peer_t *peer,
                         uint8 *data, size_t data_length) {

  if (!IS_NEWSESSIONTICKET(data, data_length))
    return 0;

  update_hs_hash(peer, data, data_length);
  inc_uint(sizeof(uint16), peer->sequence_number);

  data += DTLS_HS_LENGTH;
  data_length -= DTLS_HS_LENGTH;

  /* Store the SessionTicket with it's length's for future resumption */
  if (sizeof(OTHER_CONFIG(peer)->session_ticket) >= data_length) {
    OTHER_CONFIG(peer)->session_ticket_len = data_length;
    memcpy(OTHER_CONFIG(peer)->session_ticket, data, data_length);
  } else {
    warn("check_new_session_ticket: Cannot store ticket (%d) >= (%d) !\n", sizeof(OTHER_CONFIG(peer)->session_ticket), data_length);
    return 0;
  }

  debug("NewSessionTicket(%d) installed\n", data_length);
  return 1;
}
/*-----------------------------------------------------------------------------*/
int
dtls_send_ccs_finish(dtls_context_t *ctx, dtls_peer_t *peer) {

  START_TIMER;
  /* ------ Change Cipher Suite ------*/

  /* client */
  dtls_cipher_free(OTHER_CONFIG(peer)->read_cipher);

  assert(OTHER_CONFIG(peer)->cipher != TLS_NULL_WITH_NULL_NULL);
  OTHER_CONFIG(peer)->read_cipher =
    dtls_cipher_new(OTHER_CONFIG(peer)->cipher,
        dtls_kb_server_write_key(OTHER_CONFIG(peer)),
        dtls_kb_key_size(OTHER_CONFIG(peer)));

  if (!OTHER_CONFIG(peer)->read_cipher) {
    warn("cannot create read cipher\n");
    return 0;
  }

  dtls_cipher_set_iv(OTHER_CONFIG(peer)->read_cipher,
         dtls_kb_server_iv(OTHER_CONFIG(peer)),
         dtls_kb_iv_size(OTHER_CONFIG(peer)));

  /* server */
  dtls_cipher_free(OTHER_CONFIG(peer)->write_cipher);

  OTHER_CONFIG(peer)->write_cipher =
    dtls_cipher_new(OTHER_CONFIG(peer)->cipher,
        dtls_kb_client_write_key(OTHER_CONFIG(peer)),
        dtls_kb_key_size(OTHER_CONFIG(peer)));

  if (!OTHER_CONFIG(peer)->write_cipher) {
    dtls_cipher_free(OTHER_CONFIG(peer)->read_cipher);
    warn("cannot create write cipher\n");
    return 0;
  }

  dtls_cipher_set_iv(OTHER_CONFIG(peer)->write_cipher,
         dtls_kb_client_iv(OTHER_CONFIG(peer)),
         dtls_kb_iv_size(OTHER_CONFIG(peer)));

  STOP_TIMER;
  debug("send CCS\n");
  if (!send_ccs(ctx, peer)) {
    debug("cannot send CCS message\n");
    return 0;
  }
  debug("dtls_server_hello: CCS sent\n");
  PRINT_EVAL("CCS");


  START_TIMER;
  /* ------ Finish ------*/

  debug ("send Finished\n");
  int length;
  unsigned char *p = ctx->sendbuf;
  unsigned char statebuf[DTLS_HASH_CTX_SIZE];

  p = dtls_set_handshake_header(DTLS_HT_FINISHED,
        peer, DTLS_FIN_LENGTH,
        0, DTLS_FIN_LENGTH, p);

  /* temporarily store hash status for roll-back after finalize */
  memcpy(statebuf, &peer->hs_state.hs_hash, DTLS_HASH_CTX_SIZE);

  length = finalize_hs_hash(peer, dtls_buf);

  /* restore hash status */
  memcpy(&peer->hs_state.hs_hash, statebuf, DTLS_HASH_CTX_SIZE);

  memset(p, 0, DTLS_FIN_LENGTH);
  dtls_p_hash(HASH_SHA256, CURRENT_CONFIG(peer)->master_secret,
     DTLS_MASTER_SECRET_LENGTH,
     PRF_LABEL(server), PRF_LABEL_SIZE(server),
     PRF_LABEL(finished), PRF_LABEL_SIZE(finished),
     dtls_buf, length,
     p, DTLS_FIN_LENGTH);

  p += DTLS_FIN_LENGTH;

  update_hs_hash(peer, ctx->sendbuf, p - ctx->sendbuf);

  STOP_TIMER;
  if (dtls_send(ctx, peer, DTLS_CT_HANDSHAKE,
    ctx->sendbuf, p - ctx->sendbuf) < 0) {
    dsrv_log(LOG_ALERT, "cannot send Finished message\n");
    return 0;
  }

  PRINT_EVAL("FINISH");
  return 1;
}
#endif /* WITH_RESUMPTION */
/*-----------------------------------------------------------------------------*/
#if !ONLY_RESUMPTION
static int
check_server_hellodone(dtls_context_t *ctx, 
		      dtls_peer_t *peer,
		      uint8 *data, size_t data_length) {

  if (!IS_SERVERHELLODONE(data, data_length))
    return 0;
  
  update_hs_hash(peer, data, data_length);
  inc_uint(sizeof(uint16), peer->sequence_number);
  STOP_TIMER;
  PRINT_EVAL("Check_SerHeDone");

  debug("FLIGHT 4 SUCCESSFUL\n");
#if WITH_PKI
  START_TIMER;
  /* Create a bigger buffer since, we need to send larger packets than FINISH*/
  uint8 *p = dtls_buf;
  size_t qlen = sizeof(ctx->sendbuf);
  const dtls_key_t *key;
  unsigned char statebuf[DTLS_HASH_CTX_SIZE];
  int length;

  /* Certificate */
  debug("check_server_hellodone: Prepare ClientCertificate\n");
  if (!send_certificate(ctx, peer, dtls_buf)) {
     debug("check_server_hellodone: sending ClientCertificate failed\n");
     return 0;
   }
  START_TIMER;
  /* ClientKeyExchange */
  debug("check_server_hellodone: Prepare ClientKeyExchange\n");
  p = dtls_set_handshake_header(DTLS_HT_CLIENT_KEY_EXCHANGE,
          peer,
          (2*ECDH_PKEY_LENGTH) + 1,    // 1 byte length field
          0, (2*ECDH_PKEY_LENGTH) + 1, // 1 byte length field
          dtls_buf);
  memset(p, 0 , (2*ECDH_PKEY_LENGTH) + 1);

  debug("check_server_hellodone: Drive ECDHE key pairs\n");
#if BUSY_WAIT_DH
  clock_wait(0.44*CLOCK_SECOND);
#else /* BUSY_WAIT_DH */
  watchdog_stop();
  cp_ecdh_gen(OTHER_CONFIG(peer)->ecdh_d, OTHER_CONFIG(peer)->ecdh_q);
  watchdog_start();

#ifndef NDEBUG
  PRINTF("ECDH private value \n");
  bn_print(OTHER_CONFIG(peer)->ecdh_d);
  PRINTF("ECDH public value (%s)\n", (ep_is_valid(OTHER_CONFIG(peer)->ecdh_q) != 0) ? "valid":"invalid");
  ep_print(OTHER_CONFIG(peer)->ecdh_q);
#endif /* NDEBUG */
#endif /* BUSY_WAIT_DH */

  // setting the length field
  dtls_int_to_uint8(p, 2 * ECDH_PKEY_LENGTH);
  p += sizeof(uint8);

  int j;
  // Relic data structure holds the values backwards!
  for (j = 0; j < ECDH_PKEY_LENGTH; j++) {
      memcpy(p + ECDH_PKEY_LENGTH - j - 1, (unsigned char*)OTHER_CONFIG(peer)->ecdh_q->x + j, 1);
  }
  p += ECDH_PKEY_LENGTH;

  for (j = 0; j < ECDH_PKEY_LENGTH; j++) {
      memcpy(p + ECDH_PKEY_LENGTH - j - 1, (unsigned char*)OTHER_CONFIG(peer)->ecdh_q->y + j, 1);
  }
  p += ECDH_PKEY_LENGTH;

  /* update the finish hash
     (FIXME: better put this in generic record_send function) */
  update_hs_hash(peer, dtls_buf, p - dtls_buf);

#if NO_DTLS_SEND
  int res;
  res = dtls_prepare_record(peer, DTLS_CT_HANDSHAKE,
          dtls_buf, p - dtls_buf,
          ctx->sendbuf, &qlen);
  if (res < 0) {
    debug("dtls_client_key_exchange: preparing record failed!\n");
    return res;
  }

  /* send out ClientKeyExchange*/
  if (!CALL(ctx, write, &peer->session, ctx->sendbuf, qlen)){
    debug("dtls_client_key_exchange: sending ClientKeyExchange failed\n");
    return 0;
  }
#endif

  STOP_TIMER;
  debug("check_server_hellodone: ClientKeyExchange ready\n");
  /* Take care of record header, sending and retransmission */
  if (!dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, dtls_buf, p - dtls_buf)){
    debug("dtls_client_key_exchange: sending ClientKeyExchange failed\n");
    return 0;
  }
  PRINT_EVAL("ClientKeyEx");
  debug("check_server_hellodone: ClientKeyExchange sent\n");

  START_TIMER;
  /* Now is a good time to drive the keying material, since the server has received
   * required input to do the same. */
  debug("check_server_hellodone: Calculate key block\n");
  if (CALL(ctx, get_key, &peer->session, NULL, 0, &key) < 0
      || !calculate_key_block(ctx,
                              OTHER_CONFIG(peer),
                              key,
                              OTHER_CONFIG(peer)->client_random,
                              OTHER_CONFIG(peer)->server_random)) {
    debug("dtls_client_key_exchange: calculate_key_block failed!\n");
    return 0;
  }

  /* Resetting the pointers */
  p = dtls_buf;
  qlen = sizeof(ctx->sendbuf);

  /* CertificateVerify */
  debug("check_server_hellodone: CertificateVerify\n");
  p = dtls_set_handshake_header(DTLS_HT_CERTIFICATE_VERIFY,
          peer,
          sizeof(ecdsa_signature_t),
          0, sizeof(ecdsa_signature_t),
          dtls_buf);
  memset(p, 0 , sizeof(ecdsa_signature_t));

//  uint16 signature_len;   /* ANSI X9.62: length of signature */
//  uint8 type_r;           /* DER decoding type, length, content */
//  uint8 len_r;
//  unsigned char r[CURVE_KEY_LENGTH]; /* r value of the signature */
//  uint8 type_s;
//  uint8 len_s;
//  unsigned char s[CURVE_KEY_LENGTH]; /* s value of the signature */
//} ecdsa_signature_t ;

  dtls_int_to_uint16(p, SIGNATURE_LENGTH); // 66 byte
  p += sizeof(uint16);

  dtls_int_to_uint8(p, 0x02);
  p += sizeof(uint8);

  dtls_int_to_uint8(p, 0x20); // 32 byte
  p += sizeof(uint8);

  int signature_r = (p - dtls_buf);
  p += ECDH_PKEY_LENGTH;

  dtls_int_to_uint8(p, 0x02);
  p += sizeof(uint8);

  dtls_int_to_uint8(p, 0x20); // 32 byte
  p += sizeof(uint8);

  int signature_s = (p - dtls_buf);
  p += ECDH_PKEY_LENGTH;

  /* We intent to store the hash at the end of the buffer space, and create
   * the signature of it. */
  if (DTLS_MAX_BUF - (dtls_buf - p) < DTLS_HMAC_MAX) {
    debug("CertificateVerify: buffer not large enough to hold the hash!\n");
    return 0;
  }

  /* temporarily store hash status for roll-back after finalize */
  memcpy(statebuf, &peer->hs_state.hs_hash, DTLS_HASH_CTX_SIZE);

  length = finalize_hs_hash(peer, dtls_buf + sizeof(dtls_buf) - DTLS_HMAC_MAX);

  /* restore hash status */
  memcpy(&peer->hs_state.hs_hash, statebuf, DTLS_HASH_CTX_SIZE);

  debug("check_server_hellodone: Signature\n");
#if BUSY_WAIT_DSA
  clock_wait(1.9*CLOCK_SECOND);
#else /* BUSY_WAIT_DSA */
  /* my private key in relic format */
  bn_t my_ecdsa_q;
  cert_set_ec_private_key_param(key->key.pki.private_key, my_ecdsa_q);

  /* Signing the running hash with our private key to proof ownership of the private key
   * corresponding to the public included in the Certificate */
  watchdog_stop();
  cp_ecdsa_sig(sig_r,
               sig_s,
               dtls_buf + sizeof(dtls_buf) - DTLS_HMAC_MAX,
               length,
               1, /* hash flag: input already DIGEST */
               my_ecdsa_q);
  watchdog_start();

  /* Writing the signature (r,s) which is  multiple precision integer into the packet buffer */
  bn_write_bin(dtls_buf + signature_r, ECDH_PKEY_LENGTH, sig_r);
  bn_write_bin(dtls_buf + signature_s, ECDH_PKEY_LENGTH, sig_s);
#endif /* BUSY_WAIT_DSA */

  /* update the finish hash
     (FIXME: better put this in generic record_send function) */
  update_hs_hash(peer, dtls_buf, p - dtls_buf);

#if NO_DTLS_SEND
  res = dtls_prepare_record(peer, DTLS_CT_HANDSHAKE,
          dtls_buf, p - dtls_buf,
          ctx->sendbuf, &qlen);
  if (res < 0) {
    debug("CertificateVerify: preparing record failed!\n");
    return res;
  }

  /* send out CertificateVerify*/
  if (!CALL(ctx, write, &peer->session, ctx->sendbuf, qlen)){
    debug("CertificateVerify: sending CertificateVerify failed\n");
    return 0;
  }
#endif

  STOP_TIMER;
  debug("check_server_hellodone: CertificateVerify ready\n");
  /* Take care of record header, sending and retransmission */
  if (!dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, dtls_buf, p - dtls_buf)){
    debug("CertificateVerify: sending CertificateVerify failed\n");
    return 0;
  }
  PRINT_EVAL("CertVerf");

  debug("check_server_hellodone: CertificateVerify sent\n");

  /* Resetting the pointers */
  p = ctx->sendbuf;
  qlen = sizeof(ctx->sendbuf);
#endif /* WITH_PKI */

#if WITH_RESUMPTION
  send_new_session_ticket(ctx, peer);
#if !defined(CONTIKI_TARGET_MINIMAL_NET)
  clock_wait(1*CLOCK_SECOND);
#endif
#endif /* WITH_RESUMPTION */

  START_TIMER;
  /* calculate master key, send CCS */
  /* set crypto context for TLS_PSK_WITH_AES_128_CCM_8 or
   * TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 */
  /* client */
  dtls_cipher_free(OTHER_CONFIG(peer)->read_cipher);

  assert(OTHER_CONFIG(peer)->cipher != TLS_NULL_WITH_NULL_NULL);
  OTHER_CONFIG(peer)->read_cipher = 
    dtls_cipher_new(OTHER_CONFIG(peer)->cipher,
		    dtls_kb_server_write_key(OTHER_CONFIG(peer)),
		    dtls_kb_key_size(OTHER_CONFIG(peer)));

  if (!OTHER_CONFIG(peer)->read_cipher) {
    warn("cannot create read cipher\n");
    return 0;
  }

  dtls_cipher_set_iv(OTHER_CONFIG(peer)->read_cipher,
		     dtls_kb_server_iv(OTHER_CONFIG(peer)),
		     dtls_kb_iv_size(OTHER_CONFIG(peer)));

  /* server */
  dtls_cipher_free(OTHER_CONFIG(peer)->write_cipher);
  
  OTHER_CONFIG(peer)->write_cipher = 
    dtls_cipher_new(OTHER_CONFIG(peer)->cipher,
		    dtls_kb_client_write_key(OTHER_CONFIG(peer)),
		    dtls_kb_key_size(OTHER_CONFIG(peer)));
  
  if (!OTHER_CONFIG(peer)->write_cipher) {
    dtls_cipher_free(OTHER_CONFIG(peer)->read_cipher);
    warn("cannot create write cipher\n");
    return 0;
  }
  
  dtls_cipher_set_iv(OTHER_CONFIG(peer)->write_cipher,
		     dtls_kb_client_iv(OTHER_CONFIG(peer)),
		     dtls_kb_iv_size(OTHER_CONFIG(peer)));

#if !WITH_PKI
  // FIXME check if we do send correct KX!
  /* send ClientKeyExchange */
  if (dtls_send_kx(ctx, peer, 1) < 0) {
    debug("cannot send KeyExchange message\n");
    return 0;
  }
#endif /* !WITH_PKI */

  /*send CCS and change the cipher mode (epoch) */
  send_ccs(ctx,peer);

  /* Client Finished */
  {
    debug ("send Finished\n");
#if !WITH_PKI
    int length;
    uint8 buf[DTLS_HMAC_MAX];
    uint8 *p = ctx->sendbuf;
    unsigned char statebuf[DTLS_HASH_CTX_SIZE];
#endif /* !WITH_PKI */

    /* FIXME: adjust message overhead calculation */
    assert(msg_overhead(peer, DTLS_HS_LENGTH + DTLS_FIN_LENGTH) 
	   < sizeof(ctx->sendbuf));

    p = dtls_set_handshake_header(DTLS_HT_FINISHED, 
				  peer, DTLS_FIN_LENGTH, 
				  0, DTLS_FIN_LENGTH, p);
  
    /* temporarily store hash status for roll-back after finalize */
    memcpy(statebuf, &peer->hs_state.hs_hash, DTLS_HASH_CTX_SIZE);

    length = finalize_hs_hash(peer, dtls_buf);

    /* restore hash status */
    memcpy(&peer->hs_state.hs_hash, statebuf, DTLS_HASH_CTX_SIZE);

    memset(p, 0, DTLS_FIN_LENGTH);
    dtls_p_hash(HASH_SHA256, CURRENT_CONFIG(peer)->master_secret,
	     DTLS_MASTER_SECRET_LENGTH,
	     PRF_LABEL(client), PRF_LABEL_SIZE(client),
	     PRF_LABEL(finished), PRF_LABEL_SIZE(finished),
	     dtls_buf, length,
	     p, DTLS_FIN_LENGTH);
  
    p += DTLS_FIN_LENGTH;

    update_hs_hash(peer, ctx->sendbuf, p - ctx->sendbuf);

    STOP_TIMER;
    if (dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, 
		  ctx->sendbuf, p - ctx->sendbuf) < 0) {
      dsrv_log(LOG_ALERT, "cannot send Finished message\n");
      return 0;
    }
    PRINT_EVAL("FINISH");
  }
  return 1;
}
#endif /* !ONLY_RESUMPTION */
int
decrypt_verify(dtls_peer_t *peer,
	       uint8 *packet, size_t length,
	       uint8 **cleartext, size_t *clen) {
  int ok = 0;
  
  *cleartext = (uint8 *)packet + DTLS_RH_LENGTH;
  *clen = length - DTLS_RH_LENGTH;

  if (CURRENT_CONFIG(peer)->cipher == TLS_NULL_WITH_NULL_NULL) {
    /* no cipher suite selected */
    return 1;
  } else {
    /* TLS_PSK_WITH_AES_128_CCM_8
     * or
     * TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
     */
    dtls_cipher_context_t *cipher_context;
    /** 
     * length of additional_data for the AEAD cipher which consists of
     * seq_num(2+6) + type(1) + version(2) + length(2)
     */
#define A_DATA_LEN 13
#define A_DATA NNCE
    unsigned char NNCE[max(DTLS_CCM_BLOCKSIZE, A_DATA_LEN)];
    long int len;


    if (*clen < 16)		/* need at least IV and MAC */
      return -1;

    memset(NNCE, 0, DTLS_CCM_BLOCKSIZE);
    memcpy(NNCE, dtls_kb_remote_iv(CURRENT_CONFIG(peer)), 
	   dtls_kb_iv_size(CURRENT_CONFIG(peer)));

    /* read epoch and seq_num from message */
    memcpy(NNCE + dtls_kb_iv_size(CURRENT_CONFIG(peer)), *cleartext, 8);
    *cleartext += 8;
    *clen -= 8;

    cipher_context = CURRENT_CONFIG(peer)->read_cipher;
    
    if (!cipher_context) {
      warn("no read_cipher available!\n");
      return 0;
    }
      
#ifndef NDEBUG
    printf("nonce:\t");
    dump(NNCE, DTLS_CCM_BLOCKSIZE);
    printf("\nkey:\t");
    dump(dtls_kb_remote_write_key(CURRENT_CONFIG(peer)), 
	 dtls_kb_key_size(CURRENT_CONFIG(peer)));
    printf("\nciphertext:\n");
    dump(*cleartext, *clen);
    printf("\n");
#endif

    dtls_cipher_set_iv(cipher_context, NNCE, DTLS_CCM_BLOCKSIZE);

    /* re-use N to create additional data according to RFC 5246, Section 6.2.3.3:
     * 
     * additional_data = seq_num + TLSCompressed.type +
     *                   TLSCompressed.version + TLSCompressed.length;
     */
    memcpy(A_DATA, &DTLS_RECORD_HEADER(packet)->epoch, 8); /* epoch and seq_num */
    memcpy(A_DATA + 8,  &DTLS_RECORD_HEADER(packet)->content_type, 3); /* type and version */
    dtls_int_to_uint16(A_DATA + 11, *clen - 8); /* length without nonce_explicit */

#if DEX_CCM
    len = aes_ccm_decrypt(dtls_kb_remote_write_key(CURRENT_CONFIG(peer)),
                          NNCE,
                          *cleartext,
                          *clen,
                          *cleartext,
                          A_DATA_LEN);
#else /* DEX_CCM */
    len = dtls_decrypt(cipher_context, *cleartext, *clen, *cleartext,
           A_DATA, A_DATA_LEN);
#endif /* DEX_CCM */

    ok = len >= 0;
    if (!ok)
      warn("decryption failed\n");
    else {
#ifndef NDEBUG
      printf("decrypt_verify(): found %ld bytes cleartext\n", len);
#endif
      *clen = len;
    }
#ifndef NDEBUG
    printf("\ncleartext:\n");
    dump(*cleartext, *clen);
    printf("\n");
#endif
  }

  return ok;
}


int
handle_handshake(dtls_context_t *ctx, dtls_peer_t *peer, 
		 uint8 *record_header, uint8 *data, size_t data_length) {

  /* The following switch construct handles the given message with
   * respect to the current internal state for this peer. In case of
   * error, it is left with return 0. */
  info("Sequence number seq(%d, %d) \n",
        dtls_uint16_to_int(DTLS_HANDSHAKE_HEADER(data)->message_seq),
        dtls_uint16_to_int(peer->sequence_number));

  if (dtls_uint16_to_int(peer->sequence_number) > 0 &&
      dtls_uint16_to_int(DTLS_HANDSHAKE_HEADER(data)->message_seq) <= dtls_uint16_to_int(peer->sequence_number)) {
    /* DROP */
    printf("Dropping retransmission seq(%d, %d) \n",
         dtls_uint16_to_int(DTLS_HANDSHAKE_HEADER(data)->message_seq),
        dtls_uint16_to_int(peer->sequence_number));
    //return 0;
  }
  dtls_stop_retransmission(ctx, peer);

  switch (peer->state) {

  /************************************************************************
   * Client states
   ************************************************************************/

  case DTLS_STATE_CLIENTHELLO:
    /* here we expect a HelloVerify or ServerHello */

    debug("DTLS_STATE_CLIENTHELLO\n");
    if (check_server_hello(ctx, peer, data, data_length)) {
#if WITH_PKI
      peer->state = DTLS_STATE_WAIT_SERVERCERTIFICATE;
#elif ONLY_RESUMPTION
      /* create a new ticket for the next session */
      if (!send_new_session_ticket(ctx, peer)) {
        warn("sending new session ticket failed!");
      }
      peer->state = DTLS_STATE_KEYEXCHANGE;
#else /* PSK */
      peer->state = DTLS_STATE_WAIT_SERVERHELLODONE;
    /* update_hs_hash(peer, data, data_length); */
#endif /* WITH_PKI */
    }

    break;

#if WITH_PKI
  case DTLS_STATE_WAIT_SERVERCERTIFICATE:
    debug("DTLS_STATE_WAIT_SERVERCERTIFICATE\n");

    if (check_certificate(ctx, peer, data, data_length)) {
      peer->state = DTLS_STATE_WAIT_SERVERFKEYEXCHANGE;
    }
    break;

  case DTLS_STATE_WAIT_SERVERFKEYEXCHANGE:
    debug("DTLS_STATE_WAIT_SERVERFKEYEXCHANGE\n");

    if (check_server_key_exchange(ctx, peer, data, data_length)) {
      peer->state = DTLS_STATE_WAIT_CERTIFICATEREQUEST;
    }
    STOP_TIMER;
    PRINT_EVAL("Check_SerKeyEx");
    break;

  case DTLS_STATE_WAIT_CERTIFICATEREQUEST:
    debug("DTLS_STATE_WAIT_CERTIFICATEREQUEST\n");

    if (check_server_certificate_request(ctx, peer, data, data_length)) {
      peer->state = DTLS_STATE_WAIT_SERVERHELLODONE;
    }
    STOP_TIMER;
    PRINT_EVAL("Check_CertReq");
    break;
#endif /* WITH_PKI */

#if !ONLY_RESUMPTION
  case DTLS_STATE_WAIT_SERVERHELLODONE:
    /* expect a ServerHelloDone */

    debug("DTLS_STATE_WAIT_SERVERHELLODONE\n");

    if (check_server_hellodone(ctx, peer, data, data_length)) {
      peer->state = DTLS_STATE_WAIT_SERVERFINISHED;
      /* update_hs_hash(peer, data, data_length); */
    }
    break;
#endif /* !ONLY_RESUMPTION */

  case DTLS_STATE_WAIT_SERVERFINISHED:
    /* expect a Finished message from server */

    debug("DTLS_STATE_WAIT_SERVERFINISHED\n");
    if (check_finished(ctx, peer, record_header, data, data_length)) {
      STOP_TIMER;
      PRINT_EVAL("Check_Finish");

#if ONLY_RESUMPTION
      START_TIMER;
      update_hs_hash(peer, data, data_length);
      inc_uint(sizeof(uint16), peer->sequence_number);
      /* this is actually client's finish */
      if (dtls_send_server_finished(ctx, peer) > 0) {
        peer->state = DTLS_STATE_CONNECTED;
      } else {
        warn("sending server Finished failed\n");
      }
#else
      peer->state = DTLS_STATE_CONNECTED;
#endif /* ONLY_RESUMPTION */
      STOP_TIMER_H;
      PRINT_EVAL_H("Client_Connected", retrans_number);
      printf("Client Connected! (%d) \n", retrans_number);

#if STACK_DUMP
        unsigned char *stack_base_1 = stack_base;
        hexdump(stack_base_1 - STACK_DUMP_SIZE, STACK_DUMP_SIZE );
        printf("\n");
#endif

#if REBOOT_AFTER_HANDSHAKE_FINISH
      SYS_REBOOT;
#endif /* REBOOT_AFTER_HANDSHAKE_FINISH */
    } else {
      warn("Server's FINISH failed!\n");
    }
    break;

  /************************************************************************
   * Server states
   ************************************************************************/

#if !ONLY_RESUMPTION
  case DTLS_STATE_SERVERHELLO:
    /* here we expect a messages from flight 5 */
    debug("DTLS_STATE_SERVERHELLO\n");

#if WITH_PKI
    if (check_certificate(ctx, peer, data, data_length)) {
      peer->state = DTLS_STATE_WAIT_CLIENTKEYEXCHANGE;
    }
    break;
#else /* WITH_PKI */
    if (!check_client_keyexchange(ctx, peer, data, data_length)) {
      warn("check_client_keyexchange failed (%d, %d)\n", data_length, data[0]);
      return 0;			/* drop it, whatever it is */
    }
    
    update_hs_hash(peer, data, data_length);
    inc_uint(sizeof(uint16), peer->sequence_number);
    peer->state = DTLS_STATE_KEYEXCHANGE;
    break;
#endif /* WITH_PKI */
#endif /*!ONLY_RESUMPTION*/

#if WITH_PKI
  case DTLS_STATE_WAIT_CLIENTKEYEXCHANGE:
    debug("DTLS_STATE_WAIT_CLIENTKEYEXCHANGE\n");

    /* Premaster key is driven in this function  */
    if (check_client_key_exchange(ctx, peer, data, data_length)) {
      peer->state = DTLS_STATE_WAIT_CERTIFICATEVERIFY;
    } else {
      warn("check_client_key_exchange failed (%d, %d)\n", data_length, data[0]);
      return 0;     /* drop it, whatever it is */
    }

    update_hs_hash(peer, data, data_length);
    inc_uint(sizeof(uint16), peer->sequence_number);
    STOP_TIMER;
    PRINT_EVAL("Check_ClientKeyEx");
    break;

  case DTLS_STATE_WAIT_CERTIFICATEVERIFY:
    debug("DTLS_STATE_WAIT_CERTIFICATEVERIFY\n");

    if (check_certificate_verify(ctx, peer, data, data_length)) {
#if WITH_RESUMPTION
      peer->state = DTLS_STATE_SESSION_TICKET;
#else /* WITH_RESUMPTION */
      peer->state = DTLS_STATE_KEYEXCHANGE;
#endif /* WITH_RESUMPTION */
    } else {
      warn("check_certificate_verify failed (%d, %d)\n", data_length, data[0]);
      return 0;     /* drop it, invalid signature! */
    }

    update_hs_hash(peer, data, data_length);
    inc_uint(sizeof(uint16), peer->sequence_number);
    STOP_TIMER;
    PRINT_EVAL("Check_CertVer");

    break;
#endif /* WITH_PKI */

#if WITH_RESUMPTION
  case DTLS_STATE_SESSION_TICKET:
    debug("DTLS_STATE_WAIT_SESSION_TICKET\n");

    if (check_new_session_ticket(ctx, peer, data, data_length)) {
      STOP_TIMER;
      PRINT_EVAL("Check_NewSeTicket");
#if ONLY_RESUMPTION
      if (!dtls_send_ccs_finish(ctx, peer)) {
        warn("failed sending CCS + FINISH");
      }
      peer->state = DTLS_STATE_WAIT_FINISHED;
#else
      /* wait for CCS */
      peer->state = DTLS_STATE_KEYEXCHANGE;
#endif /* ONLY_RESUMPTION */

    } else {
      warn("no valid Session Ticket \n");
    }

    break;
#endif /* WITH_RESUMPTION */

  case DTLS_STATE_WAIT_FINISHED:
    debug("DTLS_STATE_WAIT_FINISHED\n");
    if (check_finished(ctx, peer, record_header, data, data_length)) {
      /* send ServerFinished */
      update_hs_hash(peer, data, data_length);
      inc_uint(sizeof(uint16), peer->sequence_number);
      STOP_TIMER;
      PRINT_EVAL("Check_Finish");
      START_TIMER;
      if (dtls_send_server_finished(ctx, peer) > 0) {
        peer->state = DTLS_STATE_CONNECTED;
        STOP_TIMER_H;
        PRINT_EVAL_H("Server_Connected", retrans_number);
        printf("Server Connected! (%d) \n", retrans_number);
#if STACK_DUMP
        unsigned char *stack_base_1 = stack_base;
        hexdump(stack_base_1 - STACK_DUMP_SIZE, STACK_DUMP_SIZE );
        printf("\n");
#endif
#if REBOOT_AFTER_HANDSHAKE_FINISH
  printf("Reboot\n");
  SYS_REBOOT;
#endif /* REBOOT_AFTER_HANDSHAKE_FINISH */
      } else {
	warn("sending server Finished failed\n");
      }
    } else {
      /* send alert */
      warn("CLient's FINISH failed!\n");
    }
    break;
      
  case DTLS_STATE_CONNECTED:
    /* At this point, we have a good relationship with this peer. This
     * state is left for re-negotiation of key material. */
    
    printf("DTLS_STATE_CONNECTED\n");

#if !ONLY_RESUMPTION
    /* renegotiation */
    if (dtls_verify_peer(ctx, peer, &peer->session, 
			 record_header, data, data_length) > 0) {

      clear_hs_hash(peer);

      if (!dtls_update_parameters(ctx, peer, data, data_length)) {
	
	warn("error updating security parameters\n");
	dtls_alert(ctx, peer, DTLS_ALERT_LEVEL_WARNING, 
		   DTLS_ALERT_NO_RENEGOTIATION);
	return 0;
      }

      /* update finish MAC */
      update_hs_hash(peer, data, data_length); 

      if (dtls_send_server_hello(ctx, peer) > 0)
	peer->state = DTLS_STATE_SERVERHELLO;
    
      /* after sending the ServerHelloDone, we expect the 
       * ClientKeyExchange (possibly containing the PSK id),
       * followed by a ChangeCipherSpec and an encrypted Finished.
       */
    }
#endif /* !ONLY_RESUMPTION */
    break;
    
  case DTLS_STATE_INIT:	      /* these states should not occur here */
  case DTLS_STATE_KEYEXCHANGE:
  default:
    dsrv_log(LOG_CRIT, "unhandled state %d\n", peer->state);
    assert(0);
  }

  return 1;
}

int
handle_ccs(dtls_context_t *ctx, dtls_peer_t *peer, 
	   uint8 *record_header, uint8 *data, size_t data_length) {

  /* A CCS message is handled after a KeyExchange message was
   * received from the client. When security parameters have been
   * updated successfully and a ChangeCipherSpec message was sent
   * by ourself, the security context is switched and the record
   * sequence number is reset. */
  
  if (peer->state != DTLS_STATE_KEYEXCHANGE
      || !check_ccs(ctx, peer, record_header, data, data_length)) {
    /* signal error? */
    warn("expected ChangeCipherSpec during handshake\n");
    return 0;
  }
  dtls_stop_retransmission(ctx, peer);

#if ONLY_RESUMPTION
  if (CURRENT_CONFIG(peer)->role == DTLS_SERVER) {
    /* I am client */
    send_ccs(ctx, peer);
    peer->state = DTLS_STATE_WAIT_SERVERFINISHED;
  } else {
    /* I am server */
    peer->state = DTLS_STATE_WAIT_FINISHED;
  }
  return 1;
}
#else /* ONLY_RESUMPTION */

   /* send change cipher suite*/
   //send_ccs(ctx,peer);

  /* FIXME: re-factoring! */
  /* send change cipher spec message and switch to new configuration */
//  if (dtls_send_ccs(ctx, peer) < 0) {
//    warn("cannot send CCS message");
//    return 0;
//  }
//
  SWITCH_CONFIG(peer);
  inc_uint(uint16, peer->epoch);
  memset(peer->rseq, 0, sizeof(peer->rseq));

  peer->state = DTLS_STATE_WAIT_FINISHED;
  return 1;
}  
#endif /* ONLY_RESUMPTION */

/** 
 * Handles incoming Alert messages. This function returns \c 1 if the
 * connection should be closed and the peer is to be invalidated.
 */
int
handle_alert(dtls_context_t *ctx, dtls_peer_t *peer, 
	     uint8 *record_header, uint8 *data, size_t data_length) {
  int free_peer = 0;		/* indicates whether to free peer */

  if (data_length < 2)
    return 0;

  info("** Alert: level %d, description %d\n", data[0], data[1]);

  /* The peer object is invalidated for FATAL alerts and close
   * notifies. This is done in two steps.: First, remove the object
   * from our list of peers. After that, the event handler callback is
   * invoked with the still existing peer object. Finally, the storage
   * used by peer is released.
   */
  if (data[0] == DTLS_ALERT_LEVEL_FATAL || data[1] == DTLS_ALERT_CLOSE) {
    dsrv_log(LOG_ALERT, "%d invalidate peer\n", data[1]);
    
#ifndef WITH_CONTIKI
    HASH_DEL_PEER(ctx->peers, peer);
#else /* WITH_CONTIKI */
    list_remove(ctx->peers, peer);

#ifndef NDEBUG
    PRINTF("removed peer [");
    PRINT6ADDR(&peer->session.addr);
    PRINTF("]:%d\n", uip_ntohs(peer->session.port));
#endif
#endif /* WITH_CONTIKI */

    free_peer = 1;

  }

  (void)CALL(ctx, event, &peer->session, 
	     (dtls_alert_level_t)data[0], (unsigned short)data[1]);
  switch (data[1]) {
  case DTLS_ALERT_CLOSE:
    /* If state is DTLS_STATE_CLOSING, we have already sent a
     * close_notify so, do not send that again. */
    if (peer->state != DTLS_STATE_CLOSING) {
      peer->state = DTLS_STATE_CLOSING;
      dtls_alert(ctx, peer, DTLS_ALERT_LEVEL_FATAL, DTLS_ALERT_CLOSE);
    } else
      peer->state = DTLS_STATE_CLOSED;
    break;
  default:
    ;
  }
  
  if (free_peer) {
    dtls_stop_retransmission(ctx, peer);
    dtls_free_peer(peer);
  }

  return free_peer;
}

/** 
 * Handles incoming data as DTLS message from given peer.
 */
int
dtls_handle_message(dtls_context_t *ctx, 
		    session_t *session,
		    uint8 *msg, int msglen) {
  dtls_peer_t *peer = NULL;
  unsigned int rlen;		/* record length */
  uint8 *data; 			/* (decrypted) payload */
  size_t data_length;		/* length of decrypted payload 
				   (without MAC and padding) */

  START_TIMER;
  /* check if we have DTLS state for addr/port/ifindex */
#ifndef WITH_CONTIKI
  HASH_FIND_PEER(ctx->peers, session, peer);
  {
    dtls_peer_t *p = NULL;
    HASH_FIND_PEER(ctx->peers, session, p);
#ifndef NDEBUG
    if (!p) {
      printf("dtls_handle_message: PEER NOT FOUND\n");
      {
	unsigned char addrbuf[72];
	dsrv_print_addr(session, addrbuf, sizeof(addrbuf));
	printf("  %s\n", addrbuf);
	dump((unsigned char *)session, sizeof(session_t));
	printf("\n");
      }
    } else 
      printf("dtls_handle_message: FOUND PEER\n");
#endif /* NDEBUG */
  }
#else /* WITH_CONTIKI */
  for (peer = list_head(ctx->peers); 
       peer && !dtls_session_equals(&peer->session, session);
       peer = list_item_next(peer))
    ;
#endif /* WITH_CONTIKI */

  if (!peer) {			
    START_TIMER_H;
    /* get first record from client message */
    rlen = is_record(msg, msglen);
    assert(rlen <= msglen);

    if (!rlen) {
#ifndef NDEBUG
      if (msglen > 3) 
	debug("dropped invalid message %02x%02x%02x%02x\n", msg[0], msg[1], msg[2], msg[3]);
      else
	debug("dropped invalid message (less than four bytes)\n");
#endif
      return 0;
    }

    /* is_record() ensures that msg contains at least a record header */
    data = msg + DTLS_RH_LENGTH;
    data_length = rlen - DTLS_RH_LENGTH;

    /* When no DTLS state exists for this peer, we only allow a
       Client Hello message with 
        
       a) a valid cookie, or 
       b) no cookie.

       Anything else will be rejected. Fragementation is not allowed
       here as it would require peer state as well.
    */

    /* No cookie involved in the abbreviated handshake */
#if !ONLY_RESUMPTION
    if (dtls_verify_peer(ctx, NULL, session, msg, data, data_length) <= 0) {
      warn("cannot verify peer\n");
      return -1;
    }
#endif /* !ONLY_RESUMPTION */

    
    /* msg contains a Client Hello with a valid cookie, so we can
       safely create the server state machine and continue with
       the handshake. */

    peer = dtls_new_peer(ctx, session);
    if (!peer) {
      dsrv_log(LOG_ALERT, "cannot create peer");
      /* FIXME: signal internal error */
      return -1;
    }

    /* Initialize record sequence number to 1 for new peers. The first
     * record with sequence number 0 is a stateless Hello Verify Request.
     */
    peer->rseq[5] = 1;

    /* First negotiation step: check for PSK
     *
     * Note that we already have checked that msg is a Handshake
     * message containing a ClientHello. dtls_get_cipher() therefore
     * does not check again.
     */
    if (!dtls_update_parameters(ctx, peer, 
			msg + DTLS_RH_LENGTH, rlen - DTLS_RH_LENGTH)) {

      warn("error updating security parameters\n");
      /* FIXME: send handshake failure Alert */
      dtls_alert(ctx, peer, DTLS_ALERT_LEVEL_FATAL, 
		 DTLS_ALERT_HANDSHAKE_FAILURE);
      dtls_free_peer(peer);
      return -1;
    }

#ifndef WITH_CONTIKI
    HASH_ADD_PEER(ctx->peers, session, peer);
#else /* WITH_CONTIKI */
    list_add(ctx->peers, peer);
#endif /* WITH_CONTIKI */
    
    /* update finish MAC */
    update_hs_hash(peer, msg + DTLS_RH_LENGTH, rlen - DTLS_RH_LENGTH);
    inc_uint(sizeof(uint16), peer->sequence_number);

    if (dtls_send_server_hello(ctx, peer) > 0)
#if ONLY_RESUMPTION
      /* Set the state machine to the correct state */
      peer->state = DTLS_STATE_SESSION_TICKET;
#else /* ONLY_RESUMPTION */
      peer->state = DTLS_STATE_SERVERHELLO;
#endif /* ONLY_RESUMPTION */

    /* after sending the ServerHelloDone, we expect the 
     * ClientKeyExchange (possibly containing the PSK id),
     * followed by a ChangeCipherSpec and an encrypted Finished.
     */

    msg += rlen;
    msglen -= rlen;
  } else {
    debug("found peer\n");
  }

  /* At this point peer contains a state machine to handle the
     received message. */

  assert(peer);

  while ((rlen = is_record(msg,msglen))) {

    /* skip packet if it is from a different epoch */
    if (memcmp(DTLS_RECORD_HEADER(msg)->epoch, 
	       peer->epoch, sizeof(uint16)) != 0){
      warn("got packet from different epoch (%d) expected (%d)\n",
           dtls_uint16_to_int(DTLS_RECORD_HEADER(msg)->epoch),
           dtls_uint16_to_int(peer->epoch));
      goto next;
    }

    /* Check sequence number of record and drop message if the
     * number is not exactly the last number that we have responded to + 1.
     * Otherwise, stop retransmissions for this specific peer and
     * continue processing. */
    if (!decrypt_verify(peer, msg, rlen, &data, &data_length)) {
      info("decrypt_verify() failed\n");
      goto next;
    }

#ifndef NDEBUG
    hexdump(msg, DTLS_RH_LENGTH);
    printf("\n");
    hexdump(data, data_length);
    printf("\n");
#endif

    /* Handle received record according to the first byte of the
     * message, i.e. the subprotocol. We currently do not support
     * combining multiple fragments of one type into a single
     * record. */

    switch (msg[0]) {

    case DTLS_CT_CHANGE_CIPHER_SPEC:
      info("** CIPHER SPEC message:\n");
      handle_ccs(ctx, peer, msg, data, data_length);
      break;

    case DTLS_CT_ALERT:
      if (handle_alert(ctx, peer, msg, data, data_length)) {
	/* handle alert has invalidated peer */
	peer = NULL;
	return 0;
      }

    case DTLS_CT_HANDSHAKE:
      info("** HANDSHAKE message:\n");
      handle_handshake(ctx, peer, msg, data, data_length);
      if (peer->state == DTLS_STATE_CONNECTED) {
	/* stop retransmissions */
	dtls_stop_retransmission(ctx, peer);
	CALL(ctx, event, &peer->session, 0, DTLS_EVENT_CONNECTED);
      }
      break;

    case DTLS_CT_APPLICATION_DATA:
      dtls_stop_retransmission(ctx, peer);
      info("** application data:\n");
      CALL(ctx, read, &peer->session, data, data_length);
      break;
    default:
      info("dropped unknown message of type %d\n",msg[0]);
    }

  next:
    /* advance msg by length of ciphertext */
    msg += rlen;
    msglen -= rlen;
  }

  return 0;
}

dtls_context_t *
dtls_new_context(void *app_data) {
  dtls_context_t *c;

  prng_init(clock_time()); /* FIXME: need something better to init PRNG here */

  c = &the_dtls_context;

  memset(c, 0, sizeof(dtls_context_t));
  c->app = app_data;
  
#ifdef WITH_CONTIKI
  LIST_STRUCT_INIT(c, peers);
  /* LIST_STRUCT_INIT(c, key_store); */
  
  LIST_STRUCT_INIT(c, sendqueue);

  process_start(&dtls_retransmit_process, (char *)c);
  PROCESS_CONTEXT_BEGIN(&dtls_retransmit_process);
  /* the retransmit timer must be initialized to some large value */
  etimer_set(&c->retransmit_timer, 0xFFFF);
  PROCESS_CONTEXT_END(&coap_retransmit_process);
#endif /* WITH_CONTIKI */

#if WITH_RESUMPTION
  /* Create secret key for protecting SessionTicket */
  if (!prng(c->ticket_secret, DTLS_TICKET_SECRET_LENGTH))
    goto error;
  /* creating a random name for the secret key */
  if (!prng(c->ticket_secret_id, DTLS_TICKET_SECRET_NAME_LENGTH))
    goto error;
#endif /* WITH_RESUMPTION */

  if (prng(c->cookie_secret, DTLS_COOKIE_SECRET_LENGTH))
    c->cookie_secret_age = clock_time();
  else 
    goto error;
  
  return c;

 error:
  dsrv_log(LOG_ALERT, "cannot create DTLS context");
  if (c)
    dtls_free_context(c);
  return NULL;
}

void dtls_free_context(dtls_context_t *ctx) {
  dtls_peer_t *p;
  
#ifndef WITH_CONTIKI
  dtls_peer_t *tmp;

  if (ctx->peers) {
    HASH_ITER(hh, ctx->peers, p, tmp) {
      dtls_free_peer(p);
    }
  }
#else /* WITH_CONTIKI */
  int i;

  p = (dtls_peer_t *)peer_storage.mem;
  for (i = 0; i < peer_storage.num; ++i, ++p) {
    if (peer_storage.count[i])
      dtls_free_peer(p);
  }
#endif /* WITH_CONTIKI */
}

int
dtls_connect(dtls_context_t *ctx, const session_t *dst) {
  dtls_peer_t *peer;
  uint8 *p = ctx->sendbuf;
  size_t size;
  int res;

  START_TIMER;
  START_TIMER_H;
  /* check if we have DTLS state for addr/port/ifindex */
#ifndef WITH_CONTIKI
  HASH_FIND_PEER(ctx->peers, dst, peer);
#else /* WITH_CONTIKI */
  for (peer = list_head(ctx->peers); peer; peer = list_item_next(peer))
    if (dtls_session_equals(&peer->session, dst))
      break;
#endif /* WITH_CONTIKI */
  
  if (peer) {
    debug("found peer, try to re-connect\n");
    /* FIXME: send HelloRequest if we are server, 
       ClientHello with good cookie if client */
    return 0;
  }

  peer = dtls_new_peer(ctx, dst);

  if (!peer) {
    dsrv_log(LOG_CRIT, "cannot create new peer\n");
    return -1;
  }
    
  /* set peer role to server: */
  OTHER_CONFIG(peer)->role = DTLS_SERVER;
  CURRENT_CONFIG(peer)->role = DTLS_SERVER;

#ifndef WITH_CONTIKI
  HASH_ADD_PEER(ctx->peers, session, peer);
#else /* WITH_CONTIKI */
  list_add(ctx->peers, peer);
#endif /* WITH_CONTIKI */

  /* send ClientHello with some Cookie */

  /* add to size:
   *   1. length of session id (including length field)
   *   2. length of cookie (including length field)
   *   3. cypher suites
   *   4. compression methods 
   */
  size = DTLS_CH_LENGTH + 8;
#if WITH_RESUMPTION
  /* ExtensionType + Empty SessionTicket */
  size += sizeof(uint16) + sizeof(uint16);
#endif /* WITH_RESUMPTION */

  /* force sending 0 as handshake message sequence number by setting
   * peer to NULL */
  p = dtls_set_handshake_header(DTLS_HT_CLIENT_HELLO, NULL, 
				size, 0, size, p);

  dtls_int_to_uint16(p, DTLS_VERSION);
  p += sizeof(uint16);

  /* Set client random: First 4 bytes are the client's Unix timestamp,
   * followed by 28 bytes of generate random data. */
  dtls_int_to_uint32(&OTHER_CONFIG(peer)->client_random, clock_time());
  prng(OTHER_CONFIG(peer)->client_random + sizeof(uint32),
       sizeof(OTHER_CONFIG(peer)->client_random) - sizeof(uint32));
  memcpy(p, OTHER_CONFIG(peer)->client_random, 
	 sizeof(OTHER_CONFIG(peer)->client_random));
  p += 32;

  /* session id (length 0) */
  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

  /* add supported cipher suite */
  dtls_int_to_uint16(p, 2);
  p += sizeof(uint16);
  
#if WITH_PKI
  dtls_int_to_uint16(p, TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
#else /* WITH_PKI */
  dtls_int_to_uint16(p, TLS_PSK_WITH_AES_128_CCM_8);
#endif /* WITH_PKI */
  p += sizeof(uint16);
  
  /* compression method */
  dtls_int_to_uint8(p, 1);  
  p += sizeof(uint8);

  dtls_int_to_uint8(p, TLS_COMP_NULL);
  p += sizeof(uint8);

#if WITH_RESUMPTION
  /* Add an empty SessionTicket extension (Client-side off-loading)*/
  /* ExtensionType */
  dtls_int_to_uint16(p, DTLS_EX_SESSIONTICKET_CLIENT);
  p += sizeof(uint16);

  /* Empty SessionTicket */
  dtls_int_to_uint16(p, 0);
  p += sizeof(uint16);
#endif /* WITH_RESUMPTION */

#if ONLY_RESUMPTION
  /* in abbr. handshake the first ClientHello is part of the final hash */
  update_hs_hash(peer, ctx->sendbuf, p - ctx->sendbuf);
#endif /* ONLY_RESUMPTION */

  STOP_TIMER;
  res = dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, ctx->sendbuf, 
		  p - ctx->sendbuf);

  if (res < 0)
    warn("cannot send ClientHello\n");
  else
    peer->state = DTLS_STATE_CLIENTHELLO;

  PRINT_EVAL("CHello0");
  return res;
}

void
dtls_retransmit(dtls_context_t *context, netq_t *node) {
  uint8 switch_cs = 0;
  if (!context || !node)
    return;

  /* re-initialize timeout when maximum number of retransmissions are not reached yet */
  if (node->retransmit_cnt < DTLS_DEFAULT_MAX_RETRANSMIT) {
      unsigned char sendbuf[DTLS_MAX_BUF];
      size_t len = sizeof(sendbuf);

      retrans_number++;
      node->retransmit_cnt++;
      node->t += (node->timeout << node->retransmit_cnt);
      netq_insert_node((netq_t **)context->sendqueue, node);
      
      debug("** retransmit packet\n");
      
      if (memcmp(node->epoch, node->peer->epoch, sizeof(uint16)) != 0) {
        debug("Retransmission with previous cipher suite (%d, %d)\n",
            dtls_uint16_to_int(node->peer->epoch),
            dtls_uint16_to_int(node->epoch));
        SWITCH_CONFIG(node->peer);
        memcpy(node->peer->epoch, node->epoch, sizeof(uint16));
        switch_cs = 1;
      }

      if (dtls_prepare_record(node->peer, node->type,
			      node->data, node->length, 
			      sendbuf, &len) > 0) {


#ifndef NDEBUG
	debug("retransmit %d bytes\n", len);
	hexdump(sendbuf, DTLS_RH_LENGTH);
	printf("\n");
	hexdump(node->data, node->length);
	printf("\n");
#endif
	
	(void)CALL(context, write, &node->peer->session, sendbuf, len);
      }
      if (switch_cs) {
        SWITCH_CONFIG(node->peer);
        inc_uint(uint16, node->peer->epoch);
      }
      return;
  }

  /* no more retransmissions, remove node from system */
  
  debug("** removed transaction\n");

  /* And finally delete the node */
  netq_node_free(node);
}

void
dtls_stop_retransmission(dtls_context_t *context, dtls_peer_t *peer) {
  void *node;
  node = list_head((list_t)context->sendqueue); 

  while (node) {
    if (dtls_session_equals(&((netq_t *)node)->peer->session,
			    &peer->session)) {
      void *tmp = node;
      node = list_item_next(node);
      list_remove((list_t)context->sendqueue, tmp);
      netq_node_free((netq_t *)tmp);
    } else
      node = list_item_next(node);    
  }
}

#ifdef WITH_CONTIKI
/*---------------------------------------------------------------------------*/
/* message retransmission */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(dtls_retransmit_process, ev, data)
{
  clock_time_t now;
  netq_t *node;

  PROCESS_BEGIN();

  debug("Started DTLS retransmit process\r\n");

  while(1) {
    PROCESS_YIELD();
    if (ev == PROCESS_EVENT_TIMER) {
      if (etimer_expired(&the_dtls_context.retransmit_timer)) {
	
  node = list_tail(the_dtls_context.sendqueue);
	
	now = clock_time();
	while (node && node->t <= now) {
    dtls_retransmit(&the_dtls_context, list_chop(the_dtls_context.sendqueue));
    node = list_tail(the_dtls_context.sendqueue);
#if !defined(CONTIKI_TARGET_MINIMAL_NET)
    clock_wait(1*CLOCK_SECOND);
#endif /* !defined(CONTIKI_TARGET_MINIMAL_NET) */
	}

	/* need to set timer to some value even if no nextpdu is available */
	etimer_set(&the_dtls_context.retransmit_timer, 
		   node ? node->t - now : 0xFFFF);
      } 
    }
  }
  
  PROCESS_END();
}
#endif /* WITH_CONTIKI */

//#ifndef NDEBUG
/** dumps packets in usual hexdump format */
void hexdump(const unsigned char *packet, int length) {
  int n = 0;

  while (length--) { 
    if (n % 16 == 0)
      printf("%08X ",n);

    printf("%02X ", *packet++);
    
    n++;
    if (n % 8 == 0) {
      if (n % 16 == 0)
	printf("\n");
      else
	printf(" ");
    }
  }
}

/** dump as narrow string of hex digits */
void dump(unsigned char *buf, size_t len) {
  while (len--) 
    printf("%02x", *buf++);
}
//#endif

