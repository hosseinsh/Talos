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

#include <stdio.h>
#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif

#include "global.h"
#include "debug.h"
#include "numeric.h"
#include "dtls.h"
#include "crypto.h"

#if DEX_CCM
#include "dex_ccm.h"
#else/* DEX_CCM */
#include "ccm.h"
#endif /* DEX_CCM */


#ifndef WITH_CONTIKI
#include <stdlib.h>

static inline dtls_cipher_context_t *
dtls_cipher_context_new() {
  return (dtls_cipher_context_t *)malloc(sizeof(dtls_cipher_context_t));
}

static inline void
dtls_cipher_context_free(dtls_cipher_context_t *ctx) {
  free(ctx);
}
#else /* WITH_CONTIKI */
MEMB(cipher_storage, dtls_cipher_context_t, DTLS_CIPHER_CONTEXT_MAX);

static inline dtls_cipher_context_t *
dtls_cipher_context_new() {
  return (dtls_cipher_context_t *)memb_alloc(&cipher_storage);
}

static inline void
dtls_cipher_context_free(dtls_cipher_context_t *ctx) {
  if (ctx)
    memb_free(&cipher_storage, ctx);
}
#endif /* WITH_CONTIKI */

extern void dtls_hmac_storage_init();

void crypto_init() {
  dtls_hmac_storage_init();

#ifdef WITH_CONTIKI
  memb_init(&cipher_storage);
#endif /* WITH_CONTIKI */
}

#ifndef NDEBUG
extern void dump(unsigned char *, size_t);
#endif

#define HMAC_UPDATE_SEED(Context,Seed,Length)		\
  if (Seed) dtls_hmac_update(Context, (Seed), (Length))

size_t
dtls_p_hash(dtls_hashfunc_t h,
	    const unsigned char *key, size_t keylen,
	    const unsigned char *label, size_t labellen,
	    const unsigned char *random1, size_t random1len,
	    const unsigned char *random2, size_t random2len,
	    unsigned char *buf, size_t buflen) {
  dtls_hmac_context_t *hmac_a, *hmac_p;

  unsigned char A[DTLS_HMAC_DIGEST_SIZE];
  unsigned char tmp[DTLS_HMAC_DIGEST_SIZE];
  size_t dlen;			/* digest length */
  size_t len = 0;			/* result length */

  hmac_a = dtls_hmac_new(key, keylen);
  if (!hmac_a)
    return 0;

  /* calculate A(1) from A(0) == seed */
  HMAC_UPDATE_SEED(hmac_a, label, labellen);
  HMAC_UPDATE_SEED(hmac_a, random1, random1len);
  HMAC_UPDATE_SEED(hmac_a, random2, random2len);

  dlen = dtls_hmac_finalize(hmac_a, A);

  hmac_p = dtls_hmac_new(key, keylen);
  if (!hmac_p)
    goto error;

  while (len + dlen < buflen) {

    /* FIXME: rewrite loop to avoid superflous call to dtls_hmac_init() */
    dtls_hmac_init(hmac_p, key, keylen);
    dtls_hmac_update(hmac_p, A, dlen);

    HMAC_UPDATE_SEED(hmac_p, label, labellen);
    HMAC_UPDATE_SEED(hmac_p, random1, random1len);
    HMAC_UPDATE_SEED(hmac_p, random2, random2len);

    len += dtls_hmac_finalize(hmac_p, tmp);
    memcpy(buf, tmp, dlen);
    buf += dlen;

    /* calculate A(i+1) */
    dtls_hmac_init(hmac_a, key, keylen);
    dtls_hmac_update(hmac_a, A, dlen);
    dtls_hmac_finalize(hmac_a, A);
  }

  dtls_hmac_init(hmac_p, key, keylen);
  dtls_hmac_update(hmac_p, A, dlen);
  
  HMAC_UPDATE_SEED(hmac_p, label, labellen);
  HMAC_UPDATE_SEED(hmac_p, random1, random1len);
  HMAC_UPDATE_SEED(hmac_p, random2, random2len);
  
  dtls_hmac_finalize(hmac_p, tmp);
  memcpy(buf, tmp, buflen - len);

 error:
  dtls_hmac_free(hmac_a);
  dtls_hmac_free(hmac_p);

  return buflen;
}

size_t 
dtls_prf(const unsigned char *key, size_t keylen,
	 const unsigned char *label, size_t labellen,
	 const unsigned char *random1, size_t random1len,
	 const unsigned char *random2, size_t random2len,
	 unsigned char *buf, size_t buflen) {

  /* Clear the result buffer */
  memset(buf, 0, buflen);
  return dtls_p_hash(HASH_SHA256, 
		     key, keylen, 
		     label, labellen, 
		     random1, random1len,
		     random2, random2len,
		     buf, buflen);
}

void
dtls_mac(dtls_hmac_context_t *hmac_ctx, 
	 const unsigned char *record,
	 const unsigned char *packet, size_t length,
	 unsigned char *buf) {
  uint16 L;
  dtls_int_to_uint16(L, length);

  assert(hmac_ctx);
  dtls_hmac_update(hmac_ctx, record +3, sizeof(uint16) + sizeof(uint48));
  dtls_hmac_update(hmac_ctx, record, sizeof(uint8) + sizeof(uint16));
  dtls_hmac_update(hmac_ctx, L, sizeof(uint16));
  dtls_hmac_update(hmac_ctx, packet, length);
  
  dtls_hmac_finalize(hmac_ctx, buf);
}

static inline void
dtls_ccm_init(aes128_ccm_t *ccm_ctx, unsigned char *NNCE, size_t length) {
  assert(ccm_ctx);

  if (length < DTLS_CCM_BLOCKSIZE)
    memset(ccm_ctx->NNCE + length, 0, DTLS_CCM_BLOCKSIZE - length);

  memcpy(ccm_ctx->NNCE, NNCE, DTLS_CCM_BLOCKSIZE);
}

size_t
dtls_ccm_encrypt(aes128_ccm_t *ccm_ctx, const unsigned char *src, size_t srclen,
		 unsigned char *buf, 
		 const unsigned char *aad, size_t la) {
  long int len;

  assert(ccm_ctx);

#if DEX_CCM
  len = aes_ccm_encrypt(ccm_ctx->key,
                        ccm_ctx->NNCE,
                        buf,
                        la,
                        srclen,
                        buf);
#else /* DEX_CCM */
  len = dtls_ccm_encrypt_message(&ccm_ctx->ctx, 8 /* M */,
				 max(2, 15 - DTLS_CCM_NONCE_SIZE),
				 ccm_ctx->NNCE,
				 buf, srclen,
				 aad, la);
#endif /* DEX_CCM */
  return len;
}

size_t
dtls_ccm_decrypt(aes128_ccm_t *ccm_ctx, const unsigned char *src,
		 size_t srclen, unsigned char *buf,
		 const unsigned char *aad, size_t la) {
  long int len;

  assert(ccm_ctx);
#if DEX_CCM
  len = aes_ccm_decrypt(ccm_ctx->key,
                        ccm_ctx->NNCE,
                        buf,
                        srclen,
                        buf,
                        la);
#else /* DEX_CCM */
  len = dtls_ccm_decrypt_message(&ccm_ctx->ctx, 8 /* M */, 
				 max(2, 15 - DTLS_CCM_NONCE_SIZE),
				 ccm_ctx->NNCE, 
				 buf, srclen, 
				 aad, la);
#endif /* DEX_CCM */
  return len;
}

size_t
dtls_pre_master_secret(unsigned char *key, size_t keylen,
		       unsigned char *result) {
  unsigned char *p = result;

  dtls_int_to_uint16(p, keylen);
  p += sizeof(uint16);

  memset(p, 0, keylen);
  p += keylen;

  memcpy(p, result, sizeof(uint16));
  p += sizeof(uint16);
  
  memcpy(p, key, keylen);

  return (sizeof(uint16) + keylen) << 1;
}

void 
dtls_cipher_set_iv(dtls_cipher_context_t *ctx,
		   unsigned char *iv, size_t length) {
  assert(ctx);
  dtls_ccm_init(&ctx->data, iv, length);
}

#if WITH_RESUMPTION
/* set the key for a given cipher_context */
uint8_t
set_ccm_cipher(dtls_cipher_context_t *cipher_context,
               unsigned char *key,
               size_t keylen) {

#if DEX_CCM
    if (memcpy((&cipher_context->data)->key, key, DTLS_CCM_BLOCKSIZE) == NULL) {
#else /* DEX_CCM */
    if (rijndael_set_key_enc_only(&(&cipher_context->data)->ctx, key, 8 * keylen) < 0) {
#endif /* DEX_CCM */

    /* cleanup everything in case the key has the wrong size */
    warn("cannot set AES key\n");
    return 0;
  }

  return 1;
}
#endif /* WITH_RESUMPTION */

dtls_cipher_context_t *
dtls_cipher_new(dtls_cipher_t cipher,
		unsigned char *key, size_t keylen) {
  dtls_cipher_context_t *cipher_context = NULL;

  cipher_context = dtls_cipher_context_new();
  if (!cipher_context) {
    warn("cannot allocate cipher_context\r\n");
    return NULL;
  }

  switch (cipher) {
  case TLS_PSK_WITH_AES_128_CCM_8: {
    aes128_ccm_t *ccm_ctx = &cipher_context->data;
    
#if DEX_CCM
    if (memcpy(ccm_ctx->key, key, DTLS_CCM_BLOCKSIZE) == NULL) {
#else /* DEX_CCM */
    if (rijndael_set_key_enc_only(&ccm_ctx->ctx, key, 8 * keylen) < 0) {
#endif /* DEX_CCM */

      /* cleanup everything in case the key has the wrong size */
      warn("cannot set AES key\n");
      goto error;
    }
    break;
  }
#if WITH_PKI
  case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: {
    aes128_ccm_t *ccm_ctx = &cipher_context->data;

#if DEX_CCM
    if (memcpy(ccm_ctx->key, key, DTLS_CCM_BLOCKSIZE) == NULL) {
#else /* DEX_CCM */
    if (rijndael_set_key_enc_only(&ccm_ctx->ctx, key, 8 * keylen) < 0) {
#endif /* DEX_CCM */

      /* cleanup everything in case the key has the wrong size */
      warn("cannot set AES key\n");
      goto error;
    }
    break;
  }
#endif /* WITH_PKI */
  default:
    warn("unknown cipher %04x\n", cipher);
    goto error;
  }
  
  return cipher_context;
 error:
  dtls_cipher_context_free(cipher_context);
  return NULL;
}

void 
dtls_cipher_free(dtls_cipher_context_t *cipher_context) {
  dtls_cipher_context_free(cipher_context);
}

int 
dtls_encrypt(dtls_cipher_context_t *ctx, 
	     const unsigned char *src, size_t length,
	     unsigned char *buf,
	     const unsigned char *aad, size_t la) {
  if (ctx) {
    if (src != buf)
      memmove(buf, src, length);
    return dtls_ccm_encrypt(&ctx->data, src, length, buf, 
			    aad, la);
  }

  return -1;
}

int 
dtls_decrypt(dtls_cipher_context_t *ctx, 
	     const unsigned char *src, size_t length,
	     unsigned char *buf,
	     const unsigned char *aad, size_t la) {
  if (ctx) {
    if (src != buf)
      memmove(buf, src, length);
    return dtls_ccm_decrypt(&ctx->data, src, length, buf,
			    aad, la);
  }

  return -1;
}

