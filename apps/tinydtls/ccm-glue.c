/*
 * Copyright (c) 2014, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author: Andreas Dröscher <contiki@anticat.ch>
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
#include "contiki.h"
#include "ccm-glue.h"
#include "crypto.h"
#include "ccm.h"
#include "pt.h"
#include "mt.h"
#include "debug.h"

int
hw_ccm_encrypt(aes128_ccm_t *ccm_ctx, const unsigned char *src, size_t srclen,
                 unsigned char *buf, unsigned char *nounce,
                 const unsigned char *aad, size_t la) {
  crypto_enable();
  if(ccm_auth_encrypt_start(3, 0, nounce, aad, la, buf, srclen, 8, PROCESS_CURRENT())) {
    crypto_disable();
    return -1;
  }

  while(!ccm_auth_encrypt_check_status()) {
    mt_yield();
  }

  if(ccm_auth_encrypt_get_result(buf + srclen, 8)) {
    crypto_disable();
    return -1;
  }

  crypto_disable();
  return srclen + 8;
}

int
hw_ccm_decrypt(aes128_ccm_t *ccm_ctx, const unsigned char *src,
                 size_t srclen, unsigned char *buf,
                 unsigned char *nounce,
                 const unsigned char *aad, size_t la) {
  crypto_enable();
  if(ccm_auth_decrypt_start(3, 0, nounce, aad, la, buf, srclen, 8, PROCESS_CURRENT())) {
    crypto_disable();
    return -1;
  }

  while(!ccm_auth_decrypt_check_status()) {
    mt_yield();
  }

  if(ccm_auth_decrypt_get_result(buf, srclen-8, 0, 0)) {
    crypto_disable();
    return -1;
  }

  crypto_disable();
  return srclen - 8;
}

int
hw_ccm_set_key(const u_char *key, int bits) {
  switch(bits) {
    case 128:
      bits = AES_KEY_STORE_SIZE_KEY_SIZE_128;
      break;
    case 192:
      bits = AES_KEY_STORE_SIZE_KEY_SIZE_192;
      break;
    case 256:
      bits = AES_KEY_STORE_SIZE_KEY_SIZE_256;
      break;
    default:
      return -1;
  }

  crypto_enable();
  int res = aes_load_keys(key, bits, 1, 0);
  crypto_disable();
  return -res;
}
