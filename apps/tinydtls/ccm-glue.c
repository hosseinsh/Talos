/*
 * Copyright (c) 2014 Andreas Dröscher <contiki@anticat.ch>
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
