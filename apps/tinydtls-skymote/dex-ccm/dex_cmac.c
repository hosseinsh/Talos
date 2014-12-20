/**************************************************************************
The following file is part of ContikiSec. Together with dex_cmac.c
it includes all functionality from sec/aes.c/h and sec/cmac.c/h needed to
compute a AES-CMAC.
It is slightly modified to run with the Texas Instruments AES implementation
for MSP430 instead of the AES implementation of ContikiSec
**************************************************************************/
/**************************************************************************
Copyright (C) 2009 Lander Casado, Philippas Tsigas

All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files
(the "Software"), to deal with the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimers. Redistributions in
binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimers in the documentation and/or
other materials provided with the distribution.

In no event shall the authors or copyright holders be liable for any special,
incidental, indirect or consequential damages of any kind, or any damages
whatsoever resulting from loss of use, data or profits, whether or not
advised of the possibility of damage, and on any theory of liability,
arising out of or in connection with the use or performance of this software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS WITH THE SOFTWARE

*****************************************************************************/
//#include <sys/param.h>
//#include <sys/systm.h>

#if AES_HARDWARE_CC2520
#define DEX_AES DEX_AES_HARDWARE
#else /* AES_HARDWARE_CC2520 */
#define DEX_AES DEX_AES_SOFTWARE
#endif /* AES_HARDWARE_CC2520 */

#define DEX_CC2420_AES_INDEX    0

#define DEX_AES_SOFTWARE        1
#define DEX_AES_HARDWARE        2


#if DEX_AES == DEX_AES_HARDWARE
  #if CONTIKI_TARGET_SKY
  #include "../../dev/cc2420/cc2420-aes.h"
  #define _aes_set_key(...) cc2420_aes_set_key(__VA_ARGS__)
  #define _aes_cipher(...) cc2420_aes_cipher(__VA_ARGS__)
  #elif CONTIKI_TARGET_WISMOTE
  #include <cc2520.h>
  #define _aes_set_key(...) cc2520_aes_set_key(__VA_ARGS__)
  #define _aes_cipher(...) cc2520_aes_cipher(__VA_ARGS__)
  #endif /* SKY or WISMOTE */
#endif /* DEX_AES_HARDWARE */

#if DEX_AES == DEX_AES_SOFTWARE
#include "TI_aes.h"
#endif /* DEX_AES_HARDWARE */

#include "dex_cmac.h"
#include <stdint.h> //uint8_t
#include <string.h> // memcpy
#include <stdlib.h> // malloc


#define LSHIFT(v, r) do {                                       \
  int i;                                                  \
           for (i = 0; i < 15; i++)                                \
                    (r)[i] = (v)[i] << 1 | (v)[i + 1] >> 7;         \
            (r)[15] = (v)[15] << 1;                                 \
    } while (0)

#define XOR(v, r) do {                                          \
            int i;                                                  \
            for (i = 0; i < 16; i++)     \
      { \
                    (r)[i] = (r)[i] ^ (v)[i]; \
      }                          \
    } while (0) \


#define MIN(a,b) (((a)<(b))?(a):(b))

void AES_CMAC_Init(AES_CMAC_CTX *ctx)
{
            memset(ctx->X, 0, sizeof ctx->X);
            ctx->M_n = 0;
#if 0
      memset(ctx->rijndael.ksch, '\0', 240);
#else
      // dex uses only a 16 byte value for ksch
      memset(ctx->rijndael.ksch, '\0', 16);
#endif
}

/**************************************************************
parts of ContikiSec sec/aes.c/h which are needed for the CMAC functionality
**************************************************************/
#if 0
#define sb_data(w) {    /* S Box data values */                            \
    w(0x63), w(0x7c), w(0x77), w(0x7b), w(0xf2), w(0x6b), w(0x6f), w(0xc5),\
    w(0x30), w(0x01), w(0x67), w(0x2b), w(0xfe), w(0xd7), w(0xab), w(0x76),\
    w(0xca), w(0x82), w(0xc9), w(0x7d), w(0xfa), w(0x59), w(0x47), w(0xf0),\
    w(0xad), w(0xd4), w(0xa2), w(0xaf), w(0x9c), w(0xa4), w(0x72), w(0xc0),\
    w(0xb7), w(0xfd), w(0x93), w(0x26), w(0x36), w(0x3f), w(0xf7), w(0xcc),\
    w(0x34), w(0xa5), w(0xe5), w(0xf1), w(0x71), w(0xd8), w(0x31), w(0x15),\
    w(0x04), w(0xc7), w(0x23), w(0xc3), w(0x18), w(0x96), w(0x05), w(0x9a),\
    w(0x07), w(0x12), w(0x80), w(0xe2), w(0xeb), w(0x27), w(0xb2), w(0x75),\
    w(0x09), w(0x83), w(0x2c), w(0x1a), w(0x1b), w(0x6e), w(0x5a), w(0xa0),\
    w(0x52), w(0x3b), w(0xd6), w(0xb3), w(0x29), w(0xe3), w(0x2f), w(0x84),\
    w(0x53), w(0xd1), w(0x00), w(0xed), w(0x20), w(0xfc), w(0xb1), w(0x5b),\
    w(0x6a), w(0xcb), w(0xbe), w(0x39), w(0x4a), w(0x4c), w(0x58), w(0xcf),\
    w(0xd0), w(0xef), w(0xaa), w(0xfb), w(0x43), w(0x4d), w(0x33), w(0x85),\
    w(0x45), w(0xf9), w(0x02), w(0x7f), w(0x50), w(0x3c), w(0x9f), w(0xa8),\
    w(0x51), w(0xa3), w(0x40), w(0x8f), w(0x92), w(0x9d), w(0x38), w(0xf5),\
    w(0xbc), w(0xb6), w(0xda), w(0x21), w(0x10), w(0xff), w(0xf3), w(0xd2),\
    w(0xcd), w(0x0c), w(0x13), w(0xec), w(0x5f), w(0x97), w(0x44), w(0x17),\
    w(0xc4), w(0xa7), w(0x7e), w(0x3d), w(0x64), w(0x5d), w(0x19), w(0x73),\
    w(0x60), w(0x81), w(0x4f), w(0xdc), w(0x22), w(0x2a), w(0x90), w(0x88),\
    w(0x46), w(0xee), w(0xb8), w(0x14), w(0xde), w(0x5e), w(0x0b), w(0xdb),\
    w(0xe0), w(0x32), w(0x3a), w(0x0a), w(0x49), w(0x06), w(0x24), w(0x5c),\
    w(0xc2), w(0xd3), w(0xac), w(0x62), w(0x91), w(0x95), w(0xe4), w(0x79),\
    w(0xe7), w(0xc8), w(0x37), w(0x6d), w(0x8d), w(0xd5), w(0x4e), w(0xa9),\
    w(0x6c), w(0x56), w(0xf4), w(0xea), w(0x65), w(0x7a), w(0xae), w(0x08),\
    w(0xba), w(0x78), w(0x25), w(0x2e), w(0x1c), w(0xa6), w(0xb4), w(0xc6),\
    w(0xe8), w(0xdd), w(0x74), w(0x1f), w(0x4b), w(0xbd), w(0x8b), w(0x8a),\
    w(0x70), w(0x3e), w(0xb5), w(0x66), w(0x48), w(0x03), w(0xf6), w(0x0e),\
    w(0x61), w(0x35), w(0x57), w(0xb9), w(0x86), w(0xc1), w(0x1d), w(0x9e),\
    w(0xe1), w(0xf8), w(0x98), w(0x11), w(0x69), w(0xd9), w(0x8e), w(0x94),\
    w(0x9b), w(0x1e), w(0x87), w(0xe9), w(0xce), w(0x55), w(0x28), w(0xdf),\
    w(0x8c), w(0xa1), w(0x89), w(0x0d), w(0xbf), w(0xe6), w(0x42), w(0x68),\
    w(0x41), w(0x99), w(0x2d), w(0x0f), w(0xb0), w(0x54), w(0xbb), w(0x16) }

#define WPOLY   0x011b

#define f1(x)   (x)
#define f2(x)   ((x << 1) ^ (((x >> 7) & 1) * WPOLY))

#define s_box(x)     sbox[(x)]

static const uint8_t sbox[256]  =  sb_data(f1);
#endif

static uint8_t dex_aes_set_key( const unsigned char key[], uint8_t keylen, aes_context ctx[1] )
{
#if 0
    uint8_t cc, rc, hi;

    switch( keylen )
    {
    case 16:
    case 128:
        keylen = 16;
        break;
    case 24:
    case 192:
        keylen = 24;
        break;
    case 32:
    case 256:
        keylen = 32;
        break;
    default:
        ctx->rnd = 0;
        return -1;
    }
#endif
    // block_copy_nn(ctx->ksch, key, keylen);
    memcpy(ctx->ksch, key, keylen);
#if 0
    hi = (keylen + 28) << 2;
    ctx->rnd = (hi >> 4) - 1;
    for( cc = keylen, rc = 1; cc < hi; cc += 4 )
    {   uint8_t tt, t0, t1, t2, t3;

        t0 = ctx->ksch[cc - 4];
        t1 = ctx->ksch[cc - 3];
        t2 = ctx->ksch[cc - 2];
        t3 = ctx->ksch[cc - 1];
        if( cc % keylen == 0 )
        {
            tt = t0;
            t0 = s_box(t1) ^ rc;
            t1 = s_box(t2);
            t2 = s_box(t3);
            t3 = s_box(tt);
            rc = f2(rc);
        }
        else if( keylen > 24 && cc % keylen == 16 )
        {
            t0 = s_box(t0);
            t1 = s_box(t1);
            t2 = s_box(t2);
            t3 = s_box(t3);
        }
        tt = cc - keylen;
        ctx->ksch[cc + 0] = ctx->ksch[tt + 0] ^ t0;
        ctx->ksch[cc + 1] = ctx->ksch[tt + 1] ^ t1;
        ctx->ksch[cc + 2] = ctx->ksch[tt + 2] ^ t2;
        ctx->ksch[cc + 3] = ctx->ksch[tt + 3] ^ t3;
    }
#endif
    return 0;
}
/****************************************************************************/

void AES_CMAC_SetKey(AES_CMAC_CTX *ctx, const u_int8_t key[AES_CMAC_KEY_LENGTH])
{
           //rijndael_set_key_enc_only(&ctx->rijndael, key, 128);
#if 0
     dex_aes_set_key( key, 128, &ctx->rijndael);
#else
     dex_aes_set_key( key, 16, &ctx->rijndael);
#endif
}

void AES_CMAC_Update(AES_CMAC_CTX *ctx, const u_int8_t *data, u_int len)
{
            u_int mlen;
      unsigned char in[16];

            if (ctx->M_n > 0) {
                  mlen = MIN(16 - ctx->M_n, len);
                    memcpy(ctx->M_last + ctx->M_n, data, mlen);
                    ctx->M_n += mlen;
                    if (ctx->M_n < 16 || len == mlen)
                            return;
                   XOR(ctx->M_last, ctx->X);
                    //rijndael_encrypt(&ctx->rijndael, ctx->X, ctx->X);
        //aes_encrypt( ctx->X, ctx->X, &ctx->rijndael);

#if DEX_AES == DEX_AES_HARDWARE
        _aes_set_key((const uint8_t *) &ctx->rijndael, DEX_CC2420_AES_INDEX);
        _aes_cipher(ctx->X, 16, DEX_CC2420_AES_INDEX);
#elif DEX_AES == DEX_AES_SOFTWARE
        aes_encrypt(ctx->X, (unsigned char *)&ctx->rijndael);
#endif


                   data += mlen;
                    len -= mlen;
            }
            while (len > 16) {      /* not last block */

                    XOR(data, ctx->X);
                    //rijndael_encrypt(&ctx->rijndael, ctx->X, ctx->X);

                    memcpy(in, &ctx->X[0], 16); //Bestela ez du ondo iten
        //aes_encrypt( in, in, &ctx->rijndael);
#if DEX_AES == DEX_AES_HARDWARE
        _aes_set_key((const uint8_t *) &ctx->rijndael, DEX_CC2420_AES_INDEX);
        _aes_cipher(in, 16, DEX_CC2420_AES_INDEX);
#elif DEX_AES == DEX_AES_SOFTWARE
        aes_encrypt(in, (unsigned char *)&ctx->rijndael);
#endif
                    memcpy(&ctx->X[0], in, 16);

                    data += 16;
                    len -= 16;
            }
            /* potential last block, save it */
            memcpy(ctx->M_last, data, len);
            ctx->M_n = len;
}

void AES_CMAC_Final(u_int8_t digest[AES_CMAC_DIGEST_LENGTH], AES_CMAC_CTX *ctx)
{
            u_int8_t K[16];
      unsigned char in[16];
            /* generate subkey K1 */
            memset(K, '\0', 16);

            //rijndael_encrypt(&ctx->rijndael, K, K);

          //aes_encrypt( K, K, &ctx->rijndael);

#if DEX_AES == DEX_AES_HARDWARE
          _aes_set_key((const uint8_t *) &ctx->rijndael, DEX_CC2420_AES_INDEX);
          _aes_cipher(K, 16, DEX_CC2420_AES_INDEX);
#elif DEX_AES == DEX_AES_SOFTWARE
          aes_encrypt(K, (unsigned char *)&ctx->rijndael);
#endif
            if (K[0] & 0x80) {
                    LSHIFT(K, K);
                   K[15] ^= 0x87;
            } else
                    LSHIFT(K, K);


            if (ctx->M_n == 16) {
                    /* last block was a complete block */
                    XOR(K, ctx->M_last);

           } else {
                   /* generate subkey K2 */
                  if (K[0] & 0x80) {
                          LSHIFT(K, K);
                          K[15] ^= 0x87;
                  } else
                           LSHIFT(K, K);

                   /* padding(M_last) */
                   ctx->M_last[ctx->M_n] = 0x80;
                   while (++ctx->M_n < 16)
                         ctx->M_last[ctx->M_n] = 0;

                  XOR(K, ctx->M_last);


           }
           XOR(ctx->M_last, ctx->X);

           //rijndael_encrypt(&ctx->rijndael, ctx->X, digest);

     memcpy(in, &ctx->X[0], 16); //Bestela ez du ondo iten
       //aes_encrypt(in, digest, &ctx->rijndael);
#if DEX_AES == DEX_AES_HARDWARE
       _aes_set_key((const uint8_t *) &ctx->rijndael, DEX_CC2420_AES_INDEX);
       _aes_cipher(in, 16, DEX_CC2420_AES_INDEX);
#elif DEX_AES == DEX_AES_SOFTWARE
       aes_encrypt(in, (unsigned char *)&ctx->rijndael);
#endif
       // dex aes always writes the encrypted data to the source so we need to copy it manually to digest
       memcpy(digest, in, 16);

           memset(K, 0, sizeof K);

}
