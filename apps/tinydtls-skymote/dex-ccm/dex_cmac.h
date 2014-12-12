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

#ifndef DEX_CMAC_H_
#define DEX_CMAC_H_

#include <stdint.h> //uint8_t
#if !AES_HARDWARE_CC2520
#include "TI_aes.h"
#endif /* !AES_HARDWARE_CC2520 */

/****************************************************************************
parts of ContikiSec sec/aes.h which are needed for the cmac functionality
****************************************************************************/
#define N_ROW                   4
#define N_COL                   4
#define N_BLOCK   (N_ROW * N_COL)
#define N_MAX_ROUNDS           14

#if 0
typedef struct
{   uint8_t ksch[(N_MAX_ROUNDS + 1) * N_BLOCK];
    uint8_t rnd;
} aes_context;
#else
/* use a modified version which only accepts keys < 16 byte
 * which is sufficient for dex
 * also we do not need the rnd parameter
 */
typedef struct
{   uint8_t ksch[N_BLOCK];
} aes_context;
#endif

/****************************************************************************/

#define AES_CMAC_KEY_LENGTH     16
#define AES_CMAC_DIGEST_LENGTH  4


typedef unsigned char  u_int8_t;
typedef unsigned int u_int;
typedef struct _AES_CMAC_CTX {
            aes_context    rijndael;
            u_int8_t        X[16];
            u_int8_t        M_last[16];
            u_int           M_n;
    } AES_CMAC_CTX;

//#include <sys/cdefs.h>

//__BEGIN_DECLS
void     AES_CMAC_Init(AES_CMAC_CTX * ctx);
void     AES_CMAC_SetKey(AES_CMAC_CTX * ctx, const u_int8_t key[AES_CMAC_KEY_LENGTH]);
void     AES_CMAC_Update(AES_CMAC_CTX * ctx, const u_int8_t * data, u_int len);
          //          __attribute__((__bounded__(__string__,2,3)));
void     AES_CMAC_Final(u_int8_t digest[AES_CMAC_DIGEST_LENGTH], AES_CMAC_CTX  * ctx);
            //     __attribute__((__bounded__(__minbytes__,1,AES_CMAC_DIGEST_LENGTH)));
//__END_DECLS


#endif /* DEX_CMAC_H_ */
