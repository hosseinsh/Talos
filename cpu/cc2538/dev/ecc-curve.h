/*
 * Original file:
 * Copyright (C) 2013 Texas Instruments Incorporated - http://www.ti.com/
 * All rights reserved.
 *
 * Port to Contiki:
 * Copyright (c) 2014 Andreas Dröscher <contiki@anticat.ch>
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
 * \addtogroup cc2538-ecc
 * @{
 *
 * \defgroup cc2538-ecc-curves cc2538 NIST curves
 *
 * NIST curves for various key sizes
 * @{
 *
 * \file
 * NIST curves for various key sizes
 */
#ifndef ECC_CURVE_H_
#define ECC_CURVE_H_

//[NIST P-256, X9.62 prime256v1]
static uint32_t nist_p_256_p[8] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
                                    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF };
static uint32_t nist_p_256_n[8] = { 0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
                                    0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF };
static uint32_t nist_p_256_a[8] = { 0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
                                    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF };
static uint32_t nist_p_256_b[8] = { 0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0,
                                    0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8 };
static uint32_t nist_p_256_x[8] = { 0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,
                                    0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2 };
static uint32_t nist_p_256_y[8] = { 0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,
                                    0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2 };

static ecc_curve_info_t nist_p_256 = {
  .name       = "NIST P-256",
  .ui8Size    = 8,
  .pui32Prime = nist_p_256_p,
  .pui32N     = nist_p_256_n,
  .pui32A     = nist_p_256_a,
  .pui32B     = nist_p_256_b,
  .pui32Gx    = nist_p_256_x,
  .pui32Gy    = nist_p_256_y
};

#endif /* CURVE_INFO_H_ */

/**
 * @}
 * @}
 */
