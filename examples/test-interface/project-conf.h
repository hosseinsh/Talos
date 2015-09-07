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
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define START_TIMER(x) start_timer(x);
#define STOP_TIMER(x, y)  stop_timer(x, y);

#define START_ECC_TIMER(x) start_timer(x);
#define STOP_ECC_TIMER(x, y)  stop_timer(x, y);

#define UART0_CONF_BAUD_RATE                     460800
#define FLASH_CCA_CONF_BOOTLDR_BACKDOOR_ACTIVE_HIGH   1
#define FLASH_CCA_CONF_BOOTLDR_BACKDOOR_PORT_A_PIN    5

#define USE_PREEMPTION                                0
#define MTARCH_CONF_STACKSIZE                       512

#define USE_APP_SHA256                                1
#define USE_APP_CCM                                   1
#define USE_APP_AES                                   1
#define USE_APP_ECC                                   1
#define HAVE_RELIC                                    0
#define HAVE_FLOCKLAB                                 0

#endif /* PROJECT_CONF_H_ */
