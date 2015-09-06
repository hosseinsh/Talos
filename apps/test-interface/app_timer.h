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
#ifndef APP_TIMER_H_
#define APP_TIMER_H_

#include <test-interface.h>

/*
 * Output timer states active/passive on GPIOs
 * Take effect next time a timer is started.
 */
void enable_timer_output();

/*
 * Do not Output timer states active/passive on GPIOs
 */
void disable_timer_output();

/*
 * Start timer
 *
 * Note: This Timers has an 30us resolution
 */
void start_timer(uint32_t index);

/*
 * Stop timer and store measurement
 */
void stop_timer(uint32_t index, uint32_t id);

/*
 * Init high resolution timer
 */
void init_high_res_timer();

/*
 * Start high resolution timer
 *
 * Note: Timer has an 1us resolution
 */
void start_high_res_timer();

/*
 * Stop high resolution timer and store measurement
 */
void stop_high_res_timer(uint32_t id);

/*
 * Store measurement and restart timer
 */
void restart_timer(uint32_t index, uint32_t id);

/*
 * Output all time measurements and clear data
 */
void print_timer();

PT_THREAD(app_timer(struct pt *pt, struct packet_t *packet));

#endif /* APP_TIMER_H_ */
