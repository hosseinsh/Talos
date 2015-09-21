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
#ifndef FLOCKLAB_H_
#define FLOCKLAB_H_

//GPIO Driver Include
#include <gpio.h>

//NVIC Driver Include
#include <nvic.h>

/*
 * FlockLab LED Outputs
 */
#define LED_PORT      GPIO_PORT_TO_BASE(GPIO_A_NUM)
#define LED1_MASK     GPIO_PIN_MASK(2)
#define LED2_MASK     GPIO_PIN_MASK(3)
#define LED3_MASK     GPIO_PIN_MASK(4)

/*
 * FlockLab INT Outputs
 */
#define INT_PORT      GPIO_PORT_TO_BASE(GPIO_D_NUM)
#define INT1_MASK     GPIO_PIN_MASK(0)
#define INT2_MASK     GPIO_PIN_MASK(1)

/*
 * FlockLab SIGNAL Inputs
 */
#define SIG_PORT_NUM  GPIO_D_NUM
#define SIG_PORT      GPIO_PORT_TO_BASE(SIG_PORT_NUM)
#define SIG_PORT_NVIC NVIC_INT_GPIO_PORT_D
#define SIG1_PIN      2
#define SIG1_MASK     GPIO_PIN_MASK(SIG1_PIN)
#define SIG2_PIN      3
#define SIG2_MASK     GPIO_PIN_MASK(SIG2_PIN)

/*
 * Configures FlockLab I/O Pins
 */
void flocklab_init();

/*
 * Register Callback
 */
void flocklab_register_callback(gpio_callback_t f, uint8_t pin);

#endif /* FLOCKLAB_H_ */
