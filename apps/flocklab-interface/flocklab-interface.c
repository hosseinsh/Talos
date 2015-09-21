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
#include "flocklab-interface.h"

void flocklab_init() {
  /*
   * Configure FlockLab output pins
   */
  GPIO_SOFTWARE_CONTROL(LED_PORT, LED1_MASK); //LED1
  GPIO_SET_OUTPUT(LED_PORT, LED1_MASK);
  GPIO_SOFTWARE_CONTROL(LED_PORT, LED2_MASK); //LED2
  GPIO_SET_OUTPUT(LED_PORT, LED2_MASK);
  GPIO_SOFTWARE_CONTROL(LED_PORT, LED3_MASK); //LED3
  GPIO_SET_OUTPUT(LED_PORT, LED3_MASK);
  GPIO_SOFTWARE_CONTROL(INT_PORT, INT1_MASK); //INT1
  GPIO_SET_OUTPUT(INT_PORT, INT1_MASK);
  GPIO_SOFTWARE_CONTROL(INT_PORT, INT2_MASK); //INT2
  GPIO_SET_OUTPUT(INT_PORT, INT2_MASK);

  /*
   * Configure FlockLab input pins
   */
  GPIO_SOFTWARE_CONTROL(SIG_PORT, SIG1_MASK);
  GPIO_SET_INPUT(SIG_PORT, SIG1_MASK);
  GPIO_SOFTWARE_CONTROL(SIG_PORT, SIG2_MASK);
  GPIO_SET_INPUT(SIG_PORT, SIG2_MASK);
}

void flocklab_register_callback(gpio_callback_t f, uint8_t pin) {
  gpio_register_callback(f, SIG_PORT_NUM, pin);
  GPIO_DETECT_EDGE(SIG_PORT, GPIO_PIN_MASK(pin));
  GPIO_TRIGGER_BOTH_EDGES(SIG_PORT, GPIO_PIN_MASK(pin));
  GPIO_ENABLE_INTERRUPT(SIG_PORT, GPIO_PIN_MASK(pin));
  GPIO_ENABLE_POWER_UP_INTERRUPT(SIG_PORT_NUM, GPIO_PIN_MASK(pin));
  GPIO_POWER_UP_ON_RISING(SIG_PORT_NUM, GPIO_PIN_MASK(pin));
  GPIO_POWER_UP_ON_FALLING(SIG_PORT_NUM, GPIO_PIN_MASK(pin));
  nvic_interrupt_enable(SIG_PORT_NVIC);
}
