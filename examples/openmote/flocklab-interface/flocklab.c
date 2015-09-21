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
#include <project-conf.h>

//Contiki OS Includes
#include <contiki.h>
#include <contiki-net.h>
#include <contiki-lib.h>
#include <rtimer.h>
#include <clock.h>

//Additional Apps and Drivers
#include <gpio.h>
#include <leds.h>
#include <flash-erase.h>
#include <flocklab-interface.h>

PROCESS(flocklab_idle_process, "FlockLab Idle Process");
AUTOSTART_PROCESSES(&flocklab_idle_process, &flash_erase_process);

/*
 * Our rtimer fired event
 */
static process_event_t event_rtimer_fired;

/*
 * Struct of the sleep timer
 */
static struct rtimer sleep_timer;

/*
 * Current LED State
 */
static uint8_t led_state = 0;

/*
 * The Callback is called SIGx level changes (edge)
 */
static void signal_cb(uint8_t port, uint8_t pin) {
  if(pin == SIG1_PIN) {
    if(GPIO_READ_PIN(SIG_PORT, SIG1_MASK)) {
      GPIO_SET_PIN(INT_PORT, INT1_MASK);
    } else {
      GPIO_CLR_PIN(INT_PORT, INT1_MASK);
    }
  }
  
  if(pin == SIG2_PIN) {
    if(GPIO_READ_PIN(SIG_PORT, SIG2_MASK)) {
      GPIO_SET_PIN(INT_PORT, INT2_MASK);
    } else {
      GPIO_CLR_PIN(INT_PORT, INT2_MASK);
    }
  }
}

/*
 * The Callback is called when the timer expires
 */
void rt_callback(struct rtimer *t, void *ptr) {
  process_post(&flocklab_idle_process, event_rtimer_fired, NULL);
}

PROCESS_THREAD(flocklab_idle_process, ev, data) {
  PROCESS_BEGIN();

  /*
   * Disable Wireless
   */
  NETSTACK_MAC.off(0);
  NETSTACK_RDC.off(0);
  NETSTACK_RADIO.off();

  /*
   * Allocate EventID
   */
  event_rtimer_fired = process_alloc_event();

  /*
   * Configure FlockLab pins
   */
  flocklab_init();
  flocklab_register_callback(signal_cb, SIG1_PIN);
  flocklab_register_callback(signal_cb, SIG2_PIN);

  /*
   * Blink Internal and External LEDs
   */
  while(1) {
    switch(led_state) {
      case 0:
        leds_on(LEDS_YELLOW);
        leds_off(LEDS_ORANGE);
        GPIO_SET_PIN(LED_PORT, LED1_MASK);
        GPIO_CLR_PIN(LED_PORT, LED3_MASK);
        break;
      case 1:
        leds_on(LEDS_GREEN);
        leds_off(LEDS_YELLOW);
        GPIO_SET_PIN(LED_PORT, LED2_MASK);
        GPIO_CLR_PIN(LED_PORT, LED1_MASK);
        break;
      case 2:
        leds_on(LEDS_ORANGE);
        leds_off(LEDS_GREEN);
        GPIO_SET_PIN(LED_PORT, LED3_MASK);
        GPIO_CLR_PIN(LED_PORT, LED2_MASK);
        break;
    }
    led_state = (led_state + 1) % 3;

    /*
     * Schedule the rtimer
     */
    rtimer_set(&sleep_timer, RTIMER_NOW() + RTIMER_SECOND*1, 1, (rtimer_callback_t)rt_callback, NULL);

    /*
     * Wait for the callback
     */
    PROCESS_WAIT_EVENT_UNTIL(ev == event_rtimer_fired);
  }

  PROCESS_END();
}
