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
#include <contiki-lib.h>
#include <contiki-net.h>
#include <timer.h>
#include <dev/gptimer.h>
#include <dev/sys-ctrl.h>

//System Includes
#include <stdio.h>
#include <string.h>
#include <log.h>

//Additional Apps and Drivers
#include <app_debug.h>
#include <gpio.h>
#include <test-interface.h>
#if HAVE_FLOCKLAB == 1
#include <flocklab-interface.h>
#endif

#define TIMER_COUNT 32

//Storage for 8 concurrent timer
static rtimer_clock_t timer[8];

//Storage for 16 time measurements
static uint32_t measurement_id[TIMER_COUNT];
static uint32_t measurement_value[TIMER_COUNT];
static uint8_t  measurement_index = 0;

//If true pins on left side of XBee connector
//will be used to signal active timers
static uint8_t output_timer_active = 0;

//Defines for timer outputs
#define TIMER_PORT_A_BASE  GPIO_PORT_TO_BASE(GPIO_A_NUM)
#define TIMER_PORT_D_BASE  GPIO_PORT_TO_BASE(GPIO_D_NUM)

struct output {
  uint32_t portbase;
  uint32_t pinmask;
};

#if HAVE_FLOCKLAB == 1
static struct output outputs[8] = {
    {
        .portbase = LED_PORT,
        .pinmask  = LED1_MASK,
    }, {
        .portbase = LED_PORT,
        .pinmask  = LED2_MASK,
    }, {
        .portbase = LED_PORT,
        .pinmask  = LED3_MASK,
    }, {
        .portbase = INT_PORT,
        .pinmask  = INT1_MASK,
    }, {
        .portbase = INT_PORT,
        .pinmask  = INT2_MASK,
    //FlockLab supports only 5 GPIOs
    //we therefore repeat the last pin.
    }, {
        .portbase = INT_PORT,
        .pinmask  = INT2_MASK,
    }, {
        .portbase = INT_PORT,
        .pinmask  = INT2_MASK,
    }, {
        .portbase = INT_PORT,
        .pinmask  = INT2_MASK,
    }
};
#else
static struct output outputs[8] = {
    {
        .portbase = TIMER_PORT_D_BASE,
        .pinmask  = GPIO_PIN_MASK(3),
    }, {
        .portbase = TIMER_PORT_D_BASE,
        .pinmask  = GPIO_PIN_MASK(2),
    }, {
        .portbase = TIMER_PORT_D_BASE,
        .pinmask  = GPIO_PIN_MASK(1),
    }, {
        .portbase = TIMER_PORT_D_BASE,
        .pinmask  = GPIO_PIN_MASK(0),
    }, {
        .portbase = TIMER_PORT_A_BASE,
        .pinmask  = GPIO_PIN_MASK(4),
    }, {
        .portbase = TIMER_PORT_A_BASE,
        .pinmask  = GPIO_PIN_MASK(6),
    }, {
        .portbase = TIMER_PORT_A_BASE,
        .pinmask  = GPIO_PIN_MASK(3),
    }, {
        .portbase = TIMER_PORT_A_BASE,
        .pinmask  = GPIO_PIN_MASK(2),
    }
};
#endif

void enable_timer_output() {
  uint8_t i;
  for(i = 0; i < 8; i++) {
    GPIO_SOFTWARE_CONTROL(outputs[i].portbase, outputs[i].pinmask);
    GPIO_SET_OUTPUT(outputs[i].portbase, outputs[i].pinmask);
    GPIO_CLR_PIN(outputs[i].portbase, outputs[i].pinmask);
  }

  output_timer_active = 1;
}

void disable_timer_output() {
  uint8_t i;
  for(i = 0; i < 8; i++) {
    GPIO_SET_INPUT(outputs[i].portbase, outputs[i].pinmask);
  }

  output_timer_active = 0;
}

inline void set_pin(uint8_t index) {
  if(!output_timer_active) {
    return;
  }

  GPIO_SET_PIN(outputs[index].portbase, outputs[index].pinmask);
}

inline void clr_pin(uint8_t index) {
  if(!output_timer_active) {
    return;
  }

  GPIO_CLR_PIN(outputs[index].portbase, outputs[index].pinmask);
}

void init_high_res_timer() {
  /* Configure GPT for 1us  */
  REG(SYS_CTRL_RCGCGPT) |= SYS_CTRL_RCGCGPT_GPT1;
  REG(GPT_1_BASE | GPTIMER_CTL)   = 0;
  REG(GPT_1_BASE | GPTIMER_CFG)   = 0x00;
  REG(GPT_1_BASE | GPTIMER_TAMR)  = GPTIMER_TAMR_TAMR_ONE_SHOT | GPTIMER_TAMR_TACDIR;
  REG(GPT_1_BASE | GPTIMER_TAILR) = 0xfffffffe;
  REG(GPT_1_BASE | GPTIMER_TAPR)  = 0x00;
}

void start_high_res_timer() {
  /* Reset Timer */
  REG(GPT_1_BASE | GPTIMER_TAV) =   0x00000000;

  /* Start GPT */
  REG(GPT_1_BASE | GPTIMER_CTL) |= GPTIMER_CTL_TAEN;

  /* Set PIN */
  set_pin(0);
}

void stop_high_res_timer(uint32_t id) {
  /* Clear PIN */
  clr_pin(0);

  /* Stop GTP */
  REG(GPT_1_BASE | GPTIMER_CTL) = 0;

  /* Read Value */
  measurement_value[measurement_index]   = REG(GPT_1_BASE | GPTIMER_TAR) / 32;
  measurement_id[measurement_index]      = id;

  //Increment Index
  measurement_index = (measurement_index + 1) % TIMER_COUNT;
}


void start_timer(uint32_t index) {
  //Normal Timer
  set_pin(index % 8);
  timer[index] = RTIMER_NOW();
}

void stop_timer(uint32_t index, uint32_t id) {
  if(!timer[index]) return;

  //Calculate interval
  rtimer_clock_t time = RTIMER_NOW() - timer[index];
  measurement_value[measurement_index] = (uint32_t)((uint64_t)time * 1000000 / RTIMER_SECOND);
  measurement_id[measurement_index] = id;

  //Increment Index
  if(measurement_index + 1 == TIMER_COUNT) {
    printf(RED "Measurement Overflow\n" DEFAULT);
  }

  measurement_index = (measurement_index + 1) % TIMER_COUNT;
  clr_pin(index % 8);
  timer[index] = 0;
}

void restart_timer(uint32_t index, uint32_t id) {
  stop_timer(index, id);
  start_timer(index);
}

void print_timer() {
  int i; for(i = 0; i<measurement_index; i++) {
    printf("%02i, id: %lu, duration:(us): %8li\n", i, measurement_id[i], measurement_value[i]);
  }
  measurement_index = 0;
}

PT_THREAD(app_timer(struct pt *pt, struct packet_t *packet)) {
  PT_BEGIN(pt);
  if(INCOMMING.function == CLEAR) {
    measurement_index = 0;
    EXIT_APP(pt, RES_SUCCESS);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == GET_COUNT) {
    OUTGOING.payload.uint8[0] = measurement_index;
    send_result(1);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == GET_VALUES) {
    uint8_t i; for(i = 0; i < measurement_index; i++) {
      OUTGOING.payload.uint32[i*2]   = UIP_HTONL(measurement_id[i]);
      OUTGOING.payload.uint32[i*2+1] = UIP_HTONL(measurement_value[i]);
    }
    send_result((measurement_index)*8);
  } else
  /*--------------------------------------------------------------------------*/
  if(INCOMMING.function == SWITCH_TIMER_OUTPUT) {
    if(UIP_HTONS(packet->payload_length) != 1) {
      ERROR_MSG("payload_length != 1");
      EXIT_APP(pt, RES_WRONG_PARAMETER);
    }
    if(packet->payload.uint8[0]) {
      enable_timer_output();
    } else {
      disable_timer_output();
    }
    EXIT_APP(pt, RES_SUCCESS);
  /*--------------------------------------------------------------------------*/
  } else {
    ERROR_MSG("Unknown Function");
  }
  PT_END(pt);
}
