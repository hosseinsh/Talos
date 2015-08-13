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
#include "mtarch.h"
#include "reg.h"
#include "scb.h"
#include "mt.h"

#include <string.h>

void clock_isr(void);

/**
 * Pointer to the next Thread or NULL if we return to main
 */
static struct mtarch_thread *next_thread = 0;

/**
 * Pointer to the current Thread or NULL if it the main
 */
static struct mtarch_thread *current_thread = 0;

/**
 * Pointer to the msp
 */
static void* msp = 0;

/**
 * Tick Counter used to time slice duration
 */
static uint32_t tick_count = 0;

/**
 * Forced preemption inhibit
 */
static uint8_t preemption_stopped = 1;

/**
 * Backup Context return SP
 */
static inline void* save_context(void) {
  void *sp = 0;
  asm volatile ("cpsid i             \n"           //Disable Interrupts
                "dsb                 \n"           //Data Synchronization Barrier
                "isb                 \n"           //Instruction Synchronization Barrier
                "mrs   %0, msp       \n"           //Read SP
                "stmdb %0!, {r4-r11} \n"           //Push Registers onto Stack
                "msr   msp, %0" : "=r" (sp));      //Update StackPointer
  return sp;
}

/**
 * Restore Context from Stack pointed to by SP
 */
static inline void load_context(void* sp){
  asm volatile ("ldmfd %0!, {r4-r11} \n"           //Pop Registers from Stack
                "msr msp, %0         \n"           //Update StackPointer
                "cpsie i " : : "r" (sp));          //ReEnable Interrupts
}

void mtarch_init(void) {
  //Set PendSV Priority below SysTick to avoid nesting
  REG(SCB_SYSPRI3) |= 0x03 << SCB_INTCTRL_PRI3_PENDSV_S;
}

void mtarch_start(struct mtarch_thread *thread,
                  void (* function)(void *data),
                  void *data) {

  //Calculate SP
  stack_struture_t* sp = (stack_struture_t*) &thread->stack[MTARCH_STACKSIZE - MTARCH_REGISTER_COUNT];
  thread->sp = sp;

  //Zero Stack
  memset(thread->stack, '\0', sizeof(void*) * MTARCH_STACKSIZE);

  //Fill Stack
  sp->r0  = data;
  sp->lr  = mt_exit;
  sp->pc  = function;
  sp->psr = (void*)0x01000000;
}

/**
 * Stack Switcher
 *
 * Be care full when modifying this implementation.
 * If the compiler requires more then 4 registers, the
 * stack alignment of new threads will be off.
 */
void pend_sv_isr(void) {
  //Backup Current Thread
  void *sp = save_context();

  if(current_thread) {
    current_thread->sp = sp;
  } else {
    msp = sp;
  }

  //Switch Threads
  current_thread = next_thread;
  next_thread    = 0;

  //Restore Next Thread
  if(current_thread) {
    sp = current_thread->sp;
  } else {
    sp = msp;
  }
  load_context(sp);
}

/**
 * Force Preemption after 7-14ms
 */
void preemption_isr(void) {
  if(tick_count && current_thread && !preemption_stopped) {
    //Trigger PendSV the handler will switch to main
    //It has lower priority therefore it is not nested
    mt_yield();
  } else {
    tick_count++;
  }
  clock_isr();
}

void mtarch_yield(void) {
  //Trigger PendSV the handler will switch to main
  REG(SCB_INTCTRL) = SCB_INTCTRL_PEND_SV;
}

void mtarch_exec(struct mtarch_thread *thread) {
  //Clear Tick Count
  tick_count = 0;

  //Enable preemption
  preemption_stopped = 0;

  //Point to the next thread
  next_thread = thread;

  //Trigger PendSV the handler will do the switch
  REG(SCB_INTCTRL) = SCB_INTCTRL_PEND_SV;
}

void mtarch_stop(struct mtarch_thread *thread) {

}

void mtarch_pstart(void) {
  //Check if time slice was exceeded while
  //preemption_stopped was set
  if(tick_count && current_thread) {
    mt_yield();
  }
  preemption_stopped = 0;
}

void mtarch_pstop(void) {
  preemption_stopped = 1;
}
