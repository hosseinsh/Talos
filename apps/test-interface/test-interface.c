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

//Contiki OS Includes
#include <contiki.h>
#include <contiki-lib.h>
#include <contiki-net.h>
#include <mt.h>

//System Includes
#include <stdio.h>
#include <string.h>

//Additional Apps and Drivers
#include <uart.h>
#include <app_debug.h>
#include <test-interface.h>
#include <serial-line.h>
#if HAVE_FLOCKLAB == 1
#include <flocklab-interface.h>
#endif

//Test Interface Apps
#include <app_ccm.h>
#include <app_aes.h>
#include <app_ecc.h>
#include <app_management.h>
#include <app_blowfish.h>
#include <app_sha256.h>
#include <app_timer.h>
#include <app_tinydtls.h>
#include <app_pailler.h>
#include <app_elgamal.h>

//Define Process
PROCESS(test_interface_process, "Test Interface Process");

//Public buffers they are access by all applications
#if USE_APP_SHA256 || USE_APP_CCM || USE_APP_ECC
union  buffer_u BUFFER;
#endif
struct packet_t INCOMMING;
struct packet_t OUTGOING;

//Public MT-Thread used by all applications
struct mt_thread test_thread;

//Event fired when a full packet is in the input buffer
static process_event_t packet_received;

void send_packet() {
  char* buf      = (char*)&OUTGOING;
  uint32_t i     = 0;
  uint32_t size  = HEADER_SIZE + UIP_HTONS(OUTGOING.payload_length);
  OUTGOING.magic = MAGIC;
  for(i = 0; i<size; i++) {
    uart_write_byte(0, buf[i]);
  }
}

void send_result_code(int8_t result_code) {
  OUTGOING.app      = RES_RESULT_CODE;
  OUTGOING.function = result_code;
  OUTGOING.payload_length = 0;
  send_packet();
}

void send_result(uint16_t payload_length) {
  OUTGOING.app      = RES_RESULT_CODE;
  OUTGOING.function = RES_SUCCESS;
  OUTGOING.payload_length = UIP_HTONS(payload_length);
  send_packet();
}

/**
 * We exploit that fact that the Host application sends at most
 * one packet at the time. We do not have to handle delays
 * introduced by the notification mechanism.
 */
int receive_cb(unsigned char c) {
  //Pointer to the next byte in the input buffer
  static uint32_t pos   = 0;
  //Number of successive magic bytes
  static uint16_t count = 0;
  //Payload length in Host Byte Order
  static uint16_t payload_length = 0x0fff;
  //Pointer to input buffer
  static char* buf = (char*)&INCOMMING;

  //Wait for magic header
  if(pos == 0) {
    if(c == 0xAA) {
      count++;
      //Rewind input pointer on every magic header
      if(count == 4) {
        pos = 4;
        count = 0;
        payload_length = 0x0fff;
      }
    } else {
      count = 0;
    }
  } else {
  //Read Packet
    buf[pos++] = c;

    //Read payload length
    if(pos == HEADER_SIZE) {
      payload_length = UIP_HTONS(INCOMMING.payload_length);
    }

    //Notify Test Interface Process on new packet
    if(pos == HEADER_SIZE + payload_length) {
      process_post(&test_interface_process, packet_received, (process_data_t*)pos);
      pos = 0;
    }

  }
  return 1;
}

/**
 * The Test Interface accepts commands trough the serial console
 * and processes them. The communication uses simple proprietary
 * protocol. Requests and responses are all received sent
 * inform of the above struct using network byte order.
 */
PROCESS_THREAD(test_interface_process, ev, data) {
  PROCESS_BEGIN();

  //Initialize GPIOs
  #if HAVE_FLOCKLAB == 1
  flocklab_init();
  #endif

  //Prepare high resolution timer
  init_high_res_timer();

  //Disable Wireless
  NETSTACK_MAC.off(0);
  NETSTACK_RDC.off(0);
  NETSTACK_RADIO.off();

  //Allocate EventID
  packet_received = process_alloc_event();

  //Replace Serial Input Handler
  uart_set_input(0, receive_cb);

  //Notify host system about Boot/Reboot
  INFO_MSG("Test-Interface ready");
  send_result_code(RES_REBOOT);

  while(1) {
    //Wait for Command
    PROCESS_WAIT_EVENT_UNTIL(ev == packet_received);

    //Check if header is correct
    if((uint32_t)data < HEADER_SIZE) {
      ERROR_MSG("data_len < HEADER_SIZE");
      continue;
    }

    //Check if payload it plausible
    if(UIP_HTONS(INCOMMING.payload_length) != (uint32_t)data - HEADER_SIZE) {
      ERROR_MSG("payload_length != data_len - HEADER_SIZE");
      send_result_code(RES_WRONG_PARAMETER);
      continue;
    }

    //Switch statements could lead to runtime errors. see(\r pt)
    static struct pt pt; PT_INIT(&pt);
    if(INCOMMING.app == APP_MANAGEMENT) {
      while(PT_SCHEDULE(app_management(&pt, &INCOMMING))) {
        PROCESS_PAUSE();
      };
    } else
    if(INCOMMING.app == APP_TIMER) {
      while(PT_SCHEDULE(app_timer(&pt, &INCOMMING))) {
        PROCESS_PAUSE();
      };
    } else
    #if USE_APP_SHA256
    if(INCOMMING.app == APP_SHA256) {
      while(PT_SCHEDULE(app_sha256(&pt, &INCOMMING))) {
        PROCESS_PAUSE();
      };
    } else
    #endif
    #if USE_APP_CCM
    if(INCOMMING.app == APP_CCM) {
      while(PT_SCHEDULE(app_ccm(&pt, &INCOMMING))) {
        PROCESS_PAUSE();
      };
    } else
    #endif
    #if USE_APP_AES
    if(INCOMMING.app == APP_AES) {
      while(PT_SCHEDULE(app_aes(&pt, &INCOMMING))) {
        PROCESS_PAUSE();
      };
    } else
    #endif
    #if USE_APP_ECC
    if(INCOMMING.app == APP_ECC) {
      while(PT_SCHEDULE(app_ecc(&pt, &INCOMMING))) {
        PROCESS_PAUSE();
      };
    } else
    #endif
    #if USE_APP_TINYDTLS
    if(INCOMMING.app == APP_TINYDTLS) {
      while(PT_SCHEDULE(app_tinydtls(&pt, &INCOMMING))) {
        PROCESS_PAUSE();
      };
    } else
    #endif
    if(INCOMMING.app == APP_BLOWFISH) {
      while(PT_SCHEDULE(app_blowfish(&pt, &INCOMMING))) {
        PROCESS_PAUSE();
      };
    } else
    if(INCOMMING.app == APP_ELGAMAL) {
      while(PT_SCHEDULE(app_elgamal(&pt, &INCOMMING))) {
        PROCESS_PAUSE();
      };
    } else
    if(INCOMMING.app == APP_PAILLER) {
      while(PT_SCHEDULE(app_pailler(&pt, &INCOMMING))) {
        PROCESS_PAUSE();
      };
    } else
    {
      ERROR_MSG("Unknown Application");
      send_result_code(RES_UNKOWN_APPLICATION);
    }
  }

  PROCESS_END();
}
