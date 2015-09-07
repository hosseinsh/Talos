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
#ifndef TEST_INTERFACE_H_
#define TEST_INTERFACE_H_

#include <project-conf.h>
#include <contiki.h>

#define HEADER_SIZE  8
#define PAYLOAD_SIZE 384
#define PAKET_SIZE   HEADER_SIZE + PAYLOAD_SIZE
#define BUFFER_SIZE  6656
#define MAGIC        0xAAAAAAAA

/*
 * List of all available Applications
 */
enum APPLICATION {
  RES_RESULT_CODE         =  0,
  APP_DEBUG               =  1,
  APP_MANAGEMENT          =  2,
  APP_TIMER               =  3,
  APP_SHA256              =  4,
  APP_CCM                 =  5,
  APP_ECC                 =  6,
  APP_TINYDTLS            =  7,
  APP_AES                 =  8,
  APP_PAILLER             =  9,
  APP_ELGAMAL             = 10,
  APP_BLOWFISH            = 11,
};

/*
 * We encode result codes
 * in function codes
 * Application is always 0
 * Result Codes are all negative
 */
enum RESUL_CODE {
  RES_SUCCESS               =  0,
  RES_ERROR                 = -1,
  RES_WRONG_PARAMETER       = -2,
  RES_UNKOWN_APPLICATION    = -3,
  RES_UNKOWN_FUNCTION       = -4,
  RES_REBOOT                = -5,
  RES_NOT_IMPLEMENTED       = -6,
  RES_ALGORITHM_FAILED      = -7,
  RES_OUT_OF_MEMORY         = -8,
};

/*
 * Debug Levels
 * We map them to Functions
 */
enum DEBUG_FUNCTION {
  LVL_DEBUG               =  1,
  LVL_INFO                =  2,
  LVL_WARNING             =  3,
  LVL_ERROR               =  4,
};

/*
 * Management Functions
 * The first byte in the payload defines
 * if we switch PKA and Crypto on or off
 */
enum MANAGEMENT_FUNCTION {
  REBOOT                  =  1,
  SWITCH_PKA              =  2,
  SWITCH_CRYPTO           =  3,
  READ_BUFFER             =  4,
  WRITE_BUFFER            =  5,
};

enum TIMER_FUNCTION {
  CLEAR                   =  1,
  GET_COUNT               =  2,
  GET_VALUES              =  3,
  SWITCH_TIMER_OUTPUT     =  4,
};

enum SHA256_FUNCTION {
  SELECT_SHA256_ENGINE    =  1,
  CALC_HASH               =  2,
};

enum CCM_FUNCTION {
  SELECT_CCM_ENGINE       =  1,
  CCM_SWITCH_UPLOAD       =  2,
  CCM_SET_KEY             =  4,
  CCM_ENCRYPT             =  5,
  CCM_DECRYPT             =  6,
};

enum AES_FUNCTION {
  SELECT_AES_MODE         =  1,
  AES_SWITCH_UPLOAD       =  2,
  AES_SET_KEY             =  4,
  AES_SET_IV              =  5,
  AES_GET_IV              =  6,
  AES_ENCRYPT             =  7,
  AES_DECRYPT             =  8,
  SELECT_AES_INTERFACE    =  9,
  CMC_ENCRYPT             = 10,
  CMC_DECRYPT             = 11,
  SELECT_AES_ENGINE       = 12,
};

enum ECC_FUNCTION {
  SELECT_ECC_ENGINE       =  1,
  EC_SET_CURVE            =  2,
  EC_SET_GENERATOR        =  3,
  EC_SET_PRIVATE_KEY      =  4,
  EC_SET_PUBLIC_KEY       =  5,
  EC_SET_EPHEMERAL_KEY    =  6,
  EC_MULTIPLY             =  7,
  EC_SIGN                 =  8,
  EC_VERIFY               =  9,
  EC_GENERATE             = 10,
  SWITCH_SIM_MUL          = 11,
};

enum PAILLER_FUNCTION {
  PAILLER_SET_P           =  1,
  PAILLER_SET_Q           =  2,
  PAILLER_SET_PLAINT      =  3,
  PAILLER_GET_PLAINT      =  4,
  PAILLER_SET_CIPHERT     =  5,
  PAILLER_GET_CIPHERT     =  6,
  PAILLER_GEN             =  7,
  PAILLER_ENC             =  8,
  PAILLER_DEC             =  9,
  PAILLER_ADD             = 10,
};

enum ELGAMAL_FUNCTION {
  EG_SET_CURVE            =  1,
  EG_SET_EXPONENT         =  2,
  EG_SET_PLAIN_TEXT       =  3,
  EG_GET_PLAIN_TEXT       =  4,
  EG_GENERATE             =  5,
  EG_MAP_TO_EC            =  6,
  EG_MAP_FROM_EC          =  7,
  EG_ENC                  =  8,
  EG_DEC                  =  9,
  EG_ADD                  = 10,
  EG_MAP_TO_EC_ALT        = 11,
};

enum BLOWFISH_FUNCTION {
  BLOWFISH_INIT           =  1,
  BLOWFISH_ENC            =  2,
  BLOWFISH_DEC            =  3,
};

/**
 * We use an union to simplify access
 * to the elements of various sizes
 */
union payload_u {
  uint8_t  uint8[PAYLOAD_SIZE];
  uint16_t uint16[PAYLOAD_SIZE/2];
  uint32_t uint32[PAYLOAD_SIZE/4];
};

/**
 * We use an union to simplify access
 * to the elements of various sizes
 */
union buffer_u {
  uint8_t  uint8[BUFFER_SIZE];
  uint16_t uint16[BUFFER_SIZE/2];
  uint32_t uint32[BUFFER_SIZE/4];
};

/**
 * Public buffer can be used by all applications
 *
 * It is intended to be used if out/in buffers
 * are to small or several commands access
 * the same data.
 */
extern union buffer_u BUFFER;

/**
 * Definition of the packet sent between
 * the host and the target application
 */
struct __attribute__ ((__packed__)) packet_t {
  uint32_t        magic;
  uint8_t         app;
  int8_t          function;
  uint16_t        payload_length;
  union payload_u payload;
};

/**
 * Incoming data buffer
 * It stores the last packet received
 */
extern struct packet_t INCOMMING;

/**
 * Outgoing data buffer
 * to save space all applications
 * share one outgoing data buffer
 * \note sending a debug message
 * might overwrite your outgoing data
 */
extern struct packet_t OUTGOING;

/**
 * MT-Thread
 * to save space all applications
 * that start long running task
 * share the same thread structure
 */
extern struct mt_thread test_thread;

/**
 * Transmit the packet in the
 * OUTGOING message buffer
 */
extern void send_packet();

/*
 * Transmit an error code
 */
extern void send_result_code(int8_t result_code);
#define CHECK_RESULT(pt, ...) {                                                \
    int result = __VA_ARGS__;                                                  \
    if(result) {                                                               \
      ERROR_MSG("File: %s, Line: %u Error: %i\n", __FILE__, __LINE__,  result);\
      EXIT_APP(pt, (int8_t)result);                                            \
    } }

#define EXIT_APP(pt, result_code) send_result_code(result_code); PT_EXIT(pt);

/*
 * Transmit an result
 */
extern void send_result(uint16_t payload_length);

/*
 * Process handling all communication from to the Python interface
 */
PROCESS_NAME(test_interface_process);

#endif /* TEST_INTERFACE_H_ */
