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
#include <stdio.h>
#include <string.h>
#include <log.h>

char *allocated = 0;

caddr_t __attribute__ ((used)) _sbrk(int incr) {
  extern char _heapdata;  // symbols are defined in cc2538.lds
  extern char _eheapdata; // they mark end of bss and end of memory.

  if (allocated == 0) {
    printf("Heap size: 0x%08x\n", (unsigned int)&_eheapdata - (unsigned int)&_heapdata);
    allocated = &_heapdata;
  }

  if (allocated + incr > &_eheapdata) {
    printf(RED "Out of heap space!\n" DEFAULT);
    return (caddr_t)0;
  } else {
    allocated += incr;
    return (caddr_t) allocated - incr;
  }
}

int _open(const char *name, int flags, int mode) {
  return 1;
}

int _close(int file) {
  return 1;
}

short _isatty(int fd) {
  return 1;
}

int _read(int file, char *ptr, int len) {
  return 0;
}

int _write(int file, const char *ptr, int len) {
  static char buf[256];
  if(len > 255) len = 255;
  memcpy(buf, ptr, len);
  buf[len] = '\0';
  printf("%s", buf);
  return len;
}

int _lseek(int file, int ptr, int dir) {
  return 0;
}

int _fstat(int file, void* st) {
  return 0;
}

void _exit(int status) {
  printf(RED "Exit called!\n" DEFAULT);
  while(1);
}
