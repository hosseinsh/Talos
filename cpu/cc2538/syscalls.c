/*
 * Copyright (c) 2014 Andreas Dröscher <contiki@anticat.ch>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
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
