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
 */
#include "contiki.h"
#include "contiki-lib.h"
#include "dev/leds.h"
#include "dev/rom-util.h"
#include "dev/button-sensor.h"

#include <string.h>

PROCESS(flash_erase_process, "Flash Erase Process");

PROCESS_THREAD(flash_erase_process, ev, data) {
  PROCESS_BEGIN();

  /*
   * Activate Sensors
   */
  SENSORS_ACTIVATE(button_sensor);

  /*
   * Wait for Button 2
   */
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(ev == sensors_event);
    if(data == &button_user_sensor) {
      leds_toggle(LEDS_GREEN);
      rom_util_page_erase(0x27F800, 0x800);
      clock_delay_usec(5000);
      rom_util_reset_device();
    }
  }

  PROCESS_END();
}
