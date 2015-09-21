# FlockLab Interface Library
The FlockLab Interface library simplifies the GPIO setup in Contiki OS. This directory contains a small example that outputs states on the LED1-LED3 and forwards signals on SIG1-SIG2 to INT1-INT2.

To configure the GPIOs for correct operation call.
```C
void flocklab_init();
```

## Signal Output
To Output Signals you can use the macros from gpio.h with the defines in flocklab-interface.h
To toggle LED1 simply use:
```C
GPIO_SET_PIN(LED_PORT, LED1_MASK);
GPIO_CLR_PIN(LED_PORT, LED1_MASK);
```


## Signal Input
To trigger on actuations you can either poll the GPIO or register a callback. To read inputs you can use macros from gpio.h with the defines in flocklab-interface.h:

```C
if(GPIO_READ_PIN(SIG_PORT, SIG1_MASK)) {

} else {

}
```

Registering a callback works the usual way the flocklab\_register\_callback function registers the call back with gpio\_register\_callback and configures the NVIC for you. The callback is registered for both edges and to for all power levels including PM2.

```C
static void signal_cb(uint8_t port, uint8_t pin) {
  //Handle Signal
}

PROCESS_THREAD(flocklab_idle_process, ev, data) {
  PROCESS_BEGIN();
  flocklab_init();
  flocklab_register_callback(signal_cb, SIG1_PIN);
  PROCESS_END();
}
```

## Serial I/O
Only UART0 of the OpenMote is connected to the serial interface of the FlockLab-Observer (the USB interface isn't). If you want to communicate to the target or trace the target using the serial interface, you have to explicitly select it in the FlockLab Test Configuration. 

```XML
<serialConf>
  <obsIds>016 018 022 023 024</obsIds>
  <baudrate>115200</baudrate>
  <mode>ascii</mode>
  <port>serial</port>
</serialConf>
```
