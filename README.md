Talos: Encrypted Query Processing for the Internet of Things (Source code of our paper at ACM SenSys 2015)
============================

In this repo we share the code used for our Talos paper published in ACM SenSys 2015.
Talos is proto-type implementation of encrypted data processing for IoT data. To show the feasablity and practicablity of encrypted data processing for the IoT, we have implemented a set of encryption algorithms for the OpenMote platform in the Contiki OS. We have utilized the hardware crypto acceleator to make the crypto operations more efficient.

OpenMotes (see http://www.openmote.com/) are based on the TI CC2538 microcontroller, i.e., 32-bit ARM Cortex-M35 SoC at 32 MHz, with a public-key cryptographic accelerator running up to 250 MHz. They are equipped with 802.15.4 compliant RF transceivers, 32 kB of RAM and 512 kB of ROM.

We integrate the following encryption schemes in our system:
  * Standard AES-modes, and AES-CMC
  * Blowfish
  * Paillier in hardware
  * EC-ElGamal in hardware
  * mOPE client

Important modlues that could be re-used in other projects are:
  * the drivers for the crypto engine in cpu/cc2538/dev/
  * example code how to use the crypo engines' API in example/cc2538dk/crypto/
  * benchmark code is as well in example/cc2538dk/crypto/
  * mOPE and Blowfish are in apps/

Main contributors to this repo are:
 * Andreas Dröscher <contiki@anticat.ch>
 * Hossein Shafagh <shafagh@inf.ethz.ch>

Please reference our paper, in of using any part of this repo:
@inproceedings{shafagh_Talos_Sensys15,
author = "Hossein Shafagh and Anwar Hithnawi and Andreas Dröscher and Simon Duquennoy and Wen Hu",
title = "Talos: Encrypted Query Processing for the Internet of Things",
year = "2015",
month = nov,
booktitle = "Proceedings of the 13th ACM Conference on Embedded Networked Sensor Systems (SenSys’15). Seoul, South Korea",
}
