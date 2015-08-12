Talos: Encrypted Query Processing for the Internet of Things (Source code of our paper at ACM SenSys 2015)
============================

In this repo we share the code used for our Talos paper published in ACM SenSys 2015.
Talos is proto-type implementation of encrypted data processing for IoT data. To show the feasablity and practicablity of encrypted data processing for the IoT, we have implemented a set of encryption algorithms for the OpenMote platform in the Contiki OS. We have utilized the hardware crypto acceleator to make the crypto operations more efficient.

We integrate the following encryption schemes in our system:
  * Standard AES-modes, and AES-CMC
  * Blowfish
  * Paillier in hardware
  * EC-Elgmal in hardware
  * mOPE client


Main contributors to this repo are:
 * Andreas Dröscher <contiki@anticat.ch>
 * Hossein Shafagh <shafagh@inf.ethz.ch>
