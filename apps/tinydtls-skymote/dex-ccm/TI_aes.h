/**************************************************************
The following file is part of the AES implementation for MSP430
provided by TEXAS INSTRUMENTS
**************************************************************/

#ifndef TI_AES
#define TI_AES

void aes_encrypt(unsigned char *state, unsigned char *key);
void aes_decrypt(unsigned char *state, unsigned char *key);

#endif
