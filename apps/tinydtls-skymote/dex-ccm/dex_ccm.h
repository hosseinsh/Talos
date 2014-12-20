/*
 *
 * Author: Christian Röller, Jens Hiller
 *
 */

#ifndef DEX_CCM_H_
#define DEX_CCM_H_

#include <stdint.h> /* uint8_t */

// should not be greater than 16 because CBC-CMAC gives us only 16 byte
#define AES_CCM_M       8 // we have test vectors for M=8 and M=10
#define AES_CCM_L       2 // we have test vectors for 13 bytes long Nonce => 15 - L = 13 => L = 2
#define AES_CCM_BLOCK   16


//static int aes_ctr_ccm(uint8_t *key, uint8_t *nonce, uint8_t *plain, int adata_len,
//					   int input_len, uint8_t *cipher, uint8_t mac[16], int mode);

/**
* @param key       16 byte key
* @param nonce     '15 - AES_CCM_L' bytes as nonce
* @param plain     pointer to plain text
* @param adata_len length of ADATA
* @param plain_len length of plain text in bytes
*                  (including the data which will only be authenticated)
* @param cipher    pointer to the addressspace where the encrypted data is written
*                  must have size of "length of plain + AES_CCM_M"
* @return          len on success, negative on error
*/
int aes_ccm_encrypt(uint8_t *key, uint8_t *nonce, uint8_t *plain, int adata_len,
					int plain_len, uint8_t *cipher);

/**
* @param key        16 byte key
* @param nonce      '15 - AES_CCM_L' bytes as nonce
* @param cipher     pointer to the addressspace where the encrypted data is written
* @param cipher_len length of cipher text in bytes
* @param plain      pointer to plain text
*                   must have size of "length of plain + AES_CCM_M"
* @param adata_len  length of ADATA
* @return           len on success (decryption and authentication), negative on error
*                   and a zero erased plain
*/
int aes_ccm_decrypt(uint8_t *key, uint8_t *nonce, uint8_t *cipher, int cipher_len,
					uint8_t *plain, int adata_len);

#endif
