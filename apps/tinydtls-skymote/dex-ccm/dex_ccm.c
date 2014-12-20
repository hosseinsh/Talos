/*
 *
 * Author: Christian Röller, Jens Hiller
 *
 */

#include <stdio.h>
#include <stdint.h> //uint8_t
#include <string.h> // memcpy
#include <stdlib.h> // malloc

#if AES_HARDWARE_CC2520
  #if CONTIKI_TARGET_SKY
  #include "../../dev/cc2420/cc2420-aes.h"
  #define _aes_set_key(...) cc2420_aes_set_key(__VA_ARGS__)
  #define _aes_cipher(...) cc2420_aes_cipher(__VA_ARGS__)
  #elif CONTIKI_TARGET_WISMOTE
  #include <cc2520.h>
  #define _aes_set_key(...) cc2520_aes_set_key(__VA_ARGS__)
  #define _aes_cipher(...) cc2520_aes_cipher(__VA_ARGS__)
  #endif /* SKY or WISMOTE */
#else  /* AES_HARDWARE_CC2520 */
#include "TI_aes.h"
#endif /* AES_HARDWARE_CC2520 */

#include "dex_ccm.h"
#include "dex_cmac.h"

#define MIN(a, b)   ((a) < (b) ? (a) : (b))
#define CCM_DEBUG  0

#define ENCRYPTION 1
#define DECRYPTION 2

#define XOR(v, r, len)                  \
do {                                    \
	int k;                              \
	for (k = 0; k < (len); k++){        \
		(r)[k] = (r)[k] ^ (v)[k];       \
	}                                   \
} while (0)                             \

#define EVAL_SYMMETRIC_CRYPTO         0
#if EVAL_SYMMETRIC_CRYPTO
#include "rtimer.h"
static rtimer_clock_t start_time;
static rtimer_clock_t end_time;
#define START_TIMER_S start_time = clock_counter()
#define STOP_TIMER_S end_time = clock_counter()
#define PRINT_EVAL_S(modul, len) printf("Energy (%s_sym_%d): cpu %u %u \n", modul,len, (end_time - start_time), RTIMER_ARCH_SECOND)
#else /*EVAL_SYMMETRIC_CRYPTO*/
#define START_TIMER_S
#define STOP_TIMER_S
#define PRINT_EVAL_S
#endif /*EVAL_SYMMETRIC_CRYPTO*/


/**
* @param key       16 byte key
* @param nonce     '15 - AES_CCM_L' bytes as nonce
* @param plain     pointer to plain text
* @param adata_len length of ADATA
* @param input_len length of plain text or cipher in bytes depending on mode
* @param cipher    pointer to the addressspace where the encrypted data is written
*                  must have size of "length of plain + AES_CCM_M"
* @param mac       pointer to computed AES-CBC-MAC, will be used to compute
*                  authentication value U in ENCRYPTION mode.
* @param mode      specify modus, means if function should encrypt or decrypt.
*                  Depending on modus the result is saved in plain or cipher.
*                  1 = ENCRYPTION, 2 = DECRYPTION
* @return          0 on success, negative on error
*/
static int aes_ctr_ccm(uint8_t *key, uint8_t *nonce, uint8_t *plain, int adata_len,
					   int input_len, uint8_t *cipher, uint8_t mac[16], int mode){

	int real_length;
	// ADATA should not be encrypted so real length of plain is: or cipher is:
	if(mode == ENCRYPTION){
		real_length = input_len - adata_len;
	}
	else{
		// MAC decryption is specially handled by S_0:
		real_length = input_len - adata_len - AES_CCM_M;
	}

	/*
	 * Compute number of stream blocks, which are necessary to
	 * XOR the plain, in case plain is no multiple of block size
	 * the result will be round up
	 */
	int num_of_stream_blocks = (real_length+15)/16;

	// 2 byte counter
	if (num_of_stream_blocks > 65535){
		return -1;
	}

	// stream block for round i
	uint8_t S_i[AES_CCM_BLOCK];

	// set pointer on plain or cipher depending on mode
	uint8_t *target_pointer;
	if(mode == ENCRYPTION){
		memcpy(cipher, plain, input_len);
		target_pointer = cipher + adata_len;
	}
	else{
		memcpy(plain, cipher, input_len - AES_CCM_M);
		// save M-bytes in mac datastructure for later decryption
		memcpy(mac, cipher + (input_len - AES_CCM_M), AES_CCM_M);
		target_pointer = plain + adata_len;
	}

	// counter variable
	uint16_t i;

	// counter as BIG_ENDIAN
	uint16_t count;

	int rest_of_input;
	for(i=0; i <= num_of_stream_blocks; i++){

		memset(S_i, 0, AES_CCM_BLOCK);

		// flags = L' = AES_CCM_L - 1
		S_i[0] = AES_CCM_L - 1;

		// nonce, sizeof('15 - AES_CCM_L')
		memcpy(&(S_i[1]), nonce, 15-AES_CCM_L);

		// counter i in most-significant-byte first order
		count = ((i>>8)&0xff)+((i << 8)&0xff00);
		memcpy(&(S_i[16-AES_CCM_L]), &count, AES_CCM_L);

#if CCM_DEBUG
		int j;
		if (i == 1){
			printf("CTR Start: ");
			for(j = 0; j < 16; j++){
				printf("%02X", S_i[j]);
				if (j+1 < 16){
					printf(" - ");
				}
				else{
					printf("\n");
				}
			}
		}
#endif

#if AES_HARDWARE_CC2520
		_aes_set_key(key, 0);
		_aes_cipher(S_i, AES_CCM_BLOCK, 0);
#else /* AES_HARDWARE_CC2520 */
		aes_encrypt(S_i,key);
#endif /* AES_HARDWARE_CC2520 */

#if CCM_DEBUG
		int end;
		if (i == 0){
			printf("CTR(MAC): ");
			end = 8;
		}
		else{
			printf("CTR(%i): ", i);
			end = 16;
		}
		for(j = 0; j < end; j++){
			printf("%02X", S_i[j]);
			if (j+1 < end){
				printf(" - ");
			}
			else{
				printf("\n");
			}
		}
#endif

		// block 0 is not used for en-, decryption
		if (i > 0){
			rest_of_input = (real_length - (i*16));
			if (rest_of_input > 0){
				XOR(S_i, target_pointer, 16);
				target_pointer += 16;
			}
			else{
				XOR(S_i, target_pointer, real_length - (i*16) + 16);
			}
		}
		else{
			// en-, decrypt MAC
			XOR(S_i, mac, AES_CCM_M);
		}
	}

	// save encrypted MAC, so value U at the end of cipher
	if (mode == ENCRYPTION){
		memcpy(cipher+input_len, mac, AES_CCM_M);
	}

	return 0;
}

/**
 * calculate the mac part of ccm before starting encrypting
 *
 * @param key           key used to calculate AES_CCM
 * @param nonce         nonce used to calculate AES_CCM
 * @param plain         plaintext of CCM
 * @param adata_len     length of data which should only be authenticated but not encrypted (in bytes)
 * @param cipher_len    'length of plain' - adata_len
 * @param cbc_mac       array in which the mac is written. MUST be able to store >= 16 bytes
 * @return              0 on success, negative on error
 */
static int aes_ccm_mac(uint8_t *key, uint8_t *nonce, uint8_t *plain, int adata_len, int cipher_len, uint8_t *cbc_mac){

  int i;

  AES_CMAC_CTX ctx;
  AES_CMAC_Init(&ctx);
  AES_CMAC_SetKey(&ctx, key);

  /*** B_0 ***/
  /* Flags = 64*Adata + 8*M' + L'
   * M' = (M-2)/2
   * L' = L-1   */
  if(adata_len > 0){
    cbc_mac[0] = 64 + 8*((AES_CCM_M-2)/2) + (AES_CCM_L - 1);
  }else{
    cbc_mac[0] = 8*((AES_CCM_M-2)/2) + (AES_CCM_L - 1);
  }

  // append nonce
  memcpy(cbc_mac+1, nonce, 15-AES_CCM_L);

  // append l(m) in most significant byte first order
  // if the datatype of plain_len is changed this needs additional work
  cbc_mac[14] = cipher_len >> 8;
  cbc_mac[15] = 0xff & cipher_len;

  AES_CMAC_Update(&ctx, cbc_mac, 16);

  /*** encoding of Adata ***/
  if(adata_len >= 65280 ){
    /* cases (2^16 - 2^8) <= l(a) < 2^32
     * and 2^32 <= l(a) < 2^64
     * are not supported
     */
    return -1;
  }

  if(adata_len > 0){
    memset(cbc_mac, 0, 16);
    // 0 < l(a) < (2^16 - 2^8)
    cbc_mac[0] = adata_len >> 8;
    cbc_mac[1] = 0xff & adata_len;
    // fill the block to 16 bytes
    memcpy(cbc_mac+2, plain, MIN(14, adata_len));

    AES_CMAC_Update(&ctx, cbc_mac, 16);

    if(adata_len > 14){
      // multiple of 16 byte
      AES_CMAC_Update(&ctx, plain+14, (adata_len-14)-((adata_len-14)%16));

      if((adata_len-14)%16 > 0){
        // padding
        memset(cbc_mac, 0, 16);
        memcpy(cbc_mac, plain+adata_len-((adata_len-14)%16), (adata_len-14)%16);
        AES_CMAC_Update(&ctx, cbc_mac, 16);
      }
    }
  }

  /*** append message ***/
  // multiple of 16 byte
  AES_CMAC_Update(&ctx, plain+adata_len, cipher_len-(cipher_len%16));

  if(cipher_len%16 > 0){
    // padding
    memset(cbc_mac, 0, 16);
    memcpy(cbc_mac, plain+adata_len+cipher_len-(cipher_len%16), cipher_len%16);
    AES_CMAC_Update(&ctx, cbc_mac, 16);
  }

  /*
   * Note that AES_CMAC is NOT CBC-MAC. In AES_CMAC the last encryption is done with
   * another key. Thus we can not use AES_CMAC_Final(...) here. But we are missing the
   * last XOR and encryption operation.
   * A simple hack to achieve these last operations is to give AES_CMAC_Update 1 byte.
   * The function will not do anything with this 1 byte because it thinks it will
   * be used with AES_CMAC_Final. But doing so it knows that the last 16 byte it remembers
   * are not the bytes for AES_CMAC_Final and starts the XOR and encryption for these memorized
   * bytes which is exactly what we want.
   * The only thing which is important is that ctx.M_n = 16 which is always the case because we
   * ensure this with the padding.
   * (B_0 has 16 byte, l(a)|adata is padded to multiple of 16 byte and plain is padded to multiple of 16 byte
   */
  AES_CMAC_Update(&ctx, cbc_mac, 1);

  // Finally copy the data to cbc_mac
  memcpy(cbc_mac, ctx.X, 16);

#if CCM_DEBUG
  printf("cbc_mac: ");
  for(i=0; i<16; i++){
    printf("%02x ", cbc_mac[i]);
  }
  printf("\n");
#endif

  return 0;

}

int aes_ccm_encrypt(uint8_t *key, uint8_t *nonce, uint8_t *plain, int adata_len, int plain_len, uint8_t *cipher){
  START_TIMER_S;
  if(plain_len == 0){
    return -1;
  }

  uint8_t *cbc_mac = malloc(16);
  if(cbc_mac == 0){
    return -1;
  }

  aes_ccm_mac(key, nonce, plain, adata_len, plain_len-adata_len, cbc_mac);

  aes_ctr_ccm(key, nonce, plain, adata_len, plain_len, cipher, cbc_mac ,ENCRYPTION);

  free(cbc_mac);

  STOP_TIMER_S;
  PRINT_EVAL_S("AES_ENC", plain_len);
  return plain_len + AES_CCM_M;
}

int aes_ccm_decrypt(uint8_t *key, uint8_t *nonce, uint8_t *cipher,
					int cipher_len, uint8_t *plain, int adata_len){
  START_TIMER_S;
	if(cipher_len == 0){
		return -1;
	}

	uint8_t *cbc_mac_recv = malloc(16);
	if(cbc_mac_recv == 0){
		return -1;
	}

	aes_ctr_ccm(key, nonce, plain, adata_len, cipher_len, cipher, cbc_mac_recv ,DECRYPTION);

	uint8_t *cbc_mac_comp = malloc(16);
	if(cbc_mac_comp == 0){
		return -1;
	}
	//                                              plain_len
	aes_ccm_mac(key, nonce, plain, adata_len, (cipher_len-AES_CCM_M) - adata_len, cbc_mac_comp);

	int res = -1;
	if (!memcmp(cbc_mac_recv, cbc_mac_comp, AES_CCM_M)){
		res = cipher_len - AES_CCM_M;
	}
	else{
		memset(plain, 0, cipher_len - AES_CCM_M);
	}

	free(cbc_mac_recv);
	free(cbc_mac_comp);

	STOP_TIMER_S;
	PRINT_EVAL_S("AES_DEC", cipher_len);

	return res;
}
