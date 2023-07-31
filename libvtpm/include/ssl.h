#ifndef __LIB_STUB_VTPM_SSL_H
#define __LIB_STUB_VTPM_SSL_H

#include <stdint.h>

typedef uint8_t byte;
typedef uint32_t word32;

#define WC_SHA512_DIGEST_SIZE 64
#define INVALID_DEVID    (-2)

struct Aes {
};
typedef struct Aes Aes;

enum {
	/* AES_ENC_TYPE   = WC_CIPHER_AES,   /\* cipher unique type *\/ */
	/* AES_ENCRYPTION = 0, */
	/* AES_DECRYPTION = 1, */

	AES_BLOCK_SIZE      = 16,

/*     KEYWRAP_BLOCK_SIZE  = 8, */

/*     GCM_NONCE_MAX_SZ = 16, /\* wolfCrypt's maximum nonce size allowed. *\/ */
/*     GCM_NONCE_MID_SZ = 12, /\* The default nonce size for AES-GCM. *\/ */
/*     GCM_NONCE_MIN_SZ = 8,  /\* wolfCrypt's minimum nonce size allowed. *\/ */
/*     CCM_NONCE_MIN_SZ = 7, */
/*     CCM_NONCE_MAX_SZ = 13, */
/*     CTR_SZ   = 4, */
/*     AES_IV_FIXED_SZ = 4, */
/* #ifdef WOLFSSL_AES_CFB */
/*     AES_CFB_MODE = 1, */
/* #endif */
/* #ifdef WOLFSSL_AES_OFB */
/*     AES_OFB_MODE = 2, */
/* #endif */
/* #ifdef WOLFSSL_AES_XTS */
/*     AES_XTS_MODE = 3, */
/* #endif */

/* #ifdef WOLF_PRIVATE_KEY_ID */
/*     AES_MAX_ID_LEN      = 32, */
/*     AES_MAX_LABEL_LEN   = 32, */
/* #endif */
};

int  wc_AesInit(Aes* aes, void* heap, int devId);
int  wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len);
int  wc_AesGcmEncrypt(Aes* aes, byte* out,
		      const byte* in, word32 sz,
		      const byte* iv, word32 ivSz,
		      byte* authTag, word32 authTagSz,
		      const byte* authIn, word32 authInSz);
int  wc_AesGcmDecrypt(Aes* aes, byte* out,
		      const byte* in, word32 sz,
		      const byte* iv, word32 ivSz,
		      const byte* authTag, word32 authTagSz,
		      const byte* authIn, word32 authInSz);
int  wc_Sha512Hash(const byte* data, word32 len, byte* hash);

#endif /* __LIB_STUB_VTPM_SSL_H */
