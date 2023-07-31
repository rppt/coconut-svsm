#include <stdlib.h>
#include <ssl.h>
#include <Tpm.h>

/************************************************************************/
/* stdlib */
size_t strlen(const char *s)
{
	return 0;
}

/************************************************************************/
/* wolfssl */
int  wc_AesInit(Aes* aes, void* heap, int devId)
{
	return 0;
}

int  wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len)
{
	return 0;
}

int  wc_AesGcmEncrypt(Aes* aes, byte* out,
		      const byte* in, word32 sz,
		      const byte* iv, word32 ivSz,
		      byte* authTag, word32 authTagSz,
		      const byte* authIn, word32 authInSz)
{
	return 0;
}

int  wc_AesGcmDecrypt(Aes* aes, byte* out,
		      const byte* in, word32 sz,
		      const byte* iv, word32 ivSz,
		      const byte* authTag, word32 authTagSz,
		      const byte* authIn, word32 authInSz)
{
	return 0;
}

int  wc_Sha512Hash(const byte* data, word32 len, byte* hash)
{
}

/************************************************************************/
/* TPM */
void _plat__Signal_PowerOn(void)
{
}

int  _plat__Signal_Reset(void)
{
	return 0;
}

int  _plat__NVEnable(void *platParameter)
{
	return 0;
}

void _plat__NVDisable(int delete)
{
}

void _plat__SetNvAvail(void)
{
}

int  _plat__NVNeedsManufacture(void)
{
	return 0;
}

int  TPM_Manufacture(int firstTime)
{
	return 0;
}

int  TPM_TearDown(void)
{
	return 0;
}

void ExecuteCommand(uint32_t requestSize, unsigned char *request,
		    uint32_t *responseSize, unsigned char **response)
{
}
