#ifndef __LIB_STUB_VTPM_TPM_H
#define __LIB_STUB_VTPM_TPM_H

struct TPMT_PUBLIC {
};
typedef struct TPMT_PUBLIC TPMT_PUBLIC;

void _plat__Signal_PowerOn(void);
int  _plat__Signal_Reset(void);
int  _plat__NVEnable(void *platParameter);
void _plat__NVDisable(int delete);
void _plat__SetNvAvail(void);
int  _plat__NVNeedsManufacture(void);
int  TPM_Manufacture(int firstTime);
int  TPM_TearDown(void);
void ExecuteCommand(uint32_t requestSize, unsigned char *request,
		    uint32_t *responseSize, unsigned char **response);

#endif /* __LIB_STUB_VTPM_TPM_H */
