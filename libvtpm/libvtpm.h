#pragma once

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

typedef uint64_t size_t;

typedef uint8_t byte;
typedef uint32_t word32;

size_t strlen(const char *s);

# define SHA512_DIGEST_LENGTH    64
unsigned char *SHA512(const unsigned char *data, size_t count, unsigned char *md_buf);

struct TPMT_PUBLIC {
};
typedef struct TPMT_PUBLIC TPMT_PUBLIC;

int  _plat__Signal_PowerOn(void);
int  _plat__Signal_Reset(void);
int  _plat__NVEnable(void *platParameter);
void _plat__NVDisable(int delete);
void _plat__SetNvAvail(void);
int  _plat__NVNeedsManufacture(void);
int  TPM_Manufacture(int firstTime);
int  TPM_TearDown(void);
void ExecuteCommand(uint32_t requestSize, unsigned char *request,
		    uint32_t *responseSize, unsigned char **response);

typedef uint32_t TPM_RC;
typedef uint16_t TPM_SU;

#define TPM_RC_SUCCESS                  (0x000)
#define TPM_SU_CLEAR	(TPM_SU)(0x0000)

// Input structure definition
typedef struct
{
    TPM_SU startupType;
} Startup_In;

TPM_RC TPM2_Startup(Startup_In *in);

struct tpm_req_header {
    uint16_t tag;
    uint32_t size;
    uint32_t ordinal;
} __attribute__((packed));

struct tpm_resp_header {
    uint16_t tag;
    uint32_t size;
    uint32_t errcode;
} __attribute__((packed));

struct tpm2_authblock {
    uint32_t auth;
    uint16_t foo; // FIXME
    uint8_t continueSession;
    uint16_t bar; // FIMXE
} __attribute__((packed));

struct tpm2_evictcontrol_req {
    struct tpm_req_header hdr;
    uint32_t auth;
    uint32_t objectHandle;
    uint32_t authblockLen;
    struct tpm2_authblock authblock;
    uint32_t persistentHandle;
} __attribute__((packed));

struct Regs {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};
