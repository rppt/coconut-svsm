LIBCRT_DIR = $(CURDIR)/libcrt
OPENSSL_DIR = $(CURDIR)/openssl
LIBTPM_DIR = $(CURDIR)/ms-tpm-20-ref/TPMCmd

LIBCRT = $(LIBCRT_DIR)/libcrt.a
LIBCRYPTO = $(OPENSSL_DIR)/libcrypto.a
LIBTPM = libtpm.a
LIBPLATFORM = libplatform.a
LIBS = $(LIBCRT) $(LIBCRYPTO) $(LIBTPM) $(LIBPLATFORM)

all: libvtpm.a

built-in.a: $(LIBS)
	rm -f $@
	ar cDPrST $@ $(LIBS)

built-in.o: built-in.a
	ld -z noexecstack -r -o $@  --whole-archive $< --no-whole-archive

libvtpm.a: built-in.o
	ar rcs $@ $<

# libcrt
$(LIBCRT):
	$(MAKE) -C libcrt

# openssl
$(LIBCRYPTO): .config
	$(MAKE) -C $(OPENSSL_DIR) RANLIB=echo ARFLAGS=cDPrST -j$$(nproc)

# TPM
$(LIBTPM_DIR)/src.mk:
	(cd $(LIBTPM_DIR) && ./bootstrap)

-include $(LIBTPM_DIR)/src.mk

TPM_O = $(addprefix $(CURDIR)/ms-tpm-20-ref/TPMCmd/, $(TPM_C:%.c=%.o))
PLATFORM_O = $(addprefix $(CURDIR)/ms-tpm-20-ref/TPMCmd/, $(PLATFORM_C:%.c=%.o))

LIBTPM_INCLUDES = -I$(LIBTPM_DIR)/tpm/include
LIBTPM_INCLUDES += -I$(LIBTPM_DIR)/tpm/include/prototypes
LIBTPM_INCLUDES += -I$(LIBTPM_DIR)/Platform/include
LIBTPM_INCLUDES += -I$(LIBTPM_DIR)/Platform/include/prototypes
LIBTPM_INCLUDES += -I$(LIBCRT_DIR)/include -I$(OPENSSL_DIR)/include
LIBTPM_DEFINES = -DSIMULATION=NO  -DVTPM -DEPHEMERAL_NV
LIBTPM_CFLAGS = -fPIE -fno-stack-protector -nostdlib -nostdinc
LIBTPM_CFLAGS += $(LIBTPM_DEFINES) $(LIBTPM_INCLUDES)

$(LIBTPM): $(TPM_O)
	rm -f $@
	ar cDPrST $@ $(TPM_O)

$(LIBPLATFORM): $(PLATFORM_O)
	rm -f $@
	ar cDPrST $@ $(PLATFORM_O)

$(TPM_O) $(PLATFORM_O): .config
$(TPM_O) $(PLATFORM_O): CFLAGS=$(LIBTPM_CFLAGS)

config: .config

.config:
	(cd $(OPENSSL_DIR) && git checkout OpenSSL_1_1_1q  && \
		./Configure \
			--config=$(CURDIR)/openssl_svsm.conf \
			SVSM \
			no-afalgeng \
			no-async \
			no-autoerrinit \
			no-autoload-config \
			no-bf \
			no-blake2 \
			no-capieng \
			no-cast \
			no-chacha \
			no-cms \
			no-ct \
			no-deprecated \
			no-des \
			no-dgram \
			no-dsa \
			no-dynamic-engine \
			no-ec2m \
			no-engine \
			no-err \
			no-filenames \
			no-gost \
			no-hw \
			no-idea \
			no-md4 \
			no-mdc2 \
			no-pic \
			no-ocb \
			no-poly1305 \
			no-posix-io \
			no-rc2 \
			no-rc4 \
			no-rfc3779 \
			no-rmd160 \
			no-scrypt \
			no-seed \
			no-sock \
			no-srp \
			no-ssl \
			no-stdio \
			no-threads \
			no-ts \
			no-whirlpool \
			no-shared \
			no-sse2 \
			no-ui-console \
			no-asm \
			--with-rand-seed=none \
			-I$(LIBCRT_DIR)/include \
			-Wl,rpath=$(LIBCRT_DIR) -lcrt )
	$(MAKE) -C $(OPENSSL_DIR) RANLIB=echo ARFLAGS=cDPrST build_generated
	touch $@

clean:
	rm -f *.o *.a
	make -C libcrt clean
	make -C openssl clean
	rm -f $(TPM_O) $(PLATFORM_O) $(LIBTPM) $(LIBPLATFORM)

distclean: clean
	rm .config

.PHONY: all clean config
