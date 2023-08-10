LIBCRT_DIR = $(CURDIR)/libcrt
OPENSSL_DIR = $(CURDIR)/openssl

LIBCRT = $(LIBCRT_DIR)/libcrt.a
LIBCRYPTO = $(OPENSSL_DIR)/libcrypto.a
LIBS = $(LIBCRT) $(LIBCRYPTO)

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

distclean: clean
	rm .config

.PHONY: all clean config
