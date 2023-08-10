LIBCRT_DIR = $(CURDIR)/libcrt

LIBCRT = $(LIBCRT_DIR)/libcrt.a
LIBS = $(LIBCRT)

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

clean:
	rm -f *.o *.a
	make -C libcrt clean


.PHONY: all clean
