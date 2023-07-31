PREFIX ?= /usr/local/
INC_DIR = $(PREFIX)/include
LIB_DIR = $(PREFIX)/lib

LIB = libvtpm.a
HEADERS = include/Tpm.h include/ssl.h include/stdlib.h

CFLAGS += -I$(CURDIR)/include
BINDGEN_FLAGS = --use-core --ctypes-prefix=cty
CLANG_FLAGS = -I$(CURDIR)/include -Wno-incompatible-library-redeclaration


all: $(LIB) bindings.rs

$(LIB): libvtpm.o
	ar rcs $@ libvtpm.o

libvtpm.o: $(HEADERS) libvtpm.c

bindings.rs: $(HEADERS) libvtpm.h
	echo "#![allow(non_upper_case_globals)]" > $@
	echo "#![allow(non_camel_case_types)]" >> $@
	echo "#![allow(non_snake_case)]" >> $@
	echo "#![allow(unused)]" >> $@
	echo "#![allow(improper_ctypes)]" >> $@

	bindgen $(BINDGEN_FLAGS) libvtpm.h -- $(CLANG_FLAGS) >> $@

clean:
	rm -f $(LIB) *.o bindings.rs

.PHONY: all clean
