pkglib_LTLIBRARIES = libsimplepgp.la
pkginclude_HEADERS = src/simplepgp.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = simplepgp.pc

libsimplepgp_la_LDFLAGS = -version-info 0:1:0
libsimplepgp_la_SOURCES = \
	src/packet.c \
	src/keychain.c \
	src/util.c \
	src/mpi.c 

installcheck-local:
	make -C examples/01_decrypt
	pushd `pwd`/examples/01_decrypt ;\
	./decrypt ;\
	popd

clean-local:
	-rm -rf build

ios:
	@./build_ios.sh
