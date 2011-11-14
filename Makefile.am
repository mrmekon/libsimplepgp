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
	@make -C examples/01_decrypt
	@make -C examples/02_decrypt_rsa
	@pushd "`pwd`/examples/01_decrypt";./decrypt;popd
	@read -p "Press return to run next test..."
	@pushd "`pwd`/examples/02_decrypt_rsa";./decrypt_rsa;popd

clean-local:
	-rm -rf build

ios:
	@./build_ios.sh
