pkglib_LTLIBRARIES = libsimplepgp.la
pkginclude_HEADERS = src/simplepgp.h

libsimplepgp_la_LDFLAGS = -version-info 0:1:0
libsimplepgp_la_SOURCES = \
	src/packet.c \
	src/keychain.c \
	src/util.c \
	src/mpi.c 

clean-local:
	-rm -rf build

ios:
	@./build_ios.sh
