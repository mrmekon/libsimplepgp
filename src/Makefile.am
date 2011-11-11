AUTOMAKE_OPTIONS = foreign

CFLAGS=-Wall -O2 `libgcrypt-config --cflags` `gpg-error-config --cflags` -I/usr/include -I/usr/local/include
LDFLAGS=`libgcrypt-config --libs` `gpg-error-config --libs`

pkglib_LTLIBRARIES = libsimplepgp.la
pkginclude_HEADERS = packet.h

libsimplepgp_la_SOURCES = \
	packet.c \
	keychain.c \
	util.c \
	mpi.c 


