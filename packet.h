/*
 *  packet.h
 *  libsimplepgp
 *
 *  Created by Trevor Bentley on 11/1/11.
 *  Copyright 2011 Trevor Bentley. All rights reserved.
 *
 */
 
#ifndef _PACKET_H

#include <stdint.h>
#include "gcrypt.h"


typedef struct spgp_packet_header_struct spgp_pkt_header_t;
typedef struct spgp_packet_struct spgp_packet_t;
typedef struct spgp_mpi_struct spgp_mpi_t;
typedef struct spgp_secret_packet_struct spgp_secret_pkt_t;

struct spgp_packet_header_struct {
	spgp_packet_t *parent;
  uint8_t rawTagByte;
  uint8_t isNewFormat;
  uint8_t type;
  uint8_t headerLength;
  uint32_t contentLength;
};

struct spgp_packet_struct {
	spgp_pkt_header_t *header;
  union {
  	spgp_secret_pkt_t *secret;
  } c;
	spgp_packet_t *next;	
};

struct spgp_mpi_struct {
	uint8_t *data;
  uint32_t bits;
  uint32_t count;
	spgp_mpi_t *next;
};

struct spgp_secret_packet_struct {
// This is public key stuff
	uint8_t version;
  uint32_t creationTime;
	uint8_t asymAlgo;
  uint8_t symAlgo;
  spgp_mpi_t *mpiHead;
  uint8_t mpiCount;
// This is secret key stuff  
	uint8_t isDecrypted;
  uint8_t s2kType;
  uint8_t s2kEncryption;
  uint8_t s2kSpecifier;
  uint8_t s2kHashAlgo;
  uint8_t *s2kSalt;
  uint8_t s2kSaltLength;
  uint8_t s2kCount;
  uint8_t *encryptedData;
  uint8_t *key;
  uint32_t keyLength;
  uint8_t *iv;
  uint8_t ivLength;
};

typedef enum {
	GENERIC_ERROR           = 0x100,
  OUT_OF_MEMORY,
  INVALID_HEADER,
  FORMAT_UNSUPPORTED,
	INVALID_ARGS,
	BUFFER_OVERFLOW,
	EXCEPTIONS_UNSUPPORTED,
} spgp_error_t;

typedef enum {
	PKT_TYPE_SIGNATURE         = 2,
	PKT_TYPE_SECRET_KEY        = 5,
  PKT_TYPE_PUBLIC_KEY        = 6,
	PKT_TYPE_SECRET_SUBKEY     = 7,
  PKT_TYPE_USER_ID           = 13,
  PKT_TYPE_PUBLIC_SUBKEY     = 14,
} spgp_pkt_type_t;

typedef enum {
	ASYM_ALGO_RSA              = 1,
  ASYM_ALGO_RSA_ENCRYPT      = 2,
  ASYM_ALGO_RSA_SIGN         = 3,
  ASYM_ALGO_ELGAMAL          = 16,
  ASYM_ALGO_DSA              = 17,
} spgp_asym_algo_t;

typedef enum {
	SYM_ALGO_PLAINTEXT         = 0,
  SYM_ALGO_IDEA,
  SYM_ALGO_3DES,
  SYM_ALGO_CAST5,
  SYM_ALGO_BLOWFISH,
  SYM_ALGO_AES128,
  SYM_ALGO_AES192,
  SYM_ALGO_AES256,
  SYM_ALGO_TWOFISH,
} spgp_sym_algo_t;

typedef enum {
	HASH_ALGO_MD5              = 1,
  HASH_ALGO_SHA1,
  HASH_ALGO_RIPEMD160,
  HASH_ALGO_SHA256,
  HASH_ALGO_SHA384,
  HASH_ALGO_SHA512,
  HASH_ALGO_SHA224,
} spgp_hash_algo_t;

spgp_packet_t *spgp_decode_message(uint8_t *message, uint32_t length);
void spgp_free_packet(spgp_packet_t **pkt);

uint32_t spgp_err(void);
const char *spgp_err_str(uint32_t err);

void tsb_test(void);

uint8_t spgp_debug_log_enabled(void);
void spgp_debug_log_set(uint8_t enable);

#define _PACKET_H
#endif
