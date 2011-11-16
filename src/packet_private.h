/*
 *  packet_private.h
 *  simplepgp
 *
 *  Created by Trevor Bentley on 11/11/11.
 *
 *  Copyright 2011 Trevor Bentley
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#ifndef _PACKET_PRIVATE_H

#include "simplepgp.h"
#include "gcrypt.h"

#include <stdio.h>
#include <setjmp.h>
#include <pthread.h>


/**********************************************************************
**
** MACROS
**
***********************************************************************/
#pragma mark Macros

#define RAISE(err) do { \
		pthread_mutex_lock(&spgp_mtx); \
		_spgp_err = (err); \
    LOG_PRINT("raise 0x%X\n",_spgp_err); \
		pthread_mutex_unlock(&spgp_mtx); \
    longjmp(exception,_spgp_err); \
  } while(0)

#define SAFE_IDX_INCREMENT(idx,max) \
	do{ \
		if (++(idx)>=(max)) {\
  		RAISE(BUFFER_OVERFLOW);\
    } \
  } while(0)
  
#define LOG_PRINT(fmt, ...) do {\
	if (debug_log_enabled) {\
  	fprintf(stderr, "SPGP [%s():%d]: " fmt, \
    	__FUNCTION__, __LINE__, ## __VA_ARGS__);\
  } } while(0)


extern pthread_mutex_t spgp_mtx;
extern uint8_t debug_log_enabled;
extern uint32_t _spgp_err;
extern jmp_buf exception;


struct spgp_packet_header_struct {
	spgp_packet_t *parent;
  uint32_t contentLength;
  uint8_t rawTagByte;
  uint8_t isNewFormat;
  uint8_t type;
  uint8_t headerLength;
  uint8_t isPartial;
};

struct spgp_packet_struct {
	spgp_pkt_header_t *header;
  union {
  	spgp_public_pkt_t    *pub;
  	spgp_secret_pkt_t    *secret;
    spgp_userid_pkt_t    *userid;
    spgp_session_pkt_t   *session;
    spgp_literal_pkt_t   *literal;
    spgp_signature_pkt_t *signature;
  } c;
	spgp_packet_t *next;
  spgp_packet_t *prev;
};

struct spgp_mpi_struct {
	uint8_t *data;
  uint32_t bits;
  uint32_t count;
	spgp_mpi_t *next;
}; 

struct spgp_literal_packet_struct {
	char *filename;
	char *data;
  uint32_t dataLen;
  uint32_t filenameLen;
};

struct spgp_signature_packet_struct {
	uint8_t version;
  uint8_t type;
  uint8_t asymAlgo;
  uint8_t hashAlgo;
  uint16_t hashedSubLength;
  uint16_t unhashedSubLength;
  uint16_t hashTest;
  spgp_mpi_t *mpiHead;
};


struct spgp_userid_packet_struct {
	uint8_t *data;
};

struct spgp_session_packet_struct {
  uint8_t keyid[8];
	uint8_t version;
  uint8_t algo;
  uint8_t symAlgo;
  uint32_t keylen;
  char *key;
  spgp_mpi_t *mpi1;
  spgp_mpi_t *mpi2;
};

struct spgp_public_packet_struct {
// This is public key stuff
	uint8_t version;
  uint32_t creationTime;
	uint8_t asymAlgo;
  spgp_mpi_t *mpiHead;
  uint8_t mpiCount;
  uint8_t *fingerprint;
} __attribute__((packed));

struct spgp_secret_packet_struct {
// This is public key stuff
	spgp_public_pkt_t pub;
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
  uint32_t encryptedDataLength;
  uint8_t *key;
  uint32_t keyLength;
  uint8_t *iv;
  uint8_t ivLength;
} __attribute__((packed));

typedef enum {
	GENERIC_ERROR           = 0x100,
  OUT_OF_MEMORY,
  INVALID_HEADER,
  FORMAT_UNSUPPORTED,
	INVALID_ARGS,
	BUFFER_OVERFLOW,
  INCOMPLETE_PACKET,
  DECRYPT_FAILED,
  GCRY_ERROR,
  KEYCHAIN_ERROR,
  ZLIB_ERROR,
} spgp_error_t;

typedef enum {
	PKT_TYPE_SESSION           = 1,
	PKT_TYPE_SIGNATURE         = 2,
	PKT_TYPE_SECRET_KEY        = 5,
  PKT_TYPE_PUBLIC_KEY        = 6,
	PKT_TYPE_SECRET_SUBKEY     = 7,
  PKT_TYPE_COMPRESSED_DATA   = 8,
  PKT_TYPE_LITERAL_DATA      = 11,
  PKT_TYPE_USER_ID           = 13,
  PKT_TYPE_PUBLIC_SUBKEY     = 14,
  PKT_TYPE_SYM_ENC_INT_DATA  = 18,
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

typedef enum {
	COMPRESSION_UNCOMPRESSED   = 0,
  COMPRESSION_ZIP,
  COMPRESSION_ZLIB,
  COMPRESSION_BZIP2,
} spgp_compression_t;

typedef enum {
	S2K_TYPE_SIMPLE            = 0,
  S2K_TYPE_SALTED,
  S2K_TYPE_RESERVED,
  S2K_TYPE_ITERATED,
} spgp_s2k_type_t;


#define _PACKET_PRIVATE_H
#endif
