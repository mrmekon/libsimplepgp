/*
 *  packet.c
 *  libsimplepgp
 *
 *  Created by Trevor Bentley on 11/1/11.
 *  Copyright 2011 Trevor Bentley. All rights reserved.
 *
 */

#include "packet.h"
#include <stdio.h>
#include <setjmp.h>
#include "gcrypt.h"

#define DEBUG_LOG

#define RAISE(err) do { \
		_spgp_err = (err); \
    LOG_PRINT("raise 0x%X\n",_spgp_err); \
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


static uint32_t _spgp_err;
static jmp_buf exception;

#ifdef DEBUG_LOG_ENABLED
static uint8_t debug_log_enabled = 1;
#else
static uint8_t debug_log_enabled = 0;
#endif

static uint8_t parse_header(uint8_t *msg, uint32_t *idx, 
														uint32_t length, spgp_packet_t *pkt);
static uint8_t spgp_parse_secret_key(uint8_t *msg, uint32_t *idx, 
          													 uint32_t length, spgp_packet_t *pkt);
static spgp_mpi_t *spgp_read_mpi(uint8_t *msg, uint32_t *idx,
														 uint32_t length);
static uint8_t spgp_read_all_public_mpis(uint8_t *msg, 
                                         uint32_t *idx,
														 						 uint32_t length, 
                                         spgp_secret_pkt_t *secret);
                                         
uint8_t spgp_debug_log_enabled(void) {
	return debug_log_enabled;
}
void spgp_debug_log_set(uint8_t enable) {
	debug_log_enabled = enable;
}

spgp_packet_t *spgp_decode_message(uint8_t *message, uint32_t length) {
	spgp_packet_t *head = NULL;
  spgp_packet_t *pkt = NULL;
  uint32_t idx = 0;
  
	LOG_PRINT("begin\n");
  
	switch (setjmp(exception)) {
  	case 0:
    	break; /* Run logic */
    /* Below here are exceptions */
    default:
    	LOG_PRINT("Exception (0x%x)\n",_spgp_err);
      spgp_free_packet(&head);
  	  goto end;
  }

	if (NULL == message || 0 == length) {
  	RAISE(INVALID_ARGS);
  }
  
  head = malloc(sizeof(*head));
  if (NULL == head)
  	RAISE(OUT_OF_MEMORY);
  memset(head, 0, sizeof(*head));
  pkt = head;
  
  parse_header(message, &idx, length, pkt);
  if (pkt->header) {
  	switch (pkt->header->type) {
    	case PKT_TYPE_SECRET_KEY:
      case PKT_TYPE_SECRET_SUBKEY:
      	spgp_parse_secret_key(message, &idx, length, pkt);
        break;
      default:
      	LOG_PRINT("WARNING: Unsupported packet type %d\n", pkt->header->type);
      	break;
    }
  }
  
  end:
  LOG_PRINT("done\n");
  return head;
}

void spgp_free_packet(spgp_packet_t **pkt) {
	if (pkt == NULL)
  	return;
  if (*pkt == NULL)
  	return;
  
  // TODO: make this recursive, free it's next pointer first
  
  // release header
  if ((*pkt)->header) {
	  free((*pkt)->header);
	  (*pkt)->header = NULL;
  }
  
  // TODO: should release MPIs here
  
  // release packet
  free(*pkt);
  *pkt = NULL;
}

uint32_t spgp_err(void) {
	return _spgp_err;
}

const char *spgp_err_str(uint32_t err) {
	switch (err) {
  	case INVALID_ARGS:
    	return "Invalid arguments given to function.";
      break;
  	case BUFFER_OVERFLOW:
    	return "Index into buffer exceeded the maximum "
      	"bound of the buffer.";
      break;
    default:
    	return "Unknown/undocumented error.";
  }
}

void tsb_test(void) {
  gcry_cipher_hd_t cipher_hd;
  gcry_error_t err;
  
	printf("This is a test library.\n");
  err = gcry_cipher_open (&cipher_hd, 
			  2,
			  GCRY_CIPHER_MODE_CFB,
			  (GCRY_CIPHER_SECURE | GCRY_CIPHER_ENABLE_SYNC));
  printf("open result: %d\n", err);
        
}

static uint8_t parse_header(uint8_t *msg, uint32_t *idx, 
														uint32_t length, spgp_packet_t *pkt) {
	uint8_t i;
  
	if (NULL == msg || NULL == pkt || NULL == idx || length == 0)
  	RAISE(INVALID_ARGS);

	// Allocate a header
	if (pkt->header == NULL) {
  	LOG_PRINT("Allocating header.\n");
  	pkt->header = malloc(sizeof(*(pkt->header)));
    if (pkt->header == NULL)
    	RAISE(OUT_OF_MEMORY);
    memset(pkt->header, 0, sizeof(*(pkt->header)));
  }
  
  // Header points to its parent packet
  pkt->header->parent = pkt;
  
  // The first byte is the 'tag byte', which tells us the packet type.
  pkt->header->rawTagByte = msg[*idx];
  SAFE_IDX_INCREMENT(*idx, length);
  LOG_PRINT("TAG BYTE: 0x%.2X\n", pkt->header->rawTagByte);
  
  // Validate tag byte -- top bit always set
  if (!(pkt->header->rawTagByte & 0x80))
  	RAISE(INVALID_HEADER);
    
  // Second-MSB tells us if this is new or old format header
  pkt->header->isNewFormat = pkt->header->rawTagByte & 0x40;
  
  // Read the packet type out of the tag byte
  if (pkt->header->isNewFormat)
  	pkt->header->type = pkt->header->rawTagByte & 0x1F;
  else // old style
  	pkt->header->type = (pkt->header->rawTagByte >> 2) & 0x0F;
  LOG_PRINT("TYPE: 0x%.2X\n", pkt->header->type);
  
  // Read the length of the packet's contents.  In old packets, the length
  // is encoded into the tag byte. 
  if (pkt->header->isNewFormat == 0) {
  	switch (pkt->header->rawTagByte & 0x03) {
    	case 0: pkt->header->headerLength = 2; break;
      case 1: pkt->header->headerLength = 3; break;
      case 2: pkt->header->headerLength = 5; break;
      default: 
      	// "indeterminate length" is supported by OpenPGP, but not us.
      	RAISE(FORMAT_UNSUPPORTED);
    }
    for (i = 0; i < pkt->header->headerLength - 1; i++) {
    	pkt->header->contentLength <<= 8;
      pkt->header->contentLength += msg[*idx];
      SAFE_IDX_INCREMENT(*idx, length);
    }
  }
  // In new packets, the length is encoded over a variable number of bytes, 
  // with the range of the first byte determining total number of bytes.
  else { // This is new style packet.
  	uint8_t len[4];
    len[0] = msg[*idx]; SAFE_IDX_INCREMENT(*idx, length);
    if (len[0] <= 191) { // 1-byte length
    	pkt->header->headerLength = 2;
      pkt->header->contentLength = len[0];
    }
    else if (len[0] > 191 && len[0] <= 223) { // 2-byte length
    	pkt->header->headerLength = 3;
      len[1] = msg[*idx]; SAFE_IDX_INCREMENT(*idx, length);
      pkt->header->contentLength = 
      	((len[0]-192)<<8) | (len[1] + 192);
    }
    else { // 4-byte length
    	pkt->header->headerLength = 5;
      len[2] = msg[*idx]; SAFE_IDX_INCREMENT(*idx, length);
      len[3] = msg[*idx]; SAFE_IDX_INCREMENT(*idx, length);
    	pkt->header->contentLength = 
      	(len[0]<<24) | (len[1]<<16) | (len[2]<<8) | len[3];
    }
  }
  
  LOG_PRINT("LENGTH: %u\n", pkt->header->contentLength);
  
	return 0;
}

static uint8_t spgp_parse_secret_key(uint8_t *msg, uint32_t *idx, 
          													 uint32_t length, spgp_packet_t *pkt) {
  spgp_secret_pkt_t secret;
  
  LOG_PRINT("Parsing secret key.\n");
  
  secret.version = msg[*idx]; 
  SAFE_IDX_INCREMENT(*idx, length);
  
  // First byte is the version.
  if (secret.version != 4) RAISE(FORMAT_UNSUPPORTED);
  
  // Next 4 bytes are big-endian 'key creation time'
  if (length - *idx < 4) RAISE(BUFFER_OVERFLOW);
  memcpy(&(secret.creationTime), msg+*idx, 4);
  *idx += 3; // this puts us on last byte of creation time
  SAFE_IDX_INCREMENT(*idx, length); // this goes to next byte (safely)

	// Next byte identifies asymmetric algorithm
	secret.asymAlgo = msg[*idx];
	SAFE_IDX_INCREMENT(*idx, length);
  LOG_PRINT("Asymmetric algorithm: %d\n", secret.asymAlgo);
  
  // Read variable number of MPIs (depends on asymmetric algorithm), each
  // of which are variable size.
	spgp_read_all_public_mpis(msg, idx, length, &secret);
  LOG_PRINT("Read %u MPIs\n", secret.mpiCount);
  
	return 0;
}

static uint8_t spgp_read_all_public_mpis(uint8_t *msg, 
                                         uint32_t *idx,
														 						 uint32_t length, 
                                         spgp_secret_pkt_t *secret) {
  spgp_mpi_t *curMpi, *newMpi;
  uint32_t i;
  
  if (NULL == msg || NULL == idx || 0 == length || NULL == secret)
  	RAISE(INVALID_ARGS);

  // Read all the MPIs
	if (secret->asymAlgo == ASYM_ALGO_DSA) {
  	// DSA public MPIs: prime p, order q, generator g, value y
    for (i = 0; i < 4; i++) {
      newMpi = spgp_read_mpi(msg, idx, length);
      if (i == 0) {
        secret->mpiHead = newMpi;
        curMpi = secret->mpiHead;
      }
      else {
        curMpi->next = newMpi;
        curMpi = curMpi->next;
      }
    }
    secret->mpiCount = 4;
	}
  else {
  	RAISE(FORMAT_UNSUPPORTED);
  }
  
	return secret->mpiCount;
}

static spgp_mpi_t *spgp_read_mpi(uint8_t *msg, uint32_t *idx,
														 uint32_t length) {
	spgp_mpi_t *mpi = NULL;
  
  if (NULL == msg || NULL == idx || 0 == length) RAISE(INVALID_ARGS);
  
  mpi = malloc(sizeof(*mpi));
  if (NULL == mpi) RAISE(OUT_OF_MEMORY);
  memset(mpi, 0, sizeof(*mpi));
  
  // First two bytes are big-endian count of bits in MPI
  if (length - *idx < 2) RAISE(BUFFER_OVERFLOW);
  mpi->bits = ((msg[*idx] << 8) | msg[*idx + 1]);
  *idx += 1;
  SAFE_IDX_INCREMENT(*idx, length);
  
  mpi->count = (mpi->bits+7)/8;
  LOG_PRINT("MPI Bits: %u\n", mpi->bits);
  
  // Allocate space for MPI data
  mpi->data = malloc(mpi->count);
  if (NULL == mpi->data) RAISE(OUT_OF_MEMORY);
  
  // Copy data from input buffer to mpi buffer
  memcpy(mpi->data, msg, mpi->count);
  *idx += mpi->count - 1;
  SAFE_IDX_INCREMENT(*idx, length);
  
  return mpi;
}

