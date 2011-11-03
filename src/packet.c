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
#include <wchar.h>
#include <locale.h>


/**********************************************************************
**
** MACROS
**
***********************************************************************/
#pragma mark Macros

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


/**********************************************************************
**
** Static variables
**
***********************************************************************/


static uint32_t _spgp_err;
static jmp_buf exception;

#ifdef DEBUG_LOG_ENABLED
static uint8_t debug_log_enabled = 1;
#else
static uint8_t debug_log_enabled = 0;
#endif


/**********************************************************************
**
** Static function prototypes
**
***********************************************************************/

static uint8_t spgp_parse_header(uint8_t *msg, uint32_t *idx, 
														uint32_t length, spgp_packet_t *pkt);

static uint8_t spgp_parse_user_id(uint8_t *msg, uint32_t *idx, 
          												uint32_t length, spgp_packet_t *pkt);
                                                              
static uint8_t spgp_parse_secret_key(uint8_t *msg, uint32_t *idx, 
          													 uint32_t length, spgp_packet_t *pkt);
                                     
static spgp_mpi_t *spgp_read_mpi(uint8_t *msg, uint32_t *idx,
														 uint32_t length);
                             
static uint8_t spgp_read_all_public_mpis(uint8_t *msg, 
                                         uint32_t *idx,
														 						 uint32_t length, 
                                         spgp_secret_pkt_t *secret);
                                         
static uint8_t spgp_read_all_secret_mpis(uint8_t *msg, 
                                         uint32_t *idx,
														 						 uint32_t length, 
                                         spgp_secret_pkt_t *secret);
                                         
static uint8_t spgp_read_salt(uint8_t *msg, 
                              uint32_t *idx,
                              uint32_t length, 
                              spgp_secret_pkt_t *secret);
                              
static uint8_t spgp_read_iv(uint8_t *msg, 
                            uint32_t *idx,
                            uint32_t length, 
                            spgp_secret_pkt_t *secret);
                            
static uint8_t spgp_iv_length_for_symmetric_algo(uint8_t algo);

static uint8_t spgp_salt_length_for_hash_algo(uint8_t algo);




/**********************************************************************
**
** External function definitions
**
***********************************************************************/
#pragma mark External Function Definitions

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
  
  // There must be at least one packet, yeah?
  head = malloc(sizeof(*head));
  if (NULL == head) RAISE(OUT_OF_MEMORY);
  memset(head, 0, sizeof(*head));
  pkt = head;
  
  
  // Loop to decode every packet in message
  while (idx < length-1) {
  	// Every packet starts with a header
    spgp_parse_header(message, &idx, length, pkt);
    if (!pkt->header) RAISE(FORMAT_UNSUPPORTED);
    
    // Decode packet contents based on the type marked in its header
    switch (pkt->header->type) {
    	case PKT_TYPE_USER_ID:
      	spgp_parse_user_id(message, &idx, length, pkt);
        break;
      case PKT_TYPE_SECRET_KEY:
      case PKT_TYPE_SECRET_SUBKEY:
        spgp_parse_secret_key(message, &idx, length, pkt);
        break;
      default:
        LOG_PRINT("WARNING: Unsupported packet type %d\n", pkt->header->type);
        // Increment to next packet.  We add the contentLength, but subtract
        // one parse_header() left us on the first byte of content.
        if (idx + pkt->header->contentLength - 1 < length)
          idx = idx + pkt->header->contentLength - 1;
        break;
    }
    
    // If we're at the end of the buffer, we're done
    if (idx >= length-1) break;
        
    // Allocate space for another packet
    pkt->next = malloc(sizeof(*pkt->next));
    if (NULL == pkt->next) RAISE(OUT_OF_MEMORY);
    memset(pkt->next, 0, sizeof(*pkt->next));
    pkt = pkt->next;
    
    // Packet parser increments to it's own last byte.  Need one more to get
    // to the next packet's first byte. 
    SAFE_IDX_INCREMENT(idx, length);
	}
    
  end:
  LOG_PRINT("done\n");
  return head;
}

void spgp_free_packet(spgp_packet_t **pkt) {
	spgp_mpi_t *curMpi, *nextMpi;
  
	if (pkt == NULL)
  	return;
  if (*pkt == NULL)
  	return;
  
  LOG_PRINT("Freeing packet: %p\n", pkt);
  
  // Recursively call on the next packet before freeing parent.
  if ((*pkt)->next) spgp_free_packet(&((*pkt)->next));
  
  // Release memory allocated for secret key fields
  if (((*pkt)->header->type == PKT_TYPE_SECRET_KEY ||
  		(*pkt)->header->type == PKT_TYPE_SECRET_SUBKEY) &&
      (*pkt)->c.secret != NULL) {
  	if ((*pkt)->c.secret->mpiCount > 0) {
    	curMpi = (*pkt)->c.secret->mpiHead;
      while (curMpi->next) {
      	nextMpi = curMpi->next;
        free(curMpi);
        curMpi = nextMpi;
      }
      (*pkt)->c.secret->mpiHead = NULL;
      (*pkt)->c.secret->mpiCount = 0;
    }
    if ((*pkt)->c.secret->s2kSalt) {
    	free((*pkt)->c.secret->s2kSalt);
      (*pkt)->c.secret->s2kSalt = NULL;
    }
    if ((*pkt)->c.secret->key) {
    	free((*pkt)->c.secret->key);
      (*pkt)->c.secret->key = NULL;
    }
    if ((*pkt)->c.secret->iv) {
    	free((*pkt)->c.secret->iv);
      (*pkt)->c.secret->iv = NULL;
    }
    free((*pkt)->c.secret);
    (*pkt)->c.secret = NULL;
  }
  else if ((*pkt)->header->type == PKT_TYPE_USER_ID &&
  				 (*pkt)->c.userid->data != NULL) {
  	free((*pkt)->c.userid->data);
    (*pkt)->c.userid->data = NULL;
    
    free((*pkt)->c.userid);
    (*pkt)->c.userid = NULL;
  }
  
  // release header
  if ((*pkt)->header) {
	  free((*pkt)->header);
	  (*pkt)->header = NULL;
  }
  
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
    case OUT_OF_MEMORY:
    	return "Not enough memory to continue parsing.";
    case INVALID_HEADER:
    	return "Invalid header format.  Corrupted or invalid data.";
    case FORMAT_UNSUPPORTED:
    	return "Message format is valid, but not currently supported.";
  	case BUFFER_OVERFLOW:
    	return "Index into buffer exceeded the maximum "
      	"bound of the buffer.";
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




/**********************************************************************
**
** Static function definitions
**
***********************************************************************/
#pragma mark Static Function Definitions


static uint8_t spgp_parse_header(uint8_t *msg, uint32_t *idx, 
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

static uint8_t spgp_parse_user_id(uint8_t *msg, uint32_t *idx, 
          												uint32_t length, spgp_packet_t *pkt) {
	spgp_userid_pkt_t *userid;

  LOG_PRINT("Parsing user id.\n");

	// Make sure we have enough bytes remaining for the copy
  if (length - *idx < pkt->header->contentLength) RAISE(BUFFER_OVERFLOW);
  
  // Allocate userid field in packet
  pkt->c.userid = malloc(sizeof(*(pkt->c.userid)));
  if (NULL == pkt->c.userid) RAISE(OUT_OF_MEMORY);
  userid = pkt->c.userid;
  
  // Allocate space for buffer, plus one byte for NUL terminator
	userid->data = malloc(sizeof(*(userid->data))*pkt->header->contentLength + 1);
  if (NULL == userid->data) RAISE(OUT_OF_MEMORY);
  
  // Copy bytes from input to structure, and add a NUL terminator
  memcpy(userid->data, msg+*idx, pkt->header->contentLength);
  userid->data[pkt->header->contentLength] = '\0';
  *idx += pkt->header->contentLength - 1;

  setlocale(LC_CTYPE, "en_US.UTF-8");
  wprintf(L"USER ID: %s\n", pkt->c.userid->data);
  
	return 0;                                     
}

static uint8_t spgp_parse_secret_key(uint8_t *msg, uint32_t *idx, 
          													 uint32_t length, spgp_packet_t *pkt) {
  spgp_secret_pkt_t *secret;
  spgp_public_pkt_t *pub;
  uint32_t startIdx = *idx;
  
  LOG_PRINT("Parsing secret key.\n");

	// Make sure we have enough bytes remaining for parsing
  if (length - *idx < pkt->header->contentLength) RAISE(BUFFER_OVERFLOW);

	// Allocate secret key in packet  
  pkt->c.secret = malloc(sizeof(*(pkt->c.secret)));
  if (NULL == pkt->c.secret) RAISE(OUT_OF_MEMORY);
	secret = pkt->c.secret;
  pub = pkt->c.pub;
  
  pub->version = msg[*idx]; 
  SAFE_IDX_INCREMENT(*idx, length);
  
  // First byte is the version.
  if (secret->version != 4) RAISE(FORMAT_UNSUPPORTED);
  
  // Next 4 bytes are big-endian 'key creation time'
  if (length - *idx < 4) RAISE(BUFFER_OVERFLOW);
  memcpy(&(secret->creationTime), msg+*idx, 4);
  *idx += 3; // this puts us on last byte of creation time
  SAFE_IDX_INCREMENT(*idx, length); // this goes to next byte (safely)

	// Next byte identifies asymmetric algorithm
	secret->asymAlgo = msg[*idx];
	SAFE_IDX_INCREMENT(*idx, length);
  LOG_PRINT("Asymmetric algorithm: %d\n", secret->asymAlgo);
  
  // Read variable number of MPIs (depends on asymmetric algorithm), each
  // of which are variable size.
	spgp_read_all_public_mpis(msg, idx, length, secret);
  LOG_PRINT("Read %u MPIs\n", secret->mpiCount);
  
  // S2K Type byte tells how to (or if to) decrypt secret exponent
  secret->s2kType = msg[*idx];
  SAFE_IDX_INCREMENT(*idx, length);
  switch (secret->s2kType) {
  	case 0:
    	// There is no encryption
    	secret->s2kEncryption = 0;
      break;
    case 254:
    case 255:
    	// Next byte is encryption type
		  secret->s2kEncryption = msg[*idx];
  		SAFE_IDX_INCREMENT(*idx, length);
			break;
    default:
    	// This byte is encryption type
    	secret->s2kEncryption = secret->s2kType;
    	break;
  }
  LOG_PRINT("Encryption: %u\n", secret->s2kEncryption);
  
  if (secret->s2kEncryption) {
  	// Secret exponent is encrypted (as it should be).  Time to decrypt.
    
    // S2K specifier tells us if there is a salt, and how to use it
    if (secret->s2kType >= 254) {
			secret->s2kSpecifier = msg[*idx];
  	  SAFE_IDX_INCREMENT(*idx, length);
   	 LOG_PRINT("S2K Specifier: %u\n", secret->s2kSpecifier);
    }
    
    // S2K hash algorithm specifies how to hash passphrase into a key
    secret->s2kHashAlgo = msg[*idx];
    SAFE_IDX_INCREMENT(*idx, length);
    LOG_PRINT("Hash algorithm: %u\n", secret->s2kHashAlgo);    
    
    // Read the salt if there is one
    switch (secret->s2kSpecifier) {
    	case 1:
      	spgp_read_salt(msg, idx, length, secret);
      	break;
      case 3:
      	spgp_read_salt(msg, idx, length, secret);
        // S2K Count is number of bytes to hash to make the key
				secret->s2kCount = msg[*idx];
    		SAFE_IDX_INCREMENT(*idx, length);
        break;
      default:
      	break;
    }
  }
  LOG_PRINT("Salt length: %u\n", secret->s2kSaltLength);
  
  // If it's not encrypted, we can just read the secret MPIs
  if (!secret->s2kEncryption) {
  	spgp_read_all_secret_mpis(msg, idx, length, secret);
  }
  // If it is encrypted, just store it for now.  We'll decrypt later.
  else {
  
  	// There's an initial vector (IV) here:
  	spgp_read_iv(msg, idx, length, secret);
    LOG_PRINT("IV length: %u\n", secret->ivLength);
  
  	uint32_t packetOffset = *idx - startIdx;
  	uint32_t remaining = pkt->header->contentLength - packetOffset;
		if (packetOffset >= pkt->header->contentLength) RAISE(BUFFER_OVERFLOW);
  	secret->encryptedData = malloc(remaining);
    if (NULL == secret->encryptedData) RAISE(OUT_OF_MEMORY);
    memcpy(secret->encryptedData, msg+*idx, remaining);
    *idx += remaining-1;
    LOG_PRINT("Stored %u encrypted bytes.\n", remaining);
    // This is the end of the data, so we do NOT do a final idx increment
  }
    
	return 0;
}

static uint8_t spgp_read_salt(uint8_t *msg, 
                              uint32_t *idx,
                              uint32_t length, 
                              spgp_secret_pkt_t *secret) {
	uint8_t saltLen = 0;
  
 	if (NULL == msg || NULL == idx || 0 == length || NULL == secret)
  	RAISE(INVALID_ARGS);
  
  if ((saltLen = spgp_salt_length_for_hash_algo(secret->s2kHashAlgo)) == 0) 
  	RAISE(FORMAT_UNSUPPORTED);
  
  if (length - *idx < saltLen) RAISE(BUFFER_OVERFLOW);
  
  secret->s2kSalt = malloc(sizeof(*(secret->s2kSalt)) * saltLen);
  if (NULL == secret->s2kSalt) RAISE(OUT_OF_MEMORY);
  
  secret->s2kSaltLength = saltLen;
  memcpy(secret->s2kSalt, msg+*idx, saltLen);
  *idx += saltLen-1;
  SAFE_IDX_INCREMENT(*idx, length);
  
	return 0;
}

static uint8_t spgp_read_iv(uint8_t *msg, 
                            uint32_t *idx,
                            uint32_t length, 
                            spgp_secret_pkt_t *secret) {
	uint8_t ivLen = 0;
  
 	if (NULL == msg || NULL == idx || 0 == length || NULL == secret)
  	RAISE(INVALID_ARGS);
  
  if ((ivLen = spgp_iv_length_for_symmetric_algo(secret->s2kEncryption)) == 0) 
  	RAISE(FORMAT_UNSUPPORTED);
  
  if (length - *idx < ivLen) RAISE(BUFFER_OVERFLOW);
  
  secret->iv = malloc(sizeof(*(secret->iv)) * ivLen);
  if (NULL == secret->iv) RAISE(OUT_OF_MEMORY);
  
  secret->ivLength = ivLen;
  memcpy(secret->iv, msg+*idx, ivLen);
  *idx += ivLen-1;
  SAFE_IDX_INCREMENT(*idx, length);
  
	return 0;
}

static uint8_t spgp_iv_length_for_symmetric_algo(uint8_t algo) {
	if (algo == SYM_ALGO_3DES) return 8;
  else RAISE(FORMAT_UNSUPPORTED); // not implemented
  return 0;
}

static uint8_t spgp_salt_length_for_hash_algo(uint8_t algo) {
	if (algo == HASH_ALGO_SHA1) return 8;
  else RAISE(FORMAT_UNSUPPORTED); // not implemented
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
  else if (secret->asymAlgo == ASYM_ALGO_ELGAMAL) {
  	// DSA public MPIs: prime p, order q, generator g, value y
    for (i = 0; i < 3; i++) {
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
    secret->mpiCount = 3;  
  }
  else {
  	RAISE(FORMAT_UNSUPPORTED);
  }
  
	return secret->mpiCount;
}

static uint8_t spgp_read_all_secret_mpis(uint8_t *msg, 
                                         uint32_t *idx,
														 						 uint32_t length, 
                                         spgp_secret_pkt_t *secret) {
  spgp_mpi_t *curMpi;
  
  if (NULL == msg || NULL == idx || 0 == length || NULL == secret)
  	RAISE(INVALID_ARGS);

	// Set curMpi to last valid Mpi in linked list
	curMpi = secret->mpiHead;
  while (curMpi->next) curMpi = curMpi->next;

  // Read all the MPIs
	if (secret->asymAlgo == ASYM_ALGO_DSA) {
  	// DSA secte MPIs: exponent x
    curMpi->next = spgp_read_mpi(msg, idx, length);
    secret->mpiCount++;
    *idx += length - 1;
    // This is the end of the data, so we do NOT do a final increment. 
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

