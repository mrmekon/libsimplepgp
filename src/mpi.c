/*
 *  mpi.c
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

#include "mpi.h"

uint8_t spgp_read_all_public_mpis(uint8_t *msg, 
                                         uint32_t *idx,
														 						 uint32_t length, 
                                         spgp_public_pkt_t *pub) {
  spgp_mpi_t *curMpi, *newMpi;
  uint32_t i;
  uint8_t mpiCount;
  
  if (NULL == msg || NULL == idx || 0 == length || NULL == pub)
  	RAISE(INVALID_ARGS);

	switch (pub->asymAlgo) {
  	case ASYM_ALGO_DSA: mpiCount = 4; break;
    case ASYM_ALGO_ELGAMAL: mpiCount = 3; break;
    default: RAISE(FORMAT_UNSUPPORTED);
  }

  // Read all the MPIs
  for (i = 0; i < mpiCount; i++) {
  	// spgp_read_mpi() doesn't increment past the end of the MPI, so if this
    // isn't the first pass we need to increment once more
  	if (i) SAFE_IDX_INCREMENT(*idx, length);    
    newMpi = spgp_read_mpi(msg, idx, length);
    if (i == 0) {
      pub->mpiHead = newMpi;
      curMpi = pub->mpiHead;
    }
    else {
      curMpi->next = newMpi;
      curMpi = curMpi->next;
    }
  }
  pub->mpiCount = mpiCount;
  
	return pub->mpiCount;
}

uint8_t spgp_read_all_secret_mpis(uint8_t *msg, 
                                         uint32_t *idx,
														 						 uint32_t length, 
                                         spgp_secret_pkt_t *secret) {
  spgp_mpi_t *curMpi;
  spgp_public_pkt_t *pub = (spgp_public_pkt_t*)secret;
  
  if (NULL == msg || NULL == idx || 0 == length || NULL == secret)
  	RAISE(INVALID_ARGS);

	// Set curMpi to last valid Mpi in linked list
	curMpi = pub->mpiHead;
  while (curMpi->next) curMpi = curMpi->next;

  // Read all the MPIs
	if (pub->asymAlgo == ASYM_ALGO_DSA) {
  	// DSA secte MPIs: exponent x
    curMpi->next = spgp_read_mpi(msg, idx, length);
    pub->mpiCount++;
	}
  else {
  	RAISE(FORMAT_UNSUPPORTED);
  }
  
	return pub->mpiCount;
}

uint32_t spgp_mpi_length(uint8_t *mpi) {
	uint32_t bits;
	if (NULL == mpi) RAISE(INVALID_ARGS);
  bits = ((mpi[0] << 8) | mpi[1]);
  return (bits+7)/8;  
}

spgp_mpi_t *spgp_read_mpi(uint8_t *msg, uint32_t *idx,
														 uint32_t length) {
	spgp_mpi_t *mpi = NULL;
  
  if (NULL == msg || NULL == idx || 0 == length) RAISE(INVALID_ARGS);
  
  mpi = malloc(sizeof(*mpi));
  if (NULL == mpi) RAISE(OUT_OF_MEMORY);
  memset(mpi, 0, sizeof(*mpi));
  
  // First two bytes are big-endian count of bits in MPI
  if (length - *idx < 2) RAISE(BUFFER_OVERFLOW);
  mpi->bits = ((msg[*idx] << 8) | msg[*idx + 1]);
  
  mpi->count = (mpi->bits+7)/8;
  LOG_PRINT("MPI Bits: %u\n", mpi->bits);
  
  // Allocate space for MPI data
  mpi->data = malloc(mpi->count + 2);
  if (NULL == mpi->data) RAISE(OUT_OF_MEMORY);
  
  // Copy data from input buffer to mpi buffer
  memcpy(mpi->data, msg+*idx, mpi->count + 2);
  *idx += mpi->count + 1;
  
  return mpi;
}
