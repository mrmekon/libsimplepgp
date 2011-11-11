/*
 *  util.c
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

#include "util.h"

uint8_t spgp_pgp_to_gcrypt_symmetric_algo(uint8_t pgpalgo) {
  switch (pgpalgo) {
  case 1: return GCRY_CIPHER_IDEA;
  case 2: return GCRY_CIPHER_3DES;
  case 3: return GCRY_CIPHER_CAST5;
  case 4: return GCRY_CIPHER_BLOWFISH;
  case 7: return GCRY_CIPHER_AES128;
  case 8: return GCRY_CIPHER_AES192;
  case 9: return GCRY_CIPHER_AES256;
  case 10:return GCRY_CIPHER_TWOFISH;
  default: return 0xFF;
  }
}

uint8_t spgp_iv_length_for_symmetric_algo(uint8_t algo) {
	size_t ivlen = 0;
	if (gcry_cipher_algo_info(spgp_pgp_to_gcrypt_symmetric_algo(algo), 
  													GCRYCTL_GET_BLKLEN, 
                            NULL, 
                            &ivlen) != 0)
  	RAISE(FORMAT_UNSUPPORTED);
  return ivlen;
}

uint8_t spgp_salt_length_for_hash_algo(uint8_t algo) {
	if (algo == HASH_ALGO_SHA1) return 8;
  else RAISE(FORMAT_UNSUPPORTED); // not implemented
  return 0;
}

