/*
 *  simplepgp.h
 *  libsimplepgp
 *
 *  Created by Trevor Bentley on 11/1/11.
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
 
#ifndef _PACKET_H

#include <stdio.h>
#include <stdint.h>

typedef struct spgp_packet_header_struct spgp_pkt_header_t;
typedef struct spgp_packet_struct spgp_packet_t;
typedef struct spgp_mpi_struct spgp_mpi_t;
typedef struct spgp_public_packet_struct    spgp_public_pkt_t;
typedef struct spgp_secret_packet_struct    spgp_secret_pkt_t;
typedef struct spgp_userid_packet_struct    spgp_userid_pkt_t;
typedef struct spgp_session_packet_struct   spgp_session_pkt_t;
typedef struct spgp_literal_packet_struct   spgp_literal_pkt_t;
typedef struct spgp_signature_packet_struct spgp_signature_pkt_t;

/**
 * Initialize simplepgp library
 *
 * This function MUST be called before calling any other functions in the
 * simplepgp library.  It initializes global variables and data structures
 * that are used throughout the library.
 *
 * @return 0 on success, non-zero on failure
 */
uint8_t spgp_init(void);

/**
 * Call when finished with simplepgp library to free resources.
 *
 * @return 0 on success, non-zero on failure
 */
uint8_t spgp_close(void);


/**
 * Break a binary OpenPGP message into decoded packets.
 *
 * This is the work-horse function of the library.  OpenPGP message, which may
 * be keys or encrypted data, are passed into this function.  It splits them
 * into a linked-list of OpenPGP packets, which can further be manipulated
 * by other functions within the library.
 *
 * Encrypted messages will be decrypted automatically using keys found in the
 * in-RAM keychain.  See spgp_decrypt_all_secret_keys() for how to load
 * a secret key into the keychain.
 *
 * @param message Binary OpenPGP message to analyze
 * @param length Length of |message|
 * @return Linked list of decoded PGP packets, or NULL on failure
 */
spgp_packet_t *spgp_decode_message(uint8_t *message, uint32_t length);


/**
 * Decrypt all secret keys found in |msg| with given passphrase.
 *
 * Call this function after decoding a message known to contain secret keys.
 * This function decrypts the secret keys in the packet chain, and stores the
 * decrypted keys internally in the in-RAM keychain.
 *
 * @param msg Linked list of PGP packets
 * @param passphrase String to use as decryption passphrase.  No NUL termination.
 * @param length Length of passphrase.
 * @return 0 for success, non-0 for failure.
 */
uint8_t spgp_decrypt_all_secret_keys(spgp_packet_t *msg, 
                                		 uint8_t *passphrase, uint32_t length);
                                     
/**
 * Gets the literal data buffer from a decrypted message
 *
 * @param Linked-list of packets to search for data
 * @param datalen Set to size of returned data (in bytes)
 * @param filename Set to buffer containing filename
 * @param filenamelen Set to size of filename (in bytes)
 * @return Buffer with literal data, or NULL if none available
 */
char *spgp_get_literal_data(spgp_packet_t *msg, uint32_t *datalen,
														char **filename, uint32_t *filenamelen);

/**
 * Frees all dynamic resources associated with |pkt|.
 *
 * @param pkt Pointer-to-pointer-to-packet to free.
 */
void spgp_free_packet(spgp_packet_t **pkt);

/**
 * Get last error code
 *
 * @return Value of last error
 */
uint32_t spgp_err(void);

/**
 * Return a string describing error code |err|.
 *
 * @return String describing error code |err|
 */
const char *spgp_err_str(uint32_t err);

/**
 * Return true if debugging enabled, false otherwise.
 *
 * @return 0 if logging disabled, non-zero if logging enabled.
 */
uint8_t spgp_debug_log_enabled(void);

/**
 * Enables debug logging to stderr
 *
 * @param enable 0 if logging should be off, 1 if logging should be on.
 */
void spgp_debug_log_set(uint8_t enable);

#define _PACKET_H
#endif
