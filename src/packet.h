/*
 *  packet.h
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
typedef struct spgp_public_packet_struct  spgp_public_pkt_t;
typedef struct spgp_secret_packet_struct  spgp_secret_pkt_t;
typedef struct spgp_userid_packet_struct  spgp_userid_pkt_t;
typedef struct spgp_session_packet_struct spgp_session_pkt_t;
typedef struct spgp_literal_packet_struct spgp_literal_pkt_t;


/**
 * Break a binary OpenPGP message into decoded packets.
 *
 * @param message Binary OpenPGP message to analyze
 * @param length Length of |message|
 * @return Linked list of decoded PGP packets, or NULL on failure
 */
spgp_packet_t *spgp_decode_message(uint8_t *message, uint32_t length);


/**
 * Decrypt all secret keys found in |msg| with given passphrase.
 *
 * @param msg Linked list of PGP packets
 * @param passphrase String to use as decryption passphrase.  No NUL termination.
 * @param length Length of passphrase.
 * @return 0 for success, non-0 for failure.
 */
uint8_t spgp_decrypt_all_secret_keys(spgp_packet_t *msg, 
                                		 uint8_t *passphrase, uint32_t length);

/**
 * Frees all dynamic resources associated with |pkt|.
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
