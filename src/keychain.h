/*
 *  keychain.h
 *  simplepgp
 *
 *  Created by Trevor Bentley on 11/8/11.
 *  Copyright 2011 Trevor Bentley. All rights reserved.
 *
 */

#ifndef _KEYCHAIN_H

#include <stdint.h>
#include <pthread.h>
#include "packet.h"


uint8_t spgp_keychain_init(void);
uint8_t spgp_keychain_free(void);
uint8_t spgp_keychain_is_valid(void);

uint8_t spgp_keychain_add_packet(spgp_packet_t *pkt);
uint8_t spgp_keychain_del_packet(spgp_packet_t *pkt);

uint8_t spgp_keychain_iter_start(void);
uint8_t spgp_keychain_iter_end(void);
spgp_packet_t *spgp_keychain_iter_next(void);

spgp_packet_t *spgp_keychain_secret_key_with_id(uint8_t *keyid);

#define _KEYCHAIN_H
#endif
