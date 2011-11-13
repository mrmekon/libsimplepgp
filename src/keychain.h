/*
 *  keychain.h
 *  simplepgp
 *
 *  Created by Trevor Bentley on 11/8/11.
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

#ifndef _KEYCHAIN_H

#include <stdint.h>
#include "simplepgp.h"


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
