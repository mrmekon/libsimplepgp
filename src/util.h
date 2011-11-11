/*
 *  util.h
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

#ifndef _UTIL_H

#include "packet_private.h"

uint8_t spgp_pgp_to_gcrypt_symmetric_algo(uint8_t pgpalgo);
                            
uint8_t spgp_iv_length_for_symmetric_algo(uint8_t algo);

uint8_t spgp_salt_length_for_hash_algo(uint8_t algo);

#define _UTIL_H
#endif
