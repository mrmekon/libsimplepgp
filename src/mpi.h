/*
 *  mpi.h
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

#ifndef _MPI_H

#include "packet_private.h"

uint32_t spgp_mpi_length(uint8_t *mpi);
                                                
spgp_mpi_t *spgp_read_mpi(uint8_t *msg, uint32_t *idx,
														 uint32_t length);
                             
uint8_t spgp_read_all_public_mpis(uint8_t *msg, 
                                         uint32_t *idx,
														 						 uint32_t length, 
                                         spgp_public_pkt_t *pub);
                                         
uint8_t spgp_read_all_secret_mpis(uint8_t *msg, 
                                         uint32_t *idx,
														 						 uint32_t length, 
                                         spgp_secret_pkt_t *secret);
 

#define _MPI_H
#endif
