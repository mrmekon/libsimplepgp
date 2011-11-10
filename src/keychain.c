/*
 *  keychain.c
 *  simplepgp
 *
 *  Created by Trevor Bentley on 11/8/11.
 *  Copyright 2011 Trevor Bentley. All rights reserved.
 *
 */

#include "keychain.h"

#define SPGP_KEYCHAIN_DEFAULT_SIZE 5

static pthread_mutex_t keychain_mtx;
static spgp_packet_t **keychain;
static uint32_t kc_count;
static uint32_t kc_used;

static uint32_t iter_idx;

uint8_t spgp_keychain_init(void) {
	if (pthread_mutex_init(&keychain_mtx, NULL)) return -1;

	keychain = malloc(sizeof(spgp_packet_t*) * SPGP_KEYCHAIN_DEFAULT_SIZE);
  if (NULL == keychain) return -1;
  kc_count = SPGP_KEYCHAIN_DEFAULT_SIZE;
	kc_used = 0;
  
	return 0;
}

uint8_t spgp_keychain_free(void) {
	kc_count = 0;
  kc_used = 0;
  free(keychain);
  keychain = NULL;
	pthread_mutex_destroy(&keychain_mtx);
	return 0;
}

uint8_t spgp_keychain_is_valid(void) {
	if (keychain) return 1;
  return 0;
}

uint8_t spgp_keychain_add_packet(spgp_packet_t *pkt) {
	if (NULL == pkt) return -1;
  
  pthread_mutex_lock(&keychain_mtx);
  
  if (kc_used == kc_count) {
  	// Need to allocate more space
    return -1; // for now, unsupported
  }
  
  keychain[kc_used] = pkt;
  kc_used++;

	// Potential feature:
  // If we wanted to be really fuckin' fancy, we could use 'secure memory'
  // to store secret keys.  Use mlock() to get a page that will never be
  // swapped to disk, and clear it when we exit.

	LOG_PRINT("Added packet to keychain.");

  pthread_mutex_unlock(&keychain_mtx);
  
	return 0;
}

uint8_t spgp_keychain_del_packet(spgp_packet_t *pkt) {
  pthread_mutex_lock(&keychain_mtx);
  pthread_mutex_unlock(&keychain_mtx);

	return -1;
}

uint8_t spgp_keychain_iter_start(void) {
  pthread_mutex_lock(&keychain_mtx);
  iter_idx = 0;
  return 0;
}
uint8_t spgp_keychain_iter_end(void) {
  pthread_mutex_unlock(&keychain_mtx);
  return 0;
}
spgp_packet_t *spgp_keychain_iter_next(void) {
	if (iter_idx < kc_used)
  	return keychain[iter_idx++];
  return NULL;
}

spgp_packet_t *spgp_keychain_secret_key_with_id(uint8_t *keyid) {
  pthread_mutex_lock(&keychain_mtx);

  pthread_mutex_unlock(&keychain_mtx);

	return NULL;
}
