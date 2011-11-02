/*
 *  packet_test.c
 *  simplepgp
 *
 *  Created by Trevor Bentley on 11/2/11.
 *  Copyright 2011 Trevor Bentley. All rights reserved.
 *
 */

#include "packet_test.h"

#define ASSERT_SUCCESS(result) do { \
		if (result) {PRINT_FAIL();goto fail;} \
    PRINT_PASS(); \
  } while(0)
#define ASSERT_EQUAL(result,val) do { \
		if (result != val) {PRINT_FAIL();goto fail;} \
    PRINT_PASS(); \
  } while(0)
#define PRINT_MODULE() fprintf(stderr, "*** MODULE: %s\n", module);
#define PRINT_FUNCTION() fprintf(stderr, " * FUNCTION %s\n", __FUNCTION__)
#define PRINT_TEST(fmt, ...) fprintf(stderr, "  - " fmt ": ", ## __VA_ARGS__);
#define PRINT_PASS() fprintf(stderr, "PASS\n");
#define PRINT_FAIL() fprintf(stderr, "FAIL\n");

static const char* module;
static const char* function;

static uint8_t test_spgp_decode_message(void) {
	uint8_t buf[1024];
	function = __FUNCTION__;
  PRINT_FUNCTION();
  
  PRINT_TEST("NULL MESSAGE");
	spgp_decode_message(NULL, 100);
  ASSERT_EQUAL(spgp_err(), INVALID_ARGS);  

  PRINT_TEST("ZERO LENGTH");
	spgp_decode_message(buf, 0);
  ASSERT_EQUAL(spgp_err(), INVALID_ARGS);  
  
  return 0;
  fail:
  return 1;
}

uint8_t test_spgp_packet(void) {
	uint8_t wasEnabled;
  
	module = "PACKET";
	PRINT_MODULE();

  wasEnabled = spgp_debug_log_enabled();
  spgp_debug_log_set(0);
  
	ASSERT_SUCCESS(test_spgp_decode_message());
  
  spgp_debug_log_set(wasEnabled);
  
  return 0;
  fail:
  return 1;
}