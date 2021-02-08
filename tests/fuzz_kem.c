// SPDX-License-Identifier: MIT

#include "fuzz.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#ifndef FUZZ_TARGET
#define FUZZ_TARGET Default
#endif

static OQS_KEM *kem = NULL;
static uint8_t *public_key_A = NULL;
static uint8_t *public_key_B = NULL;
static uint8_t *secret_key_A = NULL;
static uint8_t *secret_key_B = NULL;
static uint8_t *ciphertext_A = NULL;
static uint8_t *ciphertext_B = NULL;
static uint8_t *shared_secret_d_A = NULL;
static uint8_t *shared_secret_d_B = NULL;
static uint8_t *shared_secret_e_A = NULL;
static uint8_t *shared_secret_e_B = NULL;

static int initialized = 0;

/* libFuzzer is clang specific, so we can use the __attribute__ extension */

__attribute__((constructor)) static void start(void) {
	if (!initialized) {
		kem = OQS_KEM_new(FUZZ_TARGET);

		public_key_A = malloc(kem->length_public_key);
		secret_key_A = malloc(kem->length_secret_key);
		ciphertext_A = malloc(kem->length_ciphertext);
		shared_secret_e_A = malloc(kem->length_shared_secret);
		shared_secret_d_A = malloc(kem->length_shared_secret);

		public_key_B = malloc(kem->length_public_key);
		secret_key_B = malloc(kem->length_secret_key);
		ciphertext_B = malloc(kem->length_ciphertext);
		shared_secret_e_B = malloc(kem->length_shared_secret);
		shared_secret_d_B = malloc(kem->length_shared_secret);

		initialized = 1;
	}
}

__attribute__((destructor)) static void stop(void) {
	if (initialized) {
		OQS_KEM_free(kem);

		free(public_key_A);
		free(secret_key_A);
		free(ciphertext_A);
		free(shared_secret_e_A);
		free(shared_secret_d_A);

		free(public_key_B);
		free(secret_key_B);
		free(ciphertext_B);
		free(shared_secret_e_B);
		free(shared_secret_d_B);

		initialized = 0;
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	start();

	oqs_fuzz_reset();
	oqs_fuzz_add_bytes(Data, Size);

	OQS_KEM_keypair(kem, public_key_A, secret_key_A);
	OQS_KEM_encaps(kem, ciphertext_A, shared_secret_e_A, public_key_A);
	OQS_KEM_decaps(kem, shared_secret_d_A, ciphertext_A, secret_key_A);

	// Check if the fuzzer provided enough input.
	// If not we'll return early to encourage it to provide more
	if (oqs_fuzz_exhausted()) {
		return 0;
	}

	/* Now re-run with a different implementation */
	oqs_fuzz_switch_impl();

	// We do not call oqs_fuzz_reset here since we allow the implementations
	// to differ in the order of RO calls they make. But we do reset the RNG
	oqs_fuzz_randombytes_reseed();

	OQS_KEM_keypair(kem, public_key_B, secret_key_B);
	OQS_KEM_encaps(kem, ciphertext_B, shared_secret_e_B, public_key_B);
	OQS_KEM_decaps(kem, shared_secret_d_B, ciphertext_B, secret_key_B);

	assert(0 == memcmp(public_key_A, public_key_B, kem->length_public_key));
	assert(0 == memcmp(secret_key_A, secret_key_B, kem->length_secret_key));
	assert(0 == memcmp(ciphertext_A, ciphertext_B, kem->length_ciphertext));
	assert(0 == memcmp(shared_secret_e_A, shared_secret_e_B, kem->length_shared_secret));
	assert(0 == memcmp(shared_secret_d_A, shared_secret_d_B, kem->length_shared_secret));

	return 0;
}
