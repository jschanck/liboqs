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

#define MESSAGE_LEN 100

static OQS_SIG *sig = NULL;
static uint8_t *public_key_A = NULL;
static uint8_t *public_key_B = NULL;
static uint8_t *secret_key_A = NULL;
static uint8_t *secret_key_B = NULL;
static uint8_t *signature_A = NULL;
static uint8_t *signature_B = NULL;

static size_t signature_len_A;
static size_t signature_len_B;
static uint8_t message[MESSAGE_LEN];

static int initialized = 0;

/* libFuzzer is clang specific, so we can use the __attribute__ extension */

__attribute__((constructor)) static void start(void) {
	if (!initialized) {
		sig = OQS_SIG_new(FUZZ_TARGET);

		public_key_A = malloc(sig->length_public_key);
		secret_key_A = malloc(sig->length_secret_key);
		signature_A = malloc(sig->length_signature);

		public_key_B = malloc(sig->length_public_key);
		secret_key_B = malloc(sig->length_secret_key);
		signature_B = malloc(sig->length_signature);

		initialized = 1;
	}
}

__attribute__((destructor)) static void stop(void) {
	if (initialized) {
		OQS_SIG_free(sig);

		free(public_key_A);
		free(secret_key_A);
		free(signature_A);

		free(public_key_B);
		free(secret_key_B);
		free(signature_B);

		initialized = 0;
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	start();

	oqs_fuzz_reset();
	oqs_fuzz_add_bytes(Data, Size);

	OQS_randombytes(message, MESSAGE_LEN);

	OQS_SIG_keypair(sig, public_key_A, secret_key_A);
	OQS_SIG_sign(sig, signature_A, &signature_len_A, message, MESSAGE_LEN, secret_key_A);
	OQS_SIG_verify(sig, message, MESSAGE_LEN, signature_A, signature_len_A, public_key_A);

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

	OQS_randombytes(message, MESSAGE_LEN);

	OQS_SIG_keypair(sig, public_key_B, secret_key_B);
	OQS_SIG_sign(sig, signature_B, &signature_len_B, message, MESSAGE_LEN, secret_key_B);
	OQS_SIG_verify(sig, message, MESSAGE_LEN, signature_B, signature_len_B, public_key_B);

	assert(0 == memcmp(public_key_A, public_key_B, sig->length_public_key));
	assert(0 == memcmp(secret_key_A, secret_key_B, sig->length_secret_key));
	assert(signature_len_A == signature_len_B);
	assert(0 == memcmp(signature_A, signature_B, signature_len_A));

	return 0;
}
