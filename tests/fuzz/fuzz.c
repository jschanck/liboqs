/*
 * \file fuzz.c
 * \brief A library that facilitates fuzzing of liboqs
 *
 * When loaded before liboqs, this library simulates the random
 * oracles listed below. It lets a fuzzer tamper with the query
 * random oracle outputs, but still answers queries consistently.
 *
 * Random oracles:
 *    OQS_randombytes
 *    OQS_SHA2_sha256
 *    OQS_SHA2_sha256_inc_finalize
 *    OQS_SHA2_sha384
 *    OQS_SHA2_sha384_inc_finalize
 *    OQS_SHA2_sha512
 *    OQS_SHA2_sha512_inc_finalize
 *    OQS_SHA3_sha3_256
 *    OQS_SHA3_sha3_512
 *    OQS_SHA3_shake128
 *    OQS_SHA3_shake256
 *    OQS_SHA3_shake128_inc_squeeze
 *    OQS_SHA3_shake256_inc_squeeze
 *    OQS_SHA3_shake128_x4
 *    OQS_SHA3_shake256_x4
 *    OQS_SHA3_shake128_x4_inc_squeeze
 *    OQS_SHA3_shake256_x4_inc_squeeze
 *    OQS_AES128_ECB_enc
 *    OQS_AES128_ECB_enc_sch
 *    OQS_AES256_ECB_enc
 *    OQS_AES256_ECB_enc_sch
 *    OQS_AES256_CTR_sch
 *
 * \author John M. Schanck
 *
 * SPDX-License-Identifier: MIT
 */

#include "fuzz.h"
#include "internal.h"

#include <oqs/oqs.h>
#include <oqs/oqsconfig.h>

#include <dlfcn.h>

/** global state **/

/* The root of the tree storing (s, H(s)) */
static query_hdr *RO = NULL;

/* Toggle for switching between implementations */
static int g_fuzz_impl = 0;

/* Counter to track number of randombytes calls */
static uint64_t g_prg_ctr = 0;

/* The fuzzer provided input */
static struct {
	uint8_t *b;
	size_t len;
	size_t offset;
	int exhausted;
} g_input = {NULL, 0, 0, 0};


/** Forward references to liboqs functions. **/

/* These references allow us to call the overloaded liboqs functions */
#define FWD(fn) fwd_##fn
#define FWD_DECLARE(ret, fn, ...) static ret (*FWD(fn))(__VA_ARGS__)
#define FWD_ASSIGN(ret, fn, ...)  FWD(fn) = (ret (*)(__VA_ARGS__))dlsym(RTLD_NEXT, #fn)

FWD_DECLARE(int, OQS_CPU_has_extension, OQS_CPU_EXT);
FWD_DECLARE(void, OQS_SHA2_sha256, uint8_t *output, const uint8_t *input, size_t inlen);
FWD_DECLARE(void, OQS_SHA2_sha384, uint8_t *output, const uint8_t *input, size_t inlen);
FWD_DECLARE(void, OQS_SHA2_sha512, uint8_t *output, const uint8_t *input, size_t inlen);
FWD_DECLARE(void, OQS_SHA2_sha256_inc_finalize, uint8_t *out, OQS_SHA2_sha256_ctx *state, const uint8_t *in, size_t inlen);
FWD_DECLARE(void, OQS_SHA2_sha384_inc_finalize, uint8_t *out, OQS_SHA2_sha384_ctx *state, const uint8_t *in, size_t inlen);
FWD_DECLARE(void, OQS_SHA2_sha512_inc_finalize, uint8_t *out, OQS_SHA2_sha512_ctx *state, const uint8_t *in, size_t inlen);
FWD_DECLARE(void, OQS_SHA3_sha3_256, uint8_t *output, const uint8_t *input, size_t inlen);
FWD_DECLARE(void, OQS_SHA3_sha3_512, uint8_t *output, const uint8_t *input, size_t inlen);
FWD_DECLARE(void, OQS_SHA3_shake128, uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen);
FWD_DECLARE(void, OQS_SHA3_shake256, uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen);
FWD_DECLARE(void, OQS_SHA3_shake128_inc_squeeze, uint8_t *, size_t, OQS_SHA3_shake128_inc_ctx *);
FWD_DECLARE(void, OQS_SHA3_shake256_inc_squeeze, uint8_t *, size_t, OQS_SHA3_shake256_inc_ctx *);
FWD_DECLARE(void, OQS_SHA3_shake128_x4_inc_squeeze, uint8_t *, uint8_t *, uint8_t *, uint8_t *, size_t, OQS_SHA3_shake128_x4_inc_ctx *);
FWD_DECLARE(void, OQS_SHA3_shake256_x4_inc_squeeze, uint8_t *, uint8_t *, uint8_t *, uint8_t *, size_t, OQS_SHA3_shake256_x4_inc_ctx *);
FWD_DECLARE(void, OQS_AES128_ECB_enc, const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext);
FWD_DECLARE(void, OQS_AES128_ECB_enc_sch, const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext);
FWD_DECLARE(void, OQS_AES256_ECB_enc, const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext);
FWD_DECLARE(void, OQS_AES256_ECB_enc_sch, const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext);
FWD_DECLARE(void, OQS_AES256_CTR_sch, const uint8_t *iv, size_t iv_len, const void *schedule, uint8_t *out, size_t out_len);


/** Random oracle simulation **/

/* see internal.h for overview */

query_hdr *query_alloc(size_t len, uint64_t seed) {
	query_hdr *new = (query_hdr *)malloc(sizeof(query_hdr) + len);
	new->left = NULL;
	new->right = NULL;
	new->seed = seed;
	new->len = len;
	if (g_input.len < len + g_input.offset) {
		oqs_fuzz_add_bytes(NULL, len + g_input.offset - g_input.len);
		g_input.exhausted = 1;
	}
	for (size_t i = 0; i < len; i++) {
		H(new)[i] = g_input.b[g_input.offset++];
	}
	return new;
}

void squeeze(uint8_t *out, size_t len, uint64_t seed, size_t skip) {
	query_hdr *Q, **next;
	uint8_t *x;
	size_t xlen;

	if (RO == NULL) {
		oqs_fuzz_reset();
	}
	Q = RO;

	/* Traverse the tree and read from stored H(seed) entries */
	do {
		if (seed == Q->seed) {
			x = H(Q);
			xlen = Q->len;
			while (skip != 0 && xlen != 0) {
				++x;
				--skip;
				--xlen;
			}
			while (skip == 0 && xlen != 0 && len != 0) {
				*out++ = *x++;
				--xlen;
				--len;
			}
		}
		next = (seed < Q->seed) ? &(Q->left) : &(Q->right);
		if (*next == NULL && len != 0) {
			// add a new node to the tree
			*next = query_alloc(len, seed);
		}
		Q = *next;
	} while (len > 0 && Q != NULL);
}


/** public api **/

void oqs_fuzz_switch_impl(void) {
	g_fuzz_impl ^= 1;
}

void oqs_fuzz_randombytes_reseed(void) {
	g_prg_ctr = 0;
}

static void free_tree(query_hdr *x) {
	if (x != NULL) {
		free_tree(x->left);
		free_tree(x->right);
		free(x);
	}
}

void oqs_fuzz_reset(void) {
	free_tree(RO);
	RO = query_alloc(0, ((uint64_t) 1) << 63);

	if (g_input.b != NULL) {
		free(g_input.b);
	}
	g_input.b = NULL;
	g_input.len = 0;
	g_input.offset = 0;
	g_input.exhausted = 0;

	oqs_fuzz_randombytes_reseed();
	oqs_fuzz_switch_impl();
}

static void oqs_fuzz_extend(size_t extlen) {
	OQS_SHA3_shake128_inc_ctx state;
	size_t i;
	uint8_t *new;

	// Extend to at least double length to minimize need for repeated calls
	if (extlen < g_input.len) {
		extlen = g_input.len;
	}
	new = malloc(g_input.len + extlen);

	OQS_SHA3_shake128_inc_init(&state);
	OQS_SHA3_shake128_inc_finalize(&state);
	FWD(OQS_SHA3_shake128_inc_squeeze)(new, g_input.len + extlen, &state);
	OQS_SHA3_shake128_inc_ctx_release(&state);

	for (i = 0; i < g_input.len; i++) {
		new[i] = g_input.b[i];
	}

	if (g_input.b != NULL) {
		free(g_input.b);
	}
	g_input.b = new;
	g_input.len += extlen;
}

void oqs_fuzz_add_bytes(const uint8_t *in, size_t len) {
	if (in == NULL) {
		oqs_fuzz_extend(len);
		return;
	}

	if (g_input.len < len + g_input.offset) {
		oqs_fuzz_extend(len + g_input.offset - g_input.len);
	}
	for (size_t i = 0; i < len; i++) {
		g_input.b[g_input.offset + i] ^= in[i];
	}
}

int oqs_fuzz_exhausted(void) {
	return g_input.exhausted;
}


/** A 64 bit hash function (FNV-1a-64) to produce seeds for H **/

uint64_t hash64_update(const uint8_t *in, size_t len, uint64_t h0) {
	for (size_t i = 0; i < len; i++) {
		h0 = (h0 ^ in[i]) * 1099511628211U;
	}
	return h0;
}

uint64_t hash64(const uint8_t *in, size_t len) {
	return hash64_update(in, len, 14695981039346656037U);
}


/** Routines that override liboqs / intercept random oracle calls **/

__attribute__((constructor)) static void oqs_fuzz_load(void) {
	FWD_ASSIGN(int, OQS_CPU_has_extension, OQS_CPU_EXT);
	FWD_ASSIGN(void, OQS_SHA2_sha256, uint8_t *output, const uint8_t *input, size_t inlen);
	FWD_ASSIGN(void, OQS_SHA2_sha384, uint8_t *output, const uint8_t *input, size_t inlen);
	FWD_ASSIGN(void, OQS_SHA2_sha512, uint8_t *output, const uint8_t *input, size_t inlen);
	FWD_ASSIGN(void, OQS_SHA2_sha256_inc_finalize, uint8_t *out, OQS_SHA2_sha256_ctx * state, const uint8_t *in, size_t inlen);
	FWD_ASSIGN(void, OQS_SHA2_sha384_inc_finalize, uint8_t *out, OQS_SHA2_sha384_ctx * state, const uint8_t *in, size_t inlen);
	FWD_ASSIGN(void, OQS_SHA2_sha512_inc_finalize, uint8_t *out, OQS_SHA2_sha512_ctx * state, const uint8_t *in, size_t inlen);
	FWD_ASSIGN(void, OQS_SHA3_sha3_256, uint8_t *output, const uint8_t *input, size_t inlen);
	FWD_ASSIGN(void, OQS_SHA3_sha3_512, uint8_t *output, const uint8_t *input, size_t inlen);
	FWD_ASSIGN(void, OQS_SHA3_shake128, uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen);
	FWD_ASSIGN(void, OQS_SHA3_shake256, uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen);
	FWD_ASSIGN(void, OQS_SHA3_shake128_inc_squeeze, uint8_t *, size_t, OQS_SHA3_shake128_inc_ctx *);
	FWD_ASSIGN(void, OQS_SHA3_shake256_inc_squeeze, uint8_t *, size_t, OQS_SHA3_shake256_inc_ctx *);
	FWD_ASSIGN(void, OQS_SHA3_shake128_x4_inc_squeeze, uint8_t *, uint8_t *, uint8_t *, uint8_t *, size_t, OQS_SHA3_shake128_x4_inc_ctx *);
	FWD_ASSIGN(void, OQS_SHA3_shake256_x4_inc_squeeze, uint8_t *, uint8_t *, uint8_t *, uint8_t *, size_t, OQS_SHA3_shake256_x4_inc_ctx *);
	FWD_ASSIGN(void, OQS_AES128_ECB_enc, const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext);
	FWD_ASSIGN(void, OQS_AES128_ECB_enc_sch, const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext);
	FWD_ASSIGN(void, OQS_AES256_ECB_enc, const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext);
	FWD_ASSIGN(void, OQS_AES256_ECB_enc_sch, const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext);
	FWD_ASSIGN(void, OQS_AES256_CTR_sch, const uint8_t *iv, size_t iv_len, const void *schedule, uint8_t *out, size_t out_len);
}

int OQS_CPU_has_extension(OQS_CPU_EXT ext) {
	if (g_fuzz_impl) {
		return FWD(OQS_CPU_has_extension(ext));
	}
	return 0;
}

void OQS_randombytes(uint8_t *random_array, size_t bytes_to_read) {
	uint8_t domain[] = "randombytes";
	uint64_t seed;
	seed = hash64(domain, sizeof(domain));
	seed = hash64_update((const uint8_t *)&g_prg_ctr, sizeof(g_prg_ctr), seed);
	squeeze(random_array, bytes_to_read, seed, 0);
	g_prg_ctr++;
}


void OQS_SHA2_sha256(uint8_t *output, const uint8_t *input, size_t inplen) {
	uint64_t seed;
	FWD(OQS_SHA2_sha256)(output, input, inplen);
	seed = hash64(output, 32);
	squeeze(output, 32, seed, 0);
}

void OQS_SHA2_sha256_inc_finalize(uint8_t *out, OQS_SHA2_sha256_ctx *state, const uint8_t *in, size_t inlen) {
	uint64_t seed;
	FWD(OQS_SHA2_sha256_inc_finalize)(out, state, in, inlen);
	seed = hash64(out, 32);
	squeeze(out, 32, seed, 0);
}

void OQS_SHA2_sha384(uint8_t *output, const uint8_t *input, size_t inplen) {
	uint64_t seed;
	FWD(OQS_SHA2_sha384)(output, input, inplen);
	seed = hash64(output, 48);
	squeeze(output, 48, seed, 0);
}

void OQS_SHA2_sha384_inc_finalize(uint8_t *out, OQS_SHA2_sha384_ctx *state, const uint8_t *in, size_t inlen) {
	uint64_t seed;
	FWD(OQS_SHA2_sha384_inc_finalize)(out, state, in, inlen);
	seed = hash64(out, 48);
	squeeze(out, 48, seed, 0);
}

void OQS_SHA2_sha512(uint8_t *output, const uint8_t *input, size_t inplen) {
	uint64_t seed;
	FWD(OQS_SHA2_sha512)(output, input, inplen);
	seed = hash64(output, 64);
	squeeze(output, 64, seed, 0);
}

void OQS_SHA2_sha512_inc_finalize(uint8_t *out, OQS_SHA2_sha512_ctx *state, const uint8_t *in, size_t inlen) {
	uint64_t seed;
	FWD(OQS_SHA2_sha512_inc_finalize)(out, state, in, inlen);
	seed = hash64(out, 64);
	squeeze(out, 64, seed, 0);
}

void OQS_SHA3_sha3_256(uint8_t *output, const uint8_t *input, size_t inplen) {
	uint64_t seed;
	FWD(OQS_SHA3_sha3_256)(output, input, inplen);
	seed = hash64(output, 32);
	squeeze(output, 32, seed, 0);
}

void OQS_SHA3_sha3_512(uint8_t *output, const uint8_t *input, size_t inplen) {
	uint64_t seed;
	FWD(OQS_SHA3_sha3_512)(output, input, inplen);
	seed = hash64(output, 64);
	squeeze(output, 64, seed, 0);
}

void OQS_SHA3_shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen) {
	uint64_t seed;
	FWD(OQS_SHA3_shake128)(output, outlen, input, inplen);
	seed = hash64(output, outlen);
	squeeze(output, outlen, seed, 0);
}

void OQS_SHA3_shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen) {
	uint64_t seed;
	FWD(OQS_SHA3_shake256)(output, outlen, input, inplen);
	seed = hash64(output, outlen);
	squeeze(output, outlen, seed, 0);
}

void OQS_SHA3_shake128_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake128_inc_ctx *state) {
	uint64_t seed;
	FWD(OQS_SHA3_shake128_inc_squeeze)(output, outlen, state);
	seed = hash64(output, outlen);
	squeeze(output, outlen, seed, 0);
}

void OQS_SHA3_shake256_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake256_inc_ctx *state) {
	uint64_t seed;
	FWD(OQS_SHA3_shake256_inc_squeeze)(output, outlen, state);
	seed = hash64(output, outlen);
	squeeze(output, outlen, seed, 0);
}

void OQS_SHA3_shake128_x4(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, size_t outlen, const uint8_t *in0, const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, size_t inlen) {
	OQS_SHA3_shake128(out0, outlen, in0, inlen);
	OQS_SHA3_shake128(out1, outlen, in1, inlen);
	OQS_SHA3_shake128(out2, outlen, in2, inlen);
	OQS_SHA3_shake128(out3, outlen, in3, inlen);
}

void OQS_SHA3_shake256_x4(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, size_t outlen, const uint8_t *in0, const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, size_t inlen) {
	OQS_SHA3_shake256(out0, outlen, in0, inlen);
	OQS_SHA3_shake256(out1, outlen, in1, inlen);
	OQS_SHA3_shake256(out2, outlen, in2, inlen);
	OQS_SHA3_shake256(out3, outlen, in3, inlen);
}

void OQS_SHA3_shake128_x4_inc_squeeze( uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, size_t outlen, OQS_SHA3_shake128_x4_inc_ctx *state) {
	uint64_t seed0, seed1, seed2, seed3;
	FWD(OQS_SHA3_shake128_x4_inc_squeeze)(out0, out1, out2, out3, outlen, state);
	seed0 = hash64(out0, outlen);
	seed1 = hash64(out1, outlen);
	seed2 = hash64(out2, outlen);
	seed3 = hash64(out3, outlen);
	squeeze(out0, outlen, seed0, 0);
	squeeze(out1, outlen, seed1, 0);
	squeeze(out2, outlen, seed2, 0);
	squeeze(out3, outlen, seed3, 0);
}

void OQS_SHA3_shake256_x4_inc_squeeze( uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, size_t outlen, OQS_SHA3_shake256_x4_inc_ctx *state) {
	uint64_t seed0, seed1, seed2, seed3;
	FWD(OQS_SHA3_shake256_x4_inc_squeeze)(out0, out1, out2, out3, outlen, state);
	seed0 = hash64(out0, outlen);
	seed1 = hash64(out1, outlen);
	seed2 = hash64(out2, outlen);
	seed3 = hash64(out3, outlen);
	squeeze(out0, outlen, seed0, 0);
	squeeze(out1, outlen, seed1, 0);
	squeeze(out2, outlen, seed2, 0);
	squeeze(out3, outlen, seed3, 0);
}

void OQS_AES128_ECB_enc(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext) {
	uint64_t seed;
	FWD(OQS_AES128_ECB_enc)(plaintext, plaintext_len, key, ciphertext);
	seed = hash64(ciphertext, plaintext_len);
	squeeze(ciphertext, plaintext_len, seed, 0);
}

void OQS_AES128_ECB_enc_sch(const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext) {
	uint64_t seed;
	FWD(OQS_AES128_ECB_enc_sch)(plaintext, plaintext_len, schedule, ciphertext);
	seed = hash64(ciphertext, plaintext_len);
	squeeze(ciphertext, plaintext_len, seed, 0);
}

void OQS_AES256_ECB_enc(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext) {
	uint64_t seed;
	FWD(OQS_AES256_ECB_enc)(plaintext, plaintext_len, key, ciphertext);
	seed = hash64(ciphertext, plaintext_len);
	squeeze(ciphertext, plaintext_len, seed, 0);
}

void OQS_AES256_ECB_enc_sch(const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext) {
	uint64_t seed;
	FWD(OQS_AES256_ECB_enc_sch)(plaintext, plaintext_len, schedule, ciphertext);
	seed = hash64(ciphertext, plaintext_len);
	squeeze(ciphertext, plaintext_len, seed, 0);
}

void OQS_AES256_CTR_sch(const uint8_t *iv, size_t iv_len, const void *schedule, uint8_t *out, size_t out_len) {
	uint64_t seed;
	FWD(OQS_AES256_CTR_sch)(iv, iv_len, schedule, out, out_len);
	seed = hash64(out, out_len);
	squeeze(out, out_len, seed, 0);
}
