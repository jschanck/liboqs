/*
 * \file internal.h
 * \brief Data structures and utility functions for fuzz.c
 * \author John M. Schanck
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OQS_FUZZ_INTERNAL_H
#define OQS_FUZZ_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

/** Data structures **/

/* We simulate XOF-like a random oracle H that maps 8 byte seeds to
 * infinite sequences of bytes.
 *
 * When the program asks for n bytes of H(s) we store (s, H(s)[1:n]) in a binary
 * tree ordered by `s`. Each node of the tree is a dynamically allocated block of
 * memory that contains
 *    [ HEADER(s, length) | DATA ]
 * where HEADER is a query_hdr struct and DATA holds `length` bytes of H(s).
 * Every query that extends H(s) adds a new node to the tree.
 */

typedef struct query_hdr {
	struct query_hdr *left;
	struct query_hdr *right;
	uint64_t seed;
	size_t len;
} query_hdr;

/* H(s) is a pointer to the 'DATA' section following the query_hdr s */
#define H(s) (((uint8_t *)(s)) + sizeof(query_hdr))


/** Utility functions **/

/* query_alloc
 *
 * Allocate a query_hdr and room for `len` bytes of H(seed), and produce
 * a value for H(seed). The value of H(seed) will be fuzzer-influenced if
 * fuzzer provided data is available. Otherwise it will be some pseudorandom
 * string.
 */
query_hdr *query_alloc(size_t len, uint64_t seed);

/* squeeze
 *
 * Read `len` bytes from H(`seed`) starting at index `skip`. This will call
 * call query_alloc if this is the first time we're reading these bytes.
 */
void squeeze(uint8_t *out, size_t len, uint64_t seed, size_t skip);

/* hash64
 *
 * A 64 bit hash function for producing values to pass to H
 */
uint64_t hash64_update(const uint8_t *in, size_t len, uint64_t h0);
uint64_t hash64(const uint8_t *in, size_t len);

#endif
