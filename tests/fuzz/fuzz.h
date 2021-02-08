/*
 * \file fuzz.h
 * \brief Public API for fuzz.c
 * \author John M. Schanck
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OQS_FUZZ_H
#define OQS_FUZZ_H

#include <stdint.h>
#include <stddef.h>

/* oqs_fuzz_reset
 *
 * Initialize and/or reset the global state.
 * Call at the beginning of LLVMFuzzerTestOneInput.
 */
void oqs_fuzz_reset(void);

/* oqs_fuzz_add_bytes
 *
 * Add data from the fuzzer with which to answer random oracle queries
 */
void oqs_fuzz_add_bytes(const uint8_t *in, size_t len);

/* oqs_fuzz_exhausted
 *
 * Check if all of the fuzzer data was consumed by answering random
 * oracle queries. Returns 0 if it was, and 1 otherwise.
 */
int oqs_fuzz_exhausted(void);

/* oqs_fuzz_randombytes_reseed
 *
 * The i-th call to randombytes outputs F(i). This resets i to 0
 */
void oqs_fuzz_randombytes_reseed(void);

/* oqs_fuzz_switch_impl
 *
 * Toggle between reference and optimized code
 */
void oqs_fuzz_switch_impl(void);

#endif
