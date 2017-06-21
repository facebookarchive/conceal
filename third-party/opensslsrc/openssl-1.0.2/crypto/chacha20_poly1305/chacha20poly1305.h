/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef OPENSSL_HEADER_POLY1305_H
#define OPENSSL_HEADER_POLY1305_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/crypto.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define POLY1305_MAC_LEN  (16)
#define POLY1305_PAD_LEN  (16)

typedef unsigned char poly1305_state[92];


/* CRYPTO_poly1305_init sets up |state| so that it can be used to calculate an
 * authentication tag with the one-time key |key|. Note that |key| is a
 * one-time key and therefore there is no `reset' method because that would
 * enable several messages to be authenticated with the same key. */
void CRYPTO_poly1305_init(poly1305_state* state, const uint8_t key[32]);

/* CRYPTO_poly1305_update processes |in_len| bytes from |in|. It can be called
 * zero or more times after poly1305_init. */
void CRYPTO_poly1305_update(poly1305_state* state, const uint8_t* in,
                            size_t in_len);

/* CRYPTO_poly1305_finish completes the poly1305 calculation and writes a 16
 * byte authentication tag to |mac|. */
void CRYPTO_poly1305_finish(poly1305_state* state,
                            uint8_t mac[POLY1305_MAC_LEN]);

/* CRYPTO_chacha_20 encrypts |in_len| bytes from |in| with the given key and
 * nonce and writes the result to |out|, which may be equal to |in|. The
 * initial block counter is specified by |counter|. */
void CRYPTO_chacha_20(uint8_t *out, const uint8_t *in, size_t in_len,
                      uint8_t nonce[48]);

#if CHAPOLY_ASM
int chacha20_poly1305_open(uint8_t *pt, const uint8_t *ct, size_t len_in, uint8_t *ad, size_t len_ad, uint8_t *key);
void chacha20_poly1305_seal(uint8_t *ct, const uint8_t *pt, size_t len_in, uint8_t *ad, size_t len_ad, uint8_t *key);
#endif

#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_POLY1305_H */
