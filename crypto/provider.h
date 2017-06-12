/*
 * OMEMO Plugin
 *
 * Copyright (C) 2016-2017, Germán Márquez Mejía <marquez.mejia@fu-berlin.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02111-1301, USA.
 *
 */
#ifndef PROVIDER_H
#define PROVIDER_H

#include <glib.h>
#include <signal_protocol.h>

/**
 * @brief Initialize crypto-provider (if needed)
 * 
 * @retval 0 on success
 */
int init_crypto_provider(void);

int random_generator(uint8_t* data, size_t len, void* user_data);

int hmac_sha256_init(void** hmac_context, const uint8_t* key, size_t key_len, void* user_data);

int hmac_sha256_update(void* hmac_context, const uint8_t* data, size_t data_len, void* user_data);

int hmac_sha256_final(void* hmac_context, signal_buffer** output, void* user_data);

void hmac_sha256_cleanup(void* hmac_context, void* user_data);

int sha512_digest(signal_buffer** output, const uint8_t* data, size_t data_len, void* user_data);

int encrypt(signal_buffer** output,
	int cipher,
	const uint8_t* key,
	size_t key_len,
	const uint8_t* iv,
	size_t iv_len,
	const uint8_t* plaintext,
	size_t plaintext_len,
	void* user_data);

int decrypt(signal_buffer** output,
	int cipher,
	const uint8_t* key,
	size_t key_len,
	const uint8_t* iv,
	size_t iv_len,
	const uint8_t* ciphertext,
	size_t ciphertext_len,
	void* user_data);

/**
 * @brief Decrypts a ciphertext encrypted with AES-128 in Galois/Counter Mode
 * @param plaintext newly allocated result or unset on failure. Must be g_free'd by caller
 * @param plaintext_len result size
 * @param key the decryption key
 * @param key_ken size of the decryption key
 * @param iv the initialization vector used on encryption
 * @param iv_len size of the initialization vector
 * @param tag authentication tag to check against after decryption
 * @param tag_size size of the authentication tag
 * @param ciphertext the ciphertext
 * @param ciphertext_len size of the ciphertext
 * @return 0 on success
 */
int decrypt_aes128_gcm(guint8** plaintext,
	gsize* plaintext_len,
	const guint8* key,
	gsize key_len,
	const guint8* iv,
	gsize iv_len,
	const guint8* tag,
	gsize tag_len,
	const guint8* ciphertext,
	gsize ciphertext_len);

/**
 * @brief Encrypts a plain text with AES-128 in Galois/Counter Mode
 * @param ciphertext newly allocated ciphertext and. Unset on failure. Must be g_free'd by caller
 * @param ciphertext_len ciphertext size. Unset on failure
 * @param tag the newly allocated authentication tag. Unset on failure. Must be g_free'd by caller
 * @param size of the authentication tag. Unset on failure
 * @param key the encryption key
 * @param key_len size of the encryption key
 * @param iv the initialization vector to use
 * @param iv_len size of the initialization vector
 * @param plaintext the plaintext
 * @param plaintext_len size of the plaintext
 * @return 0 on success
 */
int encrypt_aes128_gcm(guint8** ciphertext,
	gsize* ciphertext_len,
	guint8** tag,
	gsize* tag_len,
	const guint8* key,
	gsize key_len,
	const guint8* iv,
	gsize iv_len,
	const guint8* plaintext,
	gsize plaintext_len);

#endif
