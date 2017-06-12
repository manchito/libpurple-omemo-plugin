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
#include <debug.h>
#include <gcrypt.h>

#include "../omemo.h"

#include "provider.h"

int init_crypto_provider()
{
	gcry_check_version(NULL);
	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

	return 0;
}

int random_generator(uint8_t* data, size_t len, void* user_data)
{
	gcry_randomize(data, len, GCRY_STRONG_RANDOM);

	return 0;
}

int hmac_sha256_init(void** hmac_context, const uint8_t* key, size_t key_len, void* user_data)
{
	gcry_mac_hd_t* handle = NULL;
	gcry_error_t err = GPG_ERR_NO_ERROR;

	handle = malloc(sizeof(gcry_mac_hd_t));
	if (!handle) {
		return SG_ERR_NOMEM;
	}

	err = gcry_mac_open(handle, GCRY_MAC_HMAC_SHA256, 0, NULL);
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		free(handle);
		return SG_ERR_UNKNOWN;
	}

	err = gcry_mac_setkey(*handle, key, key_len);
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		gcry_mac_close(*handle);
		free(handle);
		return SG_ERR_UNKNOWN;
	}

	*hmac_context = handle;

	return 0;
}

int hmac_sha256_update(void* hmac_context, const uint8_t* data, size_t data_len, void* user_data)
{
	gcry_mac_hd_t* handle = NULL;
	gcry_error_t err = GPG_ERR_NO_ERROR;

	handle = (gcry_mac_hd_t*) hmac_context;
	err = gcry_mac_write(*handle, data, data_len);
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		return SG_ERR_UNKNOWN;
	}

	return 0;
}

int hmac_sha256_final(void* hmac_context, signal_buffer** output, void* user_data)
{
	size_t len = gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA256);
	gcry_mac_hd_t* handle = NULL;
	uint8_t buffer[len];
	signal_buffer* output_buffer = NULL;
	gcry_error_t err = GPG_ERR_NO_ERROR;

	handle = (gcry_mac_hd_t*) hmac_context;
	err = gcry_mac_read(*handle, buffer, &len);
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		return SG_ERR_UNKNOWN;
	}

	output_buffer = signal_buffer_create(buffer, len);
	if (!output_buffer) {
		return SG_ERR_NOMEM;
	}

	//purple_debug_misc(PLUGIN_ID, _("HMAC SHA-256 finalized\n"));

	*output = output_buffer;

	return 0;
}

void hmac_sha256_cleanup(void* hmac_context, void* user_data)
{
	gcry_mac_hd_t* handle = NULL;

	handle = (gcry_mac_hd_t*) hmac_context;

	gcry_mac_close(*handle);
	free(handle);
}

int sha512_digest(signal_buffer** output, const uint8_t* data, size_t data_len, void* user_data)
{
	uint8_t buffer[gcry_md_get_algo_dlen(GCRY_MD_SHA512)];
	signal_buffer* output_buffer = NULL;

	gcry_md_hash_buffer(GCRY_MD_SHA512, buffer, data, data_len);

	output_buffer = signal_buffer_create(buffer, gcry_md_get_algo_dlen(GCRY_MD_SHA512));
	if (!output_buffer) {
		return SG_ERR_NOMEM;
	}

	//purple_debug_misc(PLUGIN_ID, _("Computed SHA-512 hash value\n"));

	*output = output_buffer;

	return 0;
}

static int encrypt_aes_cbc(signal_buffer** output,
	const uint8_t* key,
	size_t key_len,
	const uint8_t* iv,
	size_t iv_len,
	const uint8_t* plaintext,
	size_t plaintext_len)
{
	int cipher_mode = GCRY_CIPHER_MODE_CBC;
	int cipher_algo;
	gcry_cipher_hd_t handle;
	uint8_t* buffer = NULL;
	size_t plaintext_padded_len;
	gcry_error_t err = GPG_ERR_NO_ERROR;
	signal_buffer* output_buffer = NULL;
	size_t padding_len = 0;
	size_t blocksize = 0;
	uint8_t* plaintext_padded = NULL;

	switch (key_len) {
		case 16:
			cipher_algo = GCRY_CIPHER_AES128;
			break;
		case 24:
			cipher_algo = GCRY_CIPHER_AES192;
			break;
		case 32:
			cipher_algo = GCRY_CIPHER_AES256;
			break;
		default:
			purple_debug_error(PLUGIN_ID, "Invalid AES key length (%u)\n", (uint32_t) key_len);
			return SG_ERR_UNKNOWN;
	}

	blocksize = gcry_cipher_get_algo_blklen(cipher_algo);

	err = gcry_cipher_open(&handle, cipher_algo, cipher_mode, 0);
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		return SG_ERR_UNKNOWN;
	}

	err = gcry_cipher_setkey(handle, key, key_len);
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		gcry_cipher_close(handle);
		return SG_ERR_UNKNOWN;
	}

	err = gcry_cipher_setiv(handle, iv, iv_len);
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		gcry_cipher_close(handle);
		return SG_ERR_UNKNOWN;
	}

	// Padding
	padding_len = blocksize - (plaintext_len % blocksize);
	plaintext_padded_len = plaintext_len + padding_len;
	plaintext_padded = malloc(plaintext_padded_len);
	if (!plaintext_padded) {
		return SG_ERR_NOMEM;
	}
	memset(plaintext_padded, (uint8_t) padding_len, plaintext_padded_len);
	memcpy(plaintext_padded, plaintext, plaintext_len);

	buffer = malloc(plaintext_padded_len);
	if (!buffer) {
		gcry_cipher_close(handle);
		return SG_ERR_NOMEM;
	}

	err = gcry_cipher_encrypt(handle, buffer, plaintext_padded_len, plaintext_padded,
		plaintext_padded_len);
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		gcry_cipher_close(handle);
		free(plaintext_padded);
		free(buffer);
		return SG_ERR_UNKNOWN;
	}
	free(plaintext_padded);

	output_buffer = signal_buffer_create(buffer, plaintext_padded_len);
	if (!output_buffer) {
		gcry_cipher_close(handle);
		free(buffer);
		return SG_ERR_NOMEM;
	}

	gcry_cipher_close(handle);
	free(buffer);

	/*purple_debug_misc(PLUGIN_ID, _("Encrypted %u bytes with %s in CBC mode (PKCS5 padding)\n"),
		(uint32_t) plaintext_len, gcry_cipher_algo_name(cipher_algo));*/

	*output = output_buffer;

	return 0;
}

static int decrypt_aes_cbc(signal_buffer** output,
	const uint8_t* key,
	size_t key_len,
	const uint8_t* iv,
	size_t iv_len,
	const uint8_t* ciphertext,
	size_t ciphertext_len)
{
	int cipher_mode = GCRY_CIPHER_MODE_CBC;
	int cipher_algo;
	gcry_cipher_hd_t handle;
	uint8_t* buffer = NULL;
	size_t plaintext_unpadded_len;
	gcry_error_t err = GPG_ERR_NO_ERROR;
	signal_buffer* output_buffer = NULL;
	size_t padding_len = 0;

	switch (key_len) {
		case 16:
			cipher_algo = GCRY_CIPHER_AES128;
			break;
		case 24:
			cipher_algo = GCRY_CIPHER_AES192;
			break;
		case 32:
			cipher_algo = GCRY_CIPHER_AES256;
			break;
		default:
			purple_debug_error(PLUGIN_ID, "Invalid AES key length (%u)\n", (uint32_t) key_len);
			return SG_ERR_UNKNOWN;
	}

	err = gcry_cipher_open(&handle, cipher_algo, cipher_mode, 0);
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		return SG_ERR_UNKNOWN;
	}

	err = gcry_cipher_setkey(handle, key, key_len);
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		gcry_cipher_close(handle);
		return SG_ERR_UNKNOWN;
	}

	err = gcry_cipher_setiv(handle, iv, iv_len);
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		gcry_cipher_close(handle);
		return SG_ERR_UNKNOWN;
	}

	buffer = malloc(ciphertext_len);
	if (!buffer) {
		gcry_cipher_close(handle);
		return SG_ERR_NOMEM;
	}

	err = gcry_cipher_decrypt(handle, buffer, ciphertext_len, ciphertext, ciphertext_len);
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		gcry_cipher_close(handle);
		free(buffer);
		return SG_ERR_UNKNOWN;
	}

	// Unpadding
	padding_len = buffer[ciphertext_len-1];
	plaintext_unpadded_len = ciphertext_len - padding_len;

	output_buffer = signal_buffer_create(buffer, plaintext_unpadded_len);
	if (!output_buffer) {
		gcry_cipher_close(handle);
		free(buffer);
		return SG_ERR_NOMEM;
	}

	gcry_cipher_close(handle);
	free(buffer);

	/*purple_debug_misc(PLUGIN_ID, _("Decrypted %u bytes with %s in CBC mode (PKCS5 padding)\n"),
		(uint32_t) plaintext_unpadded_len, gcry_cipher_algo_name(cipher_algo));*/

	*output = output_buffer;

	return 0;
}

static int encdec_aes_ctr(signal_buffer** output,
	const uint8_t* key,
	size_t key_len,
	const uint8_t* ic,
	size_t ic_len,
	const uint8_t* text,
	size_t text_len,
	int encrypt)
{
	int cipher_mode = GCRY_CIPHER_MODE_CTR;
	int cipher_algo;
	gcry_cipher_hd_t handle;
	uint8_t* buffer = NULL;
	gcry_error_t err = GPG_ERR_NO_ERROR;
	signal_buffer* output_buffer = NULL;

	switch (key_len) {
		case 16:
			cipher_algo = GCRY_CIPHER_AES128;
			break;
		case 24:
			cipher_algo = GCRY_CIPHER_AES192;
			break;
		case 32:
			cipher_algo = GCRY_CIPHER_AES256;
			break;
		default:
			purple_debug_error(PLUGIN_ID, "Invalid AES key length (%u)\n", (uint32_t) key_len);
			return SG_ERR_UNKNOWN;
	}

	err = gcry_cipher_open(&handle, cipher_algo, cipher_mode, 0);
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		return SG_ERR_UNKNOWN;
	}

	err = gcry_cipher_setkey(handle, key, key_len);
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		gcry_cipher_close(handle);
		return SG_ERR_UNKNOWN;
	}

	err = gcry_cipher_setctr(handle, ic, ic_len);
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		gcry_cipher_close(handle);
		return SG_ERR_UNKNOWN;
	}

	buffer = malloc(text_len);
	if (!buffer) {
		gcry_cipher_close(handle);
		return SG_ERR_NOMEM;
	}

	
	if (encrypt) {
		err = gcry_cipher_encrypt(handle, buffer, text_len, text, text_len);
	} else {
		err = gcry_cipher_decrypt(handle, buffer, text_len, text, text_len);
	}
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		gcry_cipher_close(handle);
		free(buffer);
		return SG_ERR_UNKNOWN;
	}

	output_buffer = signal_buffer_create(buffer, text_len);
	if (!output_buffer) {
		gcry_cipher_close(handle);
		free(buffer);
		return SG_ERR_NOMEM;
	}

	gcry_cipher_close(handle);
	free(buffer);

	/*purple_debug_misc(PLUGIN_ID, _("%s %u bytes with %s in CTR mode (no padding)\n"),
		encrypt ? "Encrypted" : "Decrypted", (uint32_t) text_len,
		gcry_cipher_algo_name(cipher_algo));*/

	*output = output_buffer;

	return 0;
}

int encrypt(signal_buffer** output,
	int cipher,
	const uint8_t* key,
	size_t key_len,
	const uint8_t* iv,
	size_t iv_len,
	const uint8_t* plaintext,
	size_t plaintext_len,
	void* user_data)
{
	if (cipher == SG_CIPHER_AES_CTR_NOPADDING) {
		return encdec_aes_ctr(output, key, key_len, iv, iv_len, plaintext, plaintext_len, 1);
	}
	else if (cipher == SG_CIPHER_AES_CBC_PKCS5) {
		return encrypt_aes_cbc(output, key, key_len, iv, iv_len, plaintext, plaintext_len);
	}
	else {
		purple_debug_error(PLUGIN_ID, "Unknown cipher mode\n");
		return SG_ERR_UNKNOWN;
	}
}

int decrypt(signal_buffer** output,
	int cipher,
	const uint8_t* key,
	size_t key_len,
	const uint8_t* iv,
	size_t iv_len,
	const uint8_t* ciphertext,
	size_t ciphertext_len,
	void* user_data)
{
	if (cipher == SG_CIPHER_AES_CTR_NOPADDING) {
		return encdec_aes_ctr(output, key, key_len, iv, iv_len, ciphertext, ciphertext_len, 0);
	}
	else if (cipher == SG_CIPHER_AES_CBC_PKCS5) {
		return decrypt_aes_cbc(output, key, key_len, iv, iv_len, ciphertext, ciphertext_len);
	}
	else {
		purple_debug_error(PLUGIN_ID, "Unknown cipher mode\n");
		return SG_ERR_UNKNOWN;
	}
}

int decrypt_aes128_gcm(guint8** plaintext,
	gsize* plaintext_len,
	const guint8* key,
	gsize key_len,
	const guint8* iv,
	gsize iv_len,
	const guint8* tag,
	gsize tag_len,
	const guint8* ciphertext,
	gsize ciphertext_len)
{
	gcry_error_t err = 0;
	gcry_cipher_hd_t handle;
	guint8* plaint = NULL;
	gsize plaint_len = 0;

	err = gcry_cipher_open(&handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
	if (err) {
		goto cleanup;
	}

	err = gcry_cipher_setkey(handle, key, key_len);
	if (err) {
		goto cleanup;
	}

	err = gcry_cipher_setiv(handle, iv, iv_len);
	if (err) {
		goto cleanup;
	}

	plaint_len = ciphertext_len;
	plaint = g_malloc(plaint_len * sizeof(*plaint));
	err = gcry_cipher_decrypt(handle, plaint, plaint_len, ciphertext, ciphertext_len);
	if (err) {
		goto cleanup;
	}

	err = gcry_cipher_checktag(handle, tag, tag_len);
	if (err) {
		goto cleanup;
	}

	gcry_cipher_close(handle);

	*plaintext = plaint;
	*plaintext_len = plaint_len;

cleanup:
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		if (plaint) g_free(plaint);
		return -1;
	}

	return 0;
}

int encrypt_aes128_gcm(guint8** ciphertext,
	gsize* ciphertext_len,
	guint8** tag,
	gsize* tag_len,
	const guint8* key,
	gsize key_len,
	const guint8* iv,
	gsize iv_len,
	const guint8* plaintext,
	gsize plaintext_len)
{
	gcry_error_t err = 0;
	gcry_cipher_hd_t handle;
	guint8* ciphert = NULL;
	guint8* tg = NULL;
	gsize ciphert_len = 0;
	const gsize tg_len = 16;

	err = gcry_cipher_open(&handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
	if (err) {
		goto cleanup;
	}

	err = gcry_cipher_setkey(handle, key, key_len);
	if (err) {
		goto cleanup;
	}

	err = gcry_cipher_setiv(handle, iv, iv_len);
	if (err) {
		goto cleanup;
	}

	ciphert_len = plaintext_len;
	ciphert = g_malloc(ciphert_len * sizeof(*ciphert));
	err = gcry_cipher_encrypt(handle, ciphert, ciphert_len, plaintext, plaintext_len);
	if (err) {
		goto cleanup;
	}

	tg = g_malloc(tg_len * sizeof(*tg));
	err = gcry_cipher_gettag(handle, tg, tg_len);
	if (err) {
		goto cleanup;
	}

	gcry_cipher_close(handle);

	*ciphertext = ciphert;
	*ciphertext_len = ciphert_len;
	*tag = tg;
	*tag_len = tg_len;

cleanup:
	if (err) {
		purple_debug_error(PLUGIN_ID, "%s: %s\n", gcry_strsource(err), gcry_strerror(err));
		if (ciphert) g_free(ciphert);
		if (tg) g_free(tg);
		return -1;
	}

	return 0;
}
