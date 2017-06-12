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
#ifndef IDENTITY_KEY_STORE_H
#define IDENTITY_KEY_STORE_H

#include <glib.h>
#include <signal_protocol.h>
#include <sqlite3.h>

int get_identity_key_pair(signal_buffer** public_data,
	signal_buffer** private_data,
	void* user_data);

int get_local_registration_id(void* user_data, uint32_t* registration_id);

/**
 * @brief Check whether an identity is saved on local storage
 * @param name the Jabber ID to look for
 * @param name_len size of the Jabber ID
 * @param key_data the public key to look for
 * @param key_len size of the public key
 * @param db a valid SQLite3 Db handle
 * @return TRUE if found. FALSE otherwise
 */
gboolean identity_exists(const char* name,
	size_t name_len,
	uint8_t* key_data,
	size_t key_len,
	sqlite3* db);

int save_identity(const char* name,
	size_t name_len,
	uint8_t* key_data,
	size_t key_len,
	void* user_data);

/**
 * @brief Verify a remote client's identity key
 * 
 * Unlike the TextSecure protocol. This implementation considers a key 'trusted' only if it is
 * explicitly marked as such in the local store. That means no 'trust on first use'.
 * 
 * @param user_data pointer to a valid SQLite3 DB handle
 * @return 1 if trusted, 0 if untrusted, negative on failure
 */
int is_trusted_identity(const char* name,
	size_t name_len,
	uint8_t* key_data,
	size_t key_len,
	void* user_data);

void identity_key_store_destroy(void* user_data);

#endif
