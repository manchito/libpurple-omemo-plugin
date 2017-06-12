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
#ifndef SIGNED_PRE_KEY_STORE_H
#define SIGNED_PRE_KEY_STORE_H

#include <signal_protocol.h>

int load_signed_pre_key(signal_buffer** record, uint32_t signed_pre_key_id, void* user_data);

int store_signed_pre_key(uint32_t signed_pre_key_id,
	uint8_t* record,
	size_t record_len,
	void* user_data);

int contains_signed_pre_key(uint32_t signed_pre_key_id, void* user_data);

int remove_signed_pre_key(uint32_t signed_pre_key_id, void* user_data);

/**
 * @brief Get the most recent signed prekey id
 * @param db a valid SQLite3 database handle
 * 
 * @return the id in [1,UINT32_MAX], 0 on error or when the local store is empty
 */
uint32_t get_current_signed_pre_key_id(sqlite3* db);

/**
 * @brief Get the age of the current signed prekey
 * @param db a valid SQLite3 database handle
 * 
 * @return the time elapsed since the generation of the current signed prekey in days
 */
uint32_t get_current_signed_pre_key_age(sqlite3* db);

/**
 * @brief Get the id to be assigned to a new signed prekey
 * @param db a valid SQLite3 database handle
 * 
 * @return an id between 1 and UINT32_MAX
 */
uint32_t get_next_signed_pre_key_id(sqlite3* db);

/**
 * @brief Removes old signed prekeys from storage
 * @param db a valid SQLite3 database handle
 * @param days the number of days after which a signed prekey is considered old
 * 
 * @return 0 on success
 */
int remove_signed_pre_keys_older_than(sqlite3* db, uint32_t days);

void signed_pre_key_store_destroy(void* user_data);

#endif
