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
#ifndef PRE_KEY_STORE_H
#define PRE_KEY_STORE_H

#include <glib.h>
#include <signal_protocol.h>

int load_pre_key(signal_buffer** record, uint32_t pre_key_id, void* user_data);

/**
 * @brief Get all pre keys in local storage
 * @param prekeys a list if (session_pre_key*) to be allocated and filled with the pre keys.
 * It's up to the caller to free it with g_list_free_full() when it's not needed anymore
 * @param db a valid SQLite3 database handle
 * @param global_context the Signal global context
 * 
 * @return the number of pre keys added to prekeys. Negative on failure
 */
int load_pre_keys(GList** prekeys, sqlite3* db, signal_context* global_context);

/**
 * @brief Stores a pre key in the Database
 * @param pre_key_id
 * @param record
 * @param record_len
 * @param user_data a valid SQLite3 database handle
 * 
 * See Signal documentation for details
 */
int store_pre_key(uint32_t pre_key_id, uint8_t* record, size_t record_len, void* user_data);

int contains_pre_key(uint32_t pre_key_id, void* user_data);

int remove_pre_key(uint32_t pre_key_id, void* user_data);

/**
 * @brief Gets the number of prekeys in local storage
 * @param db a valid SQLite3 database handle
 * 
 * @return the number of prekeys in local storage
 */
uint32_t get_pre_key_count(sqlite3* db);

/**
 * @brief Get the last id used for a prekey
 * @param db a valid SQLite3 database handle
 * 
 * @return an id between 1 and UINT16_MAX
 */
uint32_t get_last_pre_key_id(sqlite3* db);

/**
 * @brief Stores the last used id for prekeys
 * @param id the las used id
 * @param db a valid SQLite3 database handle
 */
void set_last_pre_key_id(uint32_t id, sqlite3* db);

void pre_key_store_destroy(void* user_data);

#endif
