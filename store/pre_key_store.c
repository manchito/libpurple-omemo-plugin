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
#include <sqlite3.h>

#include "../omemo.h"

#include "pre_key_store.h"

int load_pre_key(signal_buffer** record, uint32_t pre_key_id, void* user_data)
{
	sqlite3_stmt* stmt = NULL;
	sqlite3* db = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	int retval = 0;
	signal_buffer* rec = NULL;

	const char* sql = \
		"SELECT key_pair FROM prekeys WHERE id = ?;";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, pre_key_id);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW) {
		purple_debug_warning(PLUGIN_ID, _("Prekey %u not found\n"), pre_key_id);
		retval = step;
		goto cleanup;
	}

	rec = signal_buffer_create(sqlite3_column_blob(stmt, 0), sqlite3_column_bytes(stmt, 0));
	if (!rec) {
		purple_debug_error(PLUGIN_ID, _("Cannot allocate memory\n"));
		retval = SG_ERR_NOMEM;
		goto cleanup;
	}

	*record = rec;

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return SG_ERR_INVALID_KEY_ID;
	}
	return SG_SUCCESS;
}

int load_pre_keys(GList** prekeys, sqlite3* db, signal_context* global_context)
{
	sqlite3_stmt* stmt = NULL;
	int err = SQLITE_OK;
	int retval = 0;
	GList* ret = NULL;
	session_pre_key* k = NULL;
	int len = 0;

	const char* sql = \
		"SELECT key_pair FROM prekeys;";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		session_pre_key_deserialize(&k, sqlite3_column_blob(stmt, 0),
			sqlite3_column_bytes(stmt, 0), global_context); 
		ret = g_list_prepend(ret, k);
		len++;
	}

	*prekeys = ret;

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return -1;
	}
	return len;
}

int store_pre_key(uint32_t pre_key_id, uint8_t* record, size_t record_len, void* user_data)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_DONE;
	int err = SQLITE_OK;
	int retval = 0;
	sqlite3* db = NULL;

	const char* sql = \
		"INSERT INTO prekeys (id, key_pair) VALUES (?,?);";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, pre_key_id);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_blob(stmt, 2, record, record_len, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_DONE) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = step;
		goto cleanup;
	}

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return -1;
	}
	return retval;
}

int contains_pre_key(uint32_t pre_key_id, void* user_data)
{
	sqlite3_stmt* stmt = NULL;
	sqlite3* db = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	int retval = 0;

	const char* sql = \
		"SELECT key_pair FROM prekeys WHERE id = ?;";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, pre_key_id);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW) {
		retval = step;
		goto cleanup;
	}

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return 0;
	}
	return 1;
}

int remove_pre_key(uint32_t pre_key_id, void* user_data)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_DONE;
	int err = SQLITE_OK;
	int retval = 0;
	sqlite3* db = NULL;

	const char* sql = \
		"DELETE FROM prekeys WHERE id = ?;";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, pre_key_id);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_DONE) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = step;
		goto cleanup;
	}

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return -1;
	}
	return retval;
}

uint32_t get_pre_key_count(sqlite3* db)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	uint32_t n = 0;

	const char* sql = \
		"SELECT COUNT(id) FROM prekeys;";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW) {
		purple_debug_error(PLUGIN_ID, _("Cannot get number of prekeys: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	n = sqlite3_column_int(stmt, 0);

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	return n;
}

uint32_t get_last_pre_key_id(sqlite3* db)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	uint32_t id = 0;

	const char* sql = \
		"SELECT last_pre_key FROM own_device;";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW) {
		purple_debug_error(PLUGIN_ID, _("Cannot find last prekey ID: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	id = sqlite3_column_int(stmt, 0);

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	return id;
}

void set_last_pre_key_id(uint32_t id, sqlite3* db)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_DONE;
	int err = SQLITE_OK;

	const char* sql = \
		"UPDATE own_device SET last_pre_key = ?;";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, id);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_DONE) {
		purple_debug_error(PLUGIN_ID, _("Cannot set last prekey ID: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

cleanup:
	if (stmt) sqlite3_finalize(stmt);
}

void pre_key_store_destroy(void* user_data)
{
}
