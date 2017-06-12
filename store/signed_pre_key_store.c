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
#include <glib.h>
#include <sqlite3.h>

#include "../omemo.h"

#include "signed_pre_key_store.h"

int load_signed_pre_key(signal_buffer** record, uint32_t signed_pre_key_id, void* user_data)
{
	sqlite3_stmt* stmt = NULL;
	sqlite3* db = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	int retval = 0;
	signal_buffer* rec = NULL;

	const char* sql = \
		"SELECT key_pair FROM signed_prekeys WHERE id = ?;";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, signed_pre_key_id);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW) {
		purple_debug_warning(PLUGIN_ID, _("Signed prekey %u not found\n"), signed_pre_key_id);
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

int store_signed_pre_key(uint32_t signed_pre_key_id,
	uint8_t* record,
	size_t record_len,
	void* user_data)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_DONE;
	int err = SQLITE_OK;
	int retval = 0;
	sqlite3* db = NULL;

	const char* sql = \
		"INSERT INTO signed_prekeys (id, key_pair) VALUES(?,?);";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, signed_pre_key_id);
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

int contains_signed_pre_key(uint32_t signed_pre_key_id, void* user_data)
{
	sqlite3_stmt* stmt = NULL;
	sqlite3* db = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	int retval = 0;

	const char* sql = \
		"SELECT key_pair FROM signed_prekeys WHERE id = ?;";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, signed_pre_key_id);
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

int remove_signed_pre_key(uint32_t signed_pre_key_id, void* user_data)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_DONE;
	int err = SQLITE_OK;
	int retval = 0;
	sqlite3* db = NULL;

	const char* sql = \
		"DELETE FROM signed_prekeys WHERE id = ?;";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, signed_pre_key_id);
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

uint32_t get_current_signed_pre_key_id(sqlite3* db)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	uint32_t id = 0;

	const char* sql = \
		"SELECT id FROM signed_prekeys ORDER BY timestamp DESC;";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW) {
		purple_debug_warning(PLUGIN_ID, _("Cannot find most recent signed prekey: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	id = sqlite3_column_int(stmt, 0);

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	return id;
}

uint32_t get_current_signed_pre_key_age(sqlite3* db)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	uint32_t age = 0;

	const char* sql = \
		"SELECT julianday('now') - julianday(timestamp) FROM signed_prekeys "
			"ORDER BY timestamp DESC;";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW) {
		purple_debug_warning(PLUGIN_ID, _("Cannot find most recent signed prekey: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	age = sqlite3_column_int(stmt, 0);

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	return age;
}

uint32_t get_next_signed_pre_key_id(sqlite3* db)
{
	uint32_t id = get_current_signed_pre_key_id(db);
	if (!id) {
		return g_random_int() % INT32_MAX;
	}

	if (id == INT32_MAX) {
		return 1;
	}
	else {
		return ++id;
	}
}

int remove_signed_pre_keys_older_than(sqlite3* db, uint32_t days)
{
	sqlite3_stmt* stmt = NULL;
	gchar* str = NULL;
	int step = SQLITE_DONE;
	int err = SQLITE_OK;
	int retval = 0;

	const char* sql = \
		"DELETE FROM signed_prekeys WHERE timestamp < DATETIME('now', ?);";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	str = g_strdup_printf("-%u days", days);
	err = sqlite3_bind_text(stmt, 1, str, -1, SQLITE_TRANSIENT);
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
	if (str) g_free(str);
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return -1;
	}
	return retval;
}

void signed_pre_key_store_destroy(void* user_data)
{
}
