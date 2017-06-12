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

#include "session_store.h"

int load_session(signal_buffer** record, const signal_protocol_address* address, void* user_data)
{
	sqlite3_stmt* stmt = NULL;
	sqlite3* db = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	signal_buffer* rec = NULL;

	const char* sql = \
		"SELECT session FROM devices WHERE id = ? AND contact_id IN ("
			"SELECT id FROM contacts "
			"WHERE jid = ?);";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, address->device_id);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 2, address->name, address->name_len, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW) {
		purple_debug_warning(PLUGIN_ID, _("Session with %s (%u) not found\n"), address->name,
			address->device_id);
		goto cleanup;
	}

	rec = signal_buffer_create(sqlite3_column_blob(stmt, 0), sqlite3_column_bytes(stmt, 0));
	if (!rec) {
		purple_debug_error(PLUGIN_ID, _("Cannot allocate memory\n"));
		goto cleanup;
	}

	/*purple_debug_misc(PLUGIN_ID, _("Signal session %s (%u) loaded\n"), address->name,
		address->device_id);*/
	*record = rec;

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (err != SQLITE_OK) {
		return -1;
	}
	if (step != SQLITE_ROW) {
		return 0;
	}
	return 1;
}

int get_sub_device_sessions(signal_int_list** sessions,
	const char* name,
	size_t name_len,
	void* user_data)
{
	sqlite3_stmt* stmt = NULL;
	sqlite3* db = NULL;
	int err = SQLITE_OK;
	int retval = 0;
	signal_int_list* sess = NULL;

	const char* sql = \
		"SELECT id FROM devices "
		"WHERE session IS NOT NULL AND status = ? AND contact_id IN ("
			"SELECT id FROM contacts "
			"WHERE jid = ?);";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, ACTIVE);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 2, name, name_len, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	sess = signal_int_list_alloc();
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		signal_int_list_push_back(sess, sqlite3_column_int(stmt, 0));
	}

	purple_debug_misc(PLUGIN_ID, _("Signal sub-device sessions queried\n"));
	*sessions = sess;

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return -1;
	}
	return signal_int_list_size(*sessions);
}

int store_session(const signal_protocol_address* address,
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
		"UPDATE devices SET session = ? WHERE id = ? AND contact_id IN ("
			"SELECT id FROM contacts "
			"WHERE jid = ?);";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_blob(stmt, 1, record, record_len, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 2, address->device_id);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 3, address->name, address->name_len, SQLITE_STATIC);
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

	/*purple_debug_misc(PLUGIN_ID, _("Signal session %s (%u) stored\n"), address->name,
		address->device_id);*/

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return -1;
	}
	return retval;
}

int contains_session(const signal_protocol_address* address, void* user_data)
{
	sqlite3_stmt* stmt = NULL;
	sqlite3* db = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	int retval = 0;

	const char* sql = \
		"SELECT id FROM devices "
		"WHERE session IS NOT NULL AND status = ? AND id = ? AND contact_id IN ("
			"SELECT id FROM contacts "
			"WHERE jid = ?);";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, ACTIVE);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 2, address->device_id);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 3, address->name, address->name_len, SQLITE_STATIC);
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

	/*purple_debug_misc(PLUGIN_ID, _("contains_session(%s, %u): %s"), address->name,
		address->device_id, retval ? _("NO\n") : _("YES\n"));*/

	return !retval;
}

int delete_session(const signal_protocol_address* address, void* user_data)
{
	sqlite3_stmt* stmt = NULL;
	sqlite3* db = NULL;
	int step = SQLITE_DONE;
	int err = SQLITE_OK;
	int retval = 0;
	int found = 0;

	const char* sql = \
		"UPDATE devices SET session = NULL "
		"WHERE id = ? AND contact_id IN ("
			"SELECT id FROM contacts "
			"WHERE jid = ?);";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, address->device_id);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 2, address->name, address->name_len, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_DONE) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 unexpected result: %s\n"), sqlite3_errmsg(db));
		retval = step;
		goto cleanup;
	}

	found = sqlite3_changes(db);

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return -1;
	}
	return found;
}

int delete_all_sessions(const char* name, size_t name_len, void* user_data)
{
	sqlite3_stmt* stmt = NULL;
	sqlite3* db = NULL;
	int step = SQLITE_DONE;
	int err = SQLITE_OK;
	int retval = 0;
	int count = 0;

	const char* sql = \
		"UPDATE devices SET session = NULL "
		"WHERE contact_id IN ("
			"SELECT id FROM contacts "
			"WHERE jid = ?);";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 1, name, name_len, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_DONE) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 unexpected result: %s\n"), sqlite3_errmsg(db));
		retval = step;
		goto cleanup;
	}

	count = sqlite3_changes(db);

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return -1;
	}
	return count;
}

void session_store_destroy(void* user_data)
{
}
