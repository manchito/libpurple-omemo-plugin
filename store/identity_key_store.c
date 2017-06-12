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

#include "../omemo.h"

#include "identity_key_store.h"

int get_identity_key_pair(signal_buffer** public_data,
	signal_buffer** private_data,
	void* user_data)
{
	sqlite3_stmt* stmt = NULL;
	sqlite3* db = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	int retval = 0;
	signal_buffer* pub_data = NULL;
	signal_buffer* priv_data = NULL;

	const char* sql = "SELECT public_key, private_key FROM own_device;";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 unexpected result: %s\n"), sqlite3_errmsg(db));
		retval = step;
		goto cleanup;
	}

	pub_data = signal_buffer_create(sqlite3_column_blob(stmt, 0), sqlite3_column_bytes(stmt, 0));
	if (!pub_data) {
		purple_debug_error(PLUGIN_ID, _("Cannot allocate memory\n"));
		retval = SG_ERR_NOMEM;
		goto cleanup;
	}

	priv_data = signal_buffer_create(sqlite3_column_blob(stmt, 1), sqlite3_column_bytes(stmt, 1));
	if (!priv_data) {
		purple_debug_error(PLUGIN_ID, _("Cannot allocate memory\n"));
		retval = SG_ERR_NOMEM;
		goto cleanup;
	}

	*public_data = pub_data;
	*private_data = priv_data;

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval == SG_ERR_NOMEM) {
		if (pub_data) signal_buffer_free(pub_data);
		if (priv_data) signal_buffer_bzero_free(priv_data);
	}
	if (retval) {
		return -1;
	}
	return retval;
}

int get_local_registration_id(void* user_data, uint32_t* device_id)
{
	sqlite3_stmt* stmt = NULL;
	sqlite3* db = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	int retval = 0;

	const char* sql = "SELECT id FROM own_device;";

	db = (sqlite3*) user_data;
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 unexpected result: %s\n"), sqlite3_errmsg(db));
		retval = step;
		goto cleanup;
	}
	
	*device_id = sqlite3_column_int(stmt, 0);

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return -1;
	}
	return retval;
}

gboolean identity_exists(const char* name,
	size_t name_len,
	uint8_t* key_data,
	size_t key_len,
	sqlite3* db)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	int retval = 0;
	int found = 0;

	const char* sql = \
		"SELECT devices.id FROM contacts, devices WHERE contacts.id = devices.contact_id AND "
			"contacts.jid = ? AND devices.public_key = ?;";

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

	err = sqlite3_bind_blob(stmt, 2, key_data, key_len, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW && step != SQLITE_DONE) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 unexpected result: %s\n"), sqlite3_errmsg(db));
		retval = step;
		goto cleanup;
	}

	found = step == SQLITE_ROW;

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return -1;
	}
	return found;
}

int save_identity(const char* name,
	size_t name_len,
	uint8_t* key_data,
	size_t key_len,
	void* user_data)
{
	// Deactivate internal identity creation. This is left to the OMEMO device management
	int retval = 0;
	purple_debug_misc(PLUGIN_ID, _("Make Signal think it did a successfull save_identity()\n"));
	/*sqlite3_stmt* stmt = NULL;
	int step = SQLITE_DONE;
	int err = SQLITE_OK;
	sqlite3* db = NULL;

	const char* sql = \
		"INSERT INTO devices (recipient_id, public_key, trust) "
			"VALUES(?, ?, ?);";

	db = (sqlite3*) user_data;
	if (identity_exists(name, name_len, key_data, key_len, db)) {
		goto cleanup;
	}

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

	err = sqlite3_bind_blob(stmt, 2, key_data, key_len, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 3, UNDECIDED);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_DONE) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = step;
	}

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return -1;
	}*/
	return retval;
}

int is_trusted_identity(const char* name,
	size_t name_len,
	uint8_t* key_data,
	size_t key_len,
	void* user_data)
{
	// Let Signal treat all identities internally as trusted. Trust management is left to OMEMO
	purple_debug_misc(PLUGIN_ID, _("Make Signal think that identity is trusted\n"));
	return 1;
	/*sqlite3_stmt* stmt = NULL;
	sqlite3* db = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	int retval = 0;
	int found = 0;

	const char* sql = \
		"SELECT trust FROM devices WHERE recipient_id = ? AND public_key = ?;";

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

	err = sqlite3_bind_blob(stmt, 2, key_data, key_len, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW && step != SQLITE_DONE) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 unexpected result: %s\n"), sqlite3_errmsg(db));
		retval = step;
		goto cleanup;
	}

	if (step == SQLITE_ROW) {
		found = sqlite3_column_int(stmt, 0) == TRUSTED;
	}

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return -1;
	}
	return found;*/
}

void identity_key_store_destroy(void* user_data)
{
}
