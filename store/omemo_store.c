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
#include "../types/omemo_device.h"

#include "omemo_store.h"

int store_local_identity_key_pair(uint32_t device_id,
	ratchet_identity_key_pair* identity_key_pair,
	sqlite3* db)
{
	sqlite3_stmt* stmt = NULL;
	ec_private_key* private_key = NULL;
	ec_public_key* public_key = NULL;
	signal_buffer* private_key_buffer = NULL;
	signal_buffer* public_key_buffer = NULL;
	int step = SQLITE_DONE;
	int err = SQLITE_OK;
	int retval = 0;

	void private_key_blob_destroy()
	{
		signal_buffer_bzero_free(private_key_buffer);
	}

	void public_key_blob_destroy()
	{
		signal_buffer_free(public_key_buffer);
	}

	const char* sql = \
		"INSERT INTO own_device(id, public_key, private_key) "
			"VALUES(?, ?, ?);";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, device_id);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	public_key = ratchet_identity_key_pair_get_public(identity_key_pair);
	if (retval = ec_public_key_serialize(&public_key_buffer, public_key)) {
		purple_debug_error(PLUGIN_ID, _("Key serialization failed\n"));
		goto cleanup;
	}
	err = sqlite3_bind_blob(stmt, 2, signal_buffer_data(public_key_buffer), signal_buffer_len(public_key_buffer), public_key_blob_destroy);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	private_key = ratchet_identity_key_pair_get_private(identity_key_pair);
	if (retval = ec_private_key_serialize(&private_key_buffer, private_key)) {
		purple_debug_error(PLUGIN_ID, _("Key serialization failed\n"));
		goto cleanup;
	}
	err = sqlite3_bind_blob(stmt, 3, signal_buffer_data(private_key_buffer), signal_buffer_len(private_key_buffer), private_key_blob_destroy);
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
	return retval;
}

int add_contact(gchar* jid, sqlite3* db) {
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_DONE;
	int err = SQLITE_OK;
	int retval = 0;

	const char* sql = \
		"INSERT INTO contacts (jid) VALUES(?);";

	if (contact_exists(jid, db)) {
		goto cleanup;
	}

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 1, jid, -1, SQLITE_STATIC);
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

	purple_debug_misc(PLUGIN_ID, _("%s added to contacts\n"), jid);

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return -1;
	}
	return retval;
}

int add_device_tuple(gchar* jid, guint32 id, sqlite3* db)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_DONE;
	int err = 0;
	int retval = 0;

	const char* sql = \
		"INSERT INTO devices (id, contact_id) "
			"SELECT ?, contacts.id FROM contacts "
			"WHERE contacts.jid = ?;";

	err = add_contact(jid, db);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot add %s to contacts\n"), jid);
		retval = err;
		goto cleanup;
	}

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, id);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 2, jid, -1, SQLITE_STATIC);
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

	purple_debug_info(PLUGIN_ID, _("New device tuple (%s, %u) added\n"), jid, id);

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return -1;
	}
	return retval;
}

gboolean encryption_is_enabled(const gchar* jid, sqlite3* db) {
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	gboolean found = FALSE;
	gchar* bare_jid = NULL;

	const char* sql = \
		"SELECT encryption FROM contacts WHERE jid = ?;";

	bare_jid = jabber_get_bare_jid(jid);

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 1, bare_jid, -1, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW && step != SQLITE_DONE) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 unexpected result: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	if (step == SQLITE_ROW) {
		found = sqlite3_column_int(stmt, 0);
		/*purple_debug_misc(PLUGIN_ID, _("Encryption with %s is %s\n"), jid,
			found ? _("enabled") : _("disabled"));*/
	}
	else {
		purple_debug_misc(PLUGIN_ID, _("Contact %s not found. Considering encryption disabled\n"),
			jid);
	}

cleanup:
	if (bare_jid) g_free(bare_jid);
	if (stmt) sqlite3_finalize(stmt);

	return found;
}

gboolean contact_exists(gchar* jid, sqlite3* db)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	int found = FALSE;

	const char* sql = \
		"SELECT id FROM contacts WHERE jid = ?;";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 1, jid, -1, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW) {
		purple_debug_misc(PLUGIN_ID, _("%s not found in contacts\n"), jid);
		goto cleanup;
	}

	found = TRUE;

cleanup:
	if (stmt) sqlite3_finalize(stmt);

	return found;
}

gboolean device_tuple_exists(gchar* jid, guint32 id, sqlite3* db)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	int found = FALSE;

	const char* sql = \
		"SELECT id FROM devices WHERE id = ? AND contact_id IN ("
			"SELECT id FROM contacts "
			"WHERE jid = ?);";

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

	err = sqlite3_bind_text(stmt, 2, jid, -1, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW) {
		purple_debug_misc(PLUGIN_ID, _("Device tuple (%s, %u) not found\n"), jid, id);
		goto cleanup;
	}

	found = TRUE;

cleanup:
	if (stmt) sqlite3_finalize(stmt);

	return found;
}

int set_device_public_key(gchar* jid, guint32 id, guint8* key, gsize key_len, sqlite3* db)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_DONE;
	int err = SQLITE_OK;
	int retval = 0;

	const char* sql = \
		"UPDATE devices SET public_key = ? "
		"WHERE devices.id = ? AND devices.contact_id IN ("
			"SELECT id FROM contacts "
			"WHERE jid = ?);";
			
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_blob(stmt, 1, key, key_len, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 2, id);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 3, jid, -1, SQLITE_STATIC);
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

static int set_device_status(gchar* jid, guint32 id, device_status status, sqlite3* db)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_DONE;
	int err = SQLITE_OK;
	int retval = 0;

	const char* sql = \
		"UPDATE devices SET status = ? "
		"WHERE devices.id = ? AND devices.contact_id IN ("
			"SELECT id FROM contacts "
			"WHERE jid = ?);";
			
	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, status);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 2, id);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 3, jid, -1, SQLITE_STATIC);
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

	purple_debug_misc(PLUGIN_ID, _("Device (%s, %u) %s\n"), jid, id,
		status == ACTIVE ? _("activated") : _("deactivated"));

cleanup:
	if (stmt) sqlite3_finalize(stmt);
	if (retval) {
		return -1;
	}
	return retval;
}

int activate_device(gchar* jid, guint32 id, sqlite3* db)
{
	return set_device_status(jid, id, ACTIVE, db);
}

int deactivate_device(gchar* jid, guint32 id, sqlite3* db)
{
	return set_device_status(jid, id, INACTIVE, db);
}

GList* get_undecided_devices(gchar* jid, signal_context* global_context, sqlite3* db)
{
	GList* result = NULL;
	sqlite3_stmt* stmt = NULL;
	int err = SQLITE_OK;
	omemo_device* device = NULL;

	const char* sql = \
		"SELECT id, public_key, session FROM devices WHERE status = ? AND trust = ? AND "
			"contact_id IN ("
				"SELECT id FROM contacts "
				"WHERE jid = ?);";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, ACTIVE);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 2, UNDECIDED);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 3, jid, -1, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		err = omemo_device_create(&device,
			sqlite3_column_int(stmt, 0),
			jid,
			sqlite3_column_blob(stmt, 1),
			sqlite3_column_bytes(stmt, 1),
			sqlite3_column_blob(stmt, 2),
			sqlite3_column_bytes(stmt, 2),
			UNDECIDED,
			ACTIVE,
			global_context);
		if (err) {
			purple_debug_error(PLUGIN_ID, _("Cannot create device\n"));
			goto cleanup;
		}
		result = g_list_prepend(result, device);
		device = NULL;
	}

cleanup:
	if (stmt) sqlite3_finalize(stmt);

	if (err) {
		if (result) g_list_free_full(result, omemo_device_free);
		return NULL;
	}

	return result;
}

GList* get_devices_without_sessions(gchar* jid, signal_context* global_context, sqlite3* db)
{
	GList* result = NULL;
	sqlite3_stmt* stmt = NULL;
	int err = SQLITE_OK;
	omemo_device* device = NULL;

	const char* sql = \
		"SELECT id, public_key, trust FROM devices WHERE status = ? AND session IS NULL AND "
			"contact_id IN ("
				"SELECT id FROM contacts "
				"WHERE jid = ?);";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, ACTIVE);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 2, jid, -1, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		err = omemo_device_create(&device,
			sqlite3_column_int(stmt, 0),
			jid,
			sqlite3_column_blob(stmt, 1),
			sqlite3_column_bytes(stmt, 1),
			NULL,
			0,
			sqlite3_column_int(stmt, 2),
			ACTIVE,
			global_context);
		if (err) {
			purple_debug_error(PLUGIN_ID, _("Cannot create device\n"));
			goto cleanup;
		}
		result = g_list_prepend(result, device);
		device = NULL;
	}

cleanup:
	if (stmt) sqlite3_finalize(stmt);

	if (err) {
		if (result) g_list_free_full(result, omemo_device_free);
		return NULL;
	}

	return result;
}

GList* get_devices_ready_to_receive(gchar* jid, signal_context* global_context, sqlite3* db)
{
	GList* result = NULL;
	sqlite3_stmt* stmt = NULL;
	int err = SQLITE_OK;
	omemo_device* device = NULL;

	const char* sql = \
		"SELECT id, public_key, session FROM devices WHERE status = ? AND trust = ? AND "
			"session IS NOT NULL AND "
			"contact_id IN ("
				"SELECT id FROM contacts "
				"WHERE jid = ?);";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, ACTIVE);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 2, TRUSTED);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 3, jid, -1, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		err = omemo_device_create(&device,
			sqlite3_column_int(stmt, 0),
			jid,
			sqlite3_column_blob(stmt, 1),
			sqlite3_column_bytes(stmt, 1),
			sqlite3_column_blob(stmt, 2),
			sqlite3_column_bytes(stmt, 2),
			TRUSTED,
			ACTIVE,
			global_context);
		if (err) {
			purple_debug_error(PLUGIN_ID, _("Cannot create device\n"));
			goto cleanup;
		}
		result = g_list_prepend(result, device);
		device = NULL;
	}

cleanup:
	if (stmt) sqlite3_finalize(stmt);

	if (err) {
		if (result) g_list_free_full(result, omemo_device_free);
		return NULL;
	}

	return result;
}

GList* get_all_devices_for_contact(gchar* jid, signal_context* global_context, sqlite3* db) {
		GList* result = NULL;
	sqlite3_stmt* stmt = NULL;
	int err = SQLITE_OK;
	omemo_device* device = NULL;

	const char* sql = \
		"SELECT id, public_key, session, trust, status FROM devices WHERE contact_id IN ("
			"SELECT id FROM contacts "
			"WHERE jid = ?);";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_text(stmt, 1, jid, -1, SQLITE_STATIC);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		err = omemo_device_create(&device,
			sqlite3_column_int(stmt, 0),
			jid,
			sqlite3_column_blob(stmt, 1),
			sqlite3_column_bytes(stmt, 1),
			sqlite3_column_blob(stmt, 2),
			sqlite3_column_bytes(stmt, 2),
			sqlite3_column_int(stmt, 3),
			sqlite3_column_int(stmt, 4),
			global_context);
		if (err) {
			purple_debug_error(PLUGIN_ID, _("Cannot create device\n"));
			goto cleanup;
		}
		result = g_list_prepend(result, device);
		device = NULL;
	}

cleanup:
	if (stmt) sqlite3_finalize(stmt);

	if (err) {
		if (result) g_list_free_full(result, omemo_device_free);
		return NULL;
	}

	return result;
}

gboolean is_own_device_published(sqlite3* db)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	gboolean published = TRUE;

	const char* sql = "SELECT published FROM own_device;";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW) {
		purple_debug_error(PLUGIN_ID, _("Local device not found in DB\n"));
		goto cleanup;
	}

	published = sqlite3_column_int(stmt, 0);

cleanup:
	if (stmt) sqlite3_finalize(stmt);

	return published;
}

int set_own_device_published(gboolean published, sqlite3* db)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_DONE;
	int err = SQLITE_OK;

	const char* sql = "UPDATE own_device SET published = ?;";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	err = sqlite3_bind_int(stmt, 1, published ? 1 : 0);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQLite3 error: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_DONE) {
		purple_debug_error(PLUGIN_ID, _("Cannot set publish status of local device\n"));
		goto cleanup;
	}

	purple_debug_info(PLUGIN_ID, _("Local device marked as %spublished\n"), published ? "" : "un");

cleanup:
	if (stmt) sqlite3_finalize(stmt);

	return err == SQLITE_OK && step == SQLITE_DONE;
}

int get_db_version(sqlite3* db)
{
	sqlite3_stmt* stmt = NULL;
	int step = SQLITE_ROW;
	int err = SQLITE_OK;
	int pragma = -1;

	const char* sql = "PRAGMA user_version;";

	err = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot prepare SQL statement: %s\n"), sqlite3_errmsg(db));
		goto cleanup;
	}

	step = sqlite3_step(stmt);
	if (step != SQLITE_ROW) {
		purple_debug_error(PLUGIN_ID, _("user-version pragma not found\n"));
		goto cleanup;
	}

	pragma = sqlite3_column_int(stmt, 0);

cleanup:
	if (stmt) sqlite3_finalize(stmt);

	return pragma;
}
