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
#include "omemo.h" 

#include <debug.h>
#include <glib/gstdio.h>
#include <key_helper.h>
#include <notify.h>
#include <protocol.h>
#include <session_builder.h>
#include <session_cipher.h>
#include <version.h>

#include "crypto/provider.h"
#include "store/identity_key_store.h"
#include "store/omemo_store.h"
#include "store/pre_key_store.h"
#include "store/session_store.h"
#include "store/signed_pre_key_store.h"
#include "types/omemo_element.h"
#include "types/omemo_envelope.h"

PurplePlugin* omemo_plugin = NULL;
signal_context* global_context = NULL;
GRecMutex* signal_mutex = NULL;

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_STANDARD,
	NULL,
	0,
	NULL,
	PURPLE_PRIORITY_DEFAULT,
	PLUGIN_ID,
	N_ ("XMPP OMEMO Encryption"),
	"0.1.0a",
	N_ ("XMPP OMEMO Plugin"),
	N_ ("XMPP OMEMO End-to-End Encryption Plugin"),
	PLUGIN_AUTHOR,
	"https://git.imp.fu-berlin.de/mancho/libpurple-omemo-plugin",
	plugin_load,
	plugin_unload,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

static void init_plugin(PurplePlugin* plugin)
{
	plugin->info->dependencies = g_list_append(plugin->info->dependencies, "prpl-jabber");
}

PURPLE_INIT_PLUGIN(omemo, init_plugin, info)

static gboolean plugin_load(PurplePlugin* plugin)
{
	gboolean retval = TRUE;
	PurplePlugin* jabber_plugin = NULL;
	signal_crypto_provider provider = {
		.random_func = random_generator,
		.hmac_sha256_init_func = hmac_sha256_init,
		.hmac_sha256_update_func = hmac_sha256_update,
		.hmac_sha256_final_func = hmac_sha256_final,
		.hmac_sha256_cleanup_func = hmac_sha256_cleanup,
		.sha512_digest_func = sha512_digest,
		.encrypt_func = encrypt,
		.decrypt_func = decrypt,
		.user_data = NULL
	};
	GList* accounts = NULL;
	GList* i = NULL;
	PurpleAccount* a = NULL;

	// Test for XMPP
	jabber_plugin = purple_find_prpl(PROTO_XMPP);
	if (!jabber_plugin) {
		purple_debug_info(PLUGIN_ID, _("XMPP plugin (%s) not found\n"), PROTO_XMPP);
		retval = FALSE;
		goto cleanup;
	}

	omemo_plugin = plugin;

	// Init libsignal-protocol-c
	if (init_crypto_provider()) {
		purple_debug_error(PLUGIN_ID, _("Initialization of crypto-provider failed\n"));
		retval = FALSE;
		goto cleanup;
	}
	signal_context_create(&global_context, 0);
	signal_context_set_crypto_provider(global_context, &provider);
	signal_mutex = g_new(GRecMutex, 1);
	g_rec_mutex_init(signal_mutex);
	signal_context_set_locking_functions(global_context, signal_lock_func, signal_unlock_func);

	// Install on each XMPP Account if needed
	accounts = purple_accounts_get_all_active();
	for (i = accounts; i; i = i->next) {
		a = i->data;
		if (omemo_account_setup(a)) {
			purple_debug_error(PLUGIN_ID, _("Account setup failed (%s)\n"),
				purple_account_get_username(a));
			retval = FALSE;
			goto cleanup;
		}
	}

	// Signals
	purple_signal_connect(jabber_plugin, "jabber-sending-xmlnode", omemo_plugin,
		PURPLE_CALLBACK(stanza_sending_cb), NULL);
	purple_signal_connect(jabber_plugin, "jabber-receiving-message", omemo_plugin,
		PURPLE_CALLBACK(message_receiving_cb), NULL);
	purple_signal_connect(purple_accounts_get_handle(), "account-added", omemo_plugin,
		PURPLE_CALLBACK(account_added_cb), NULL);
	purple_signal_connect(purple_accounts_get_handle(), "account-enabled", omemo_plugin,
		PURPLE_CALLBACK(account_enabled_cb), NULL);
	purple_signal_connect(purple_accounts_get_handle(), "account-removed", omemo_plugin,
		PURPLE_CALLBACK(account_removed_cb), NULL);
	purple_signal_connect(purple_accounts_get_handle(), "account-disabled", omemo_plugin,
		PURPLE_CALLBACK(account_disabled_cb), NULL);
	purple_signal_connect(purple_accounts_get_handle(), "account-signed-on", omemo_plugin,
		PURPLE_CALLBACK(account_signed_on_cb), NULL);
	purple_signal_connect(purple_accounts_get_handle(), "account-authorization-granted", omemo_plugin,
		PURPLE_CALLBACK(account_authorization_granted_cb), NULL);
 
	jabber_pep_register_handler(OMEMO_DEVICELIST_NS, device_list_update_cb);
	subscribe_to_devicelist_updates();

	purple_debug_info(PLUGIN_ID, _("Plugin loaded\n"));

cleanup:
	if (accounts) g_list_free(accounts);
	if (!retval && global_context) {
		signal_context_destroy(global_context);
		global_context = NULL;
	}

	return retval;
}

static gboolean plugin_unload(PurplePlugin* plugin)
{
	jabber_remove_feature(OMEMO_FEATURE_VAR);
	purple_signals_disconnect_by_handle(omemo_plugin);

	g_rec_mutex_clear(signal_mutex);
	g_free(signal_mutex);
	signal_context_destroy(global_context);

	return TRUE;
}

static signal_protocol_store_context* signal_store_context_create(sqlite3* db)
{
	int err = 0;
	signal_protocol_store_context* store_context = NULL;

	signal_protocol_session_store session_store = {
		.load_session_func = load_session,
		.get_sub_device_sessions_func = get_sub_device_sessions,
		.store_session_func = store_session,
		.contains_session_func = contains_session,
		.delete_session_func = delete_session,
		.delete_all_sessions_func = delete_all_sessions,
		.destroy_func = session_store_destroy,
		.user_data = db
	};

	signal_protocol_pre_key_store pre_key_store = {
		.load_pre_key = load_pre_key,
		.store_pre_key = store_pre_key,
		.contains_pre_key = contains_pre_key,
		.remove_pre_key = remove_pre_key,
		.destroy_func = pre_key_store_destroy,
		.user_data = db
	};

	signal_protocol_signed_pre_key_store signed_pre_key_store = {
		.load_signed_pre_key = load_signed_pre_key,
		.store_signed_pre_key = store_signed_pre_key,
		.contains_signed_pre_key = contains_signed_pre_key,
		.remove_signed_pre_key = remove_signed_pre_key,
		.destroy_func = signed_pre_key_store_destroy,
		.user_data = db
	};

	signal_protocol_identity_key_store identity_key_store = {
		.get_identity_key_pair = get_identity_key_pair,
		.get_local_registration_id = get_local_registration_id,
		.save_identity = save_identity,
		.is_trusted_identity = is_trusted_identity,
		.destroy_func = identity_key_store_destroy,
		.user_data = db
	};

	err = signal_protocol_store_context_create(&store_context, global_context) ||
	signal_protocol_store_context_set_session_store(store_context, &session_store) ||
	signal_protocol_store_context_set_pre_key_store(store_context, &pre_key_store) ||
	signal_protocol_store_context_set_signed_pre_key_store(store_context, &signed_pre_key_store) ||
	signal_protocol_store_context_set_identity_key_store(store_context, &identity_key_store);

	if (err) {
		if (store_context) signal_protocol_store_context_destroy(store_context);
		return NULL;
	}

	return store_context;
}

int omemo_account_setup(PurpleAccount* a)
{
	int retval = 0;
	gchar* db_id = NULL;
	gchar* db_file = NULL;

	if (purple_strequal(purple_account_get_protocol_id(a), PROTO_XMPP)) {
		db_id = g_strdup(purple_account_get_string(a, SETTINGS_DB_ID, NULL));
		if (!db_id) {
			purple_debug_info(PLUGIN_ID, "No OMEMO DB found for account %s\n",
				purple_account_get_username(a));
			db_id = rand_string(DB_ID_LEN);
			retval = omemo_install(a, db_id);
		} else {
			db_file = get_db_path(db_id);
			if (!g_file_test(db_file, G_FILE_TEST_EXISTS)) {
				purple_debug_warning(PLUGIN_ID, "No OMEMO DB found for account %s and %s %s\n",
				purple_account_get_username(a), SETTINGS_DB_ID, db_id);
				retval = omemo_install(a, db_id);
			}
			g_free(db_file);

			retval = migrate_db(a);
		}
		if (db_id) {
			g_free(db_id);
			db_id = NULL;
		}
	}

	return retval;
}

int omemo_account_undo_announce(PurpleAccount* a)
{
	unpublish_device(a);
	unpublish_bundle(a);

	return 0;
}

int omemo_install(PurpleAccount* account, const gchar* db_id)
{
	ratchet_identity_key_pair* identity_key_pair = NULL;
	guint32 registration_id;
	signal_buffer* buffer = NULL;
	session_signed_pre_key* signed_pre_key = NULL;
	gchar* path = NULL;
	sqlite3* db = NULL;
	char* sql_err = NULL;
	int retval = 0;
	int err = SQLITE_OK;

	const gchar* sql_schema = \
		"PRAGMA foreign_keys = ON;"
		"BEGIN TRANSACTION;"
		"CREATE TABLE IF NOT EXISTS contacts ("
			"id INTEGER PRIMARY KEY AUTOINCREMENT,"
			"jid TEXT NOT NULL,"
			"encryption INTEGER DEFAULT 0 NOT NULL);"
		"CREATE UNIQUE INDEX IF NOT EXISTS jid_index ON contacts (jid);"

		"CREATE TABLE IF NOT EXISTS devices ("
			"id INTEGER NOT NULL,"
			"contact_id INTEGER NOT NULL,"
			"public_key BLOB,"
			"session BLOB,"
			"trust INTEGER DEFAULT 2 NOT NULL,"
			"status INTEGER DEFAULT 1 NOT NULL,"
			"timestamp INTEGER DEFAULT CURRENT_TIMESTAMP NOT NULL,"
			"FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE ON UPDATE CASCADE,"
			"PRIMARY KEY (id, contact_id));"
		"CREATE UNIQUE INDEX IF NOT EXISTS public_key_index ON devices(contact_id, public_key);"
		"CREATE TRIGGER status_updated AFTER UPDATE OF status ON devices "
		"BEGIN "
			"UPDATE devices SET timestamp = DATETIME('now') WHERE id = NEW.id AND NEW.status = 1;"
		"END;"

		"CREATE TABLE IF NOT EXISTS prekeys("
			"id INTEGER PRIMARY KEY AUTOINCREMENT,"
			"key_pair BLOB NOT NULL);"

		"CREATE TABLE IF NOT EXISTS signed_prekeys ("
			"id INTEGER PRIMARY KEY AUTOINCREMENT,"
			"key_pair BLOB NOT NULL,"
			"timestamp NUMERIC DEFAULT CURRENT_TIMESTAMP NOT NULL);"
		"CREATE INDEX IF NOT EXISTS timestamp_index ON signed_prekeys(timestamp);"

		"CREATE TABLE IF NOT EXISTS own_device ("
			"id INTEGER PRIMARY KEY NOT NULL,"
			"public_key BLOB NOT NULL,"
			"private_key BLOB NOT NULL,"
			"last_pre_key INTEGER,"
			"published INTEGER NOT NULL DEFAULT 0);"

		"PRAGMA user_version="DB_SCHEMA";"
		"COMMIT;";

	// Create OMEMO directory
	path = g_build_filename(purple_user_dir(), OMEMO_DIR, NULL);
	if (retval = purple_build_dir(path, 0700)) {
		purple_debug_error(PLUGIN_ID, _("Cannot create directory: %s\n"), path);
		goto cleanup;
	}
	g_free(path);
	path = NULL;

	// Create database
	path = get_db_path(db_id);
	purple_debug_info(PLUGIN_ID, "Try to create account database on %s\n", path);
	err = sqlite3_open(path, &db);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot open database: %s\n"), sqlite3_errmsg(db));
		retval = err;
		goto cleanup;
	}

	err = sqlite3_exec(db, sql_schema, NULL, NULL, &sql_err);
	if (err != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("SQL Error: %s\n"), sql_err);
		sqlite3_free(sql_err);
		retval = err;
		goto cleanup;
	}
	
	// Generate Signal elements
	if (retval = signal_protocol_key_helper_generate_identity_key_pair(&identity_key_pair, global_context)) {
		purple_debug_error(PLUGIN_ID, _("Cannot generate identity key pair\n"));
		goto cleanup;
	}

	if (retval = signal_protocol_key_helper_generate_registration_id(&registration_id, 1, global_context)) {
		purple_debug_error(PLUGIN_ID, _("Cannot generate registration ID\n"));
		goto cleanup;
	}
	
	if (retval = signal_protocol_key_helper_generate_signed_pre_key(&signed_pre_key, identity_key_pair, get_next_signed_pre_key_id(db), g_get_real_time(), global_context)) {
		purple_debug_error(PLUGIN_ID, _("Cannot generate signed pre key\n"));
		goto cleanup;
	}

	// Store identity_key_pair
	if (retval = store_local_identity_key_pair(registration_id, identity_key_pair, db)) {
		purple_debug_error(PLUGIN_ID, _("Cannot store identity key pair\n"));
		goto cleanup;
	}

	// Generate and store pre keys
	if (retval = generate_prekeys(g_random_int() % (G_MAXUINT16 - OPTIMAL_PRE_KEY_COUNT),
		OPTIMAL_PRE_KEY_COUNT, db)) {
		purple_debug_error(PLUGIN_ID, _("PreKey generation failed\n"));
		goto cleanup;
	}

	// Store signed pre key
	session_signed_pre_key_serialize(&buffer, signed_pre_key);
	if (retval = store_signed_pre_key(session_signed_pre_key_get_id(signed_pre_key), signal_buffer_data(buffer), signal_buffer_len(buffer), db)) {
		purple_debug_error(PLUGIN_ID, _("Cannot store signed pre key\n"));
		goto cleanup;
	}

	purple_account_set_string(account, SETTINGS_DB_ID, db_id);

	// Announce support
	publish_bundle(account);
	publish_device(account);

cleanup:
	if (buffer) signal_buffer_bzero_free(buffer);
	if (signed_pre_key) SIGNAL_UNREF(signed_pre_key);
	if (identity_key_pair) SIGNAL_UNREF(identity_key_pair);
	if (db) sqlite3_close(db);
	if (path) g_free(path);
	return retval;
}

int migrate_db(PurpleAccount* account)
{
	sqlite3* db = NULL;
	char* sql_err = NULL;
	int version = -1;
	int err = 0;

	const gchar* _1to2 = \
			"PRAGMA foreign_keys = ON;"
			"BEGIN TRANSACTION;"
			"ALTER TABLE own_device ADD COLUMN published INTEGER NOT NULL DEFAULT 0;"
			"UPDATE own_device SET published = 1;"
			"PRAGMA user_version=2;"
			"COMMIT;";

	get_omemo_db_for_account(&db, account);
	if (err = !db) {
		purple_debug_error(PLUGIN_ID, _("Cannot get DB handler for account %s\n"),
			purple_account_get_username(account));
		goto cleanup;
	}

	version = get_db_version(db);
	if (err = (version < 0)) {
		goto cleanup;
	}

	// From 1 to 2
	if (version == 1) {
		err = sqlite3_exec(db, _1to2, NULL, NULL, &sql_err);
		if (err != SQLITE_OK) {
			purple_debug_error(PLUGIN_ID, _("SQL Error: %s\n"), sql_err);
			sqlite3_free(sql_err);
			goto cleanup;
		}
		purple_debug_info(PLUGIN_ID, _("OMEMO store for %s migrated from version 1 to 2\n"),
			purple_account_get_username(account));
	}

cleanup:
	if (db) sqlite3_close(db);

	return err;
}

int build_session(PurpleAccount* account,
	gchar* jid,
	guint32 device_id,
	device_bundle* omemo_bundle)
{
	int retval = 0;
	guint32 r = 0;
	guint32 rand_pos = 0;
	guint32 pre_key_id = 0;
	GList* ids = NULL;
	ec_public_key* pre_key = NULL;
	sqlite3* db = NULL;
	signal_protocol_store_context* store_context = NULL;
	session_pre_key_bundle* signal_bundle = NULL;
	int session_result = SG_SUCCESS;
	session_builder* builder = NULL;
	int err = 0;

	get_omemo_db_for_account(&db, account);

	store_context = signal_store_context_create(db);
	if (!store_context) {
		purple_debug_error(PLUGIN_ID, _("Cannot create store context\n"));
		retval = -1;
		goto cleanup;
	}

	// Instantiate a session_builder for a recipient address
	signal_protocol_address address = {
		jid, strlen(jid), device_id
	};
	err = session_builder_create(&builder, store_context, &address, global_context);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot create session builder\n"));
		retval = -1;
		goto cleanup;
	}

	// Pick a random PreKey
	r = g_random_int();
	rand_pos = r % (g_hash_table_size(omemo_bundle->pre_keys_pub) - 1);
	ids = g_hash_table_get_keys(omemo_bundle->pre_keys_pub);
	pre_key_id = GPOINTER_TO_UINT(g_list_nth(ids, rand_pos)->data);
	g_list_free(ids);
	pre_key = g_hash_table_lookup(omemo_bundle->pre_keys_pub, GUINT_TO_POINTER(pre_key_id));

	// Build a session with the pre key bundle
	//purple_debug_info(PLUGIN_ID, _("About to build session with pre key %u\n"), pre_key_id);
	session_pre_key_bundle_create(&signal_bundle, device_id, 0, pre_key_id, pre_key,
		omemo_bundle->signed_pre_key_id,
		omemo_bundle->signed_pre_key_pub,
		signal_buffer_data(omemo_bundle->signed_pre_key_signature),
		signal_buffer_len(omemo_bundle->signed_pre_key_signature),
		omemo_bundle->identity_key_pub);

	session_result = session_builder_process_pre_key_bundle(builder, signal_bundle);
	switch (session_result) {
		case SG_ERR_INVALID_KEY:
			purple_debug_error(PLUGIN_ID,
				_("Cannot build session with %s (%u). Session pre key signal_bundle badly formatted\n"),
				jid, device_id);
			retval = session_result;
			goto cleanup;
		case SG_ERR_UNTRUSTED_IDENTITY:
			purple_debug_warning(PLUGIN_ID,
				_("Cannot build session with %s (%u). Sender's identity key is not trusted.\n"),
				jid, device_id);
			retval = session_result;
			goto cleanup;
		case SG_SUCCESS:
			purple_debug_info(PLUGIN_ID, _("Session with %s (%u) successfully built/updated.\n"),
				jid, device_id);
			break;
		default:
			purple_debug_error(PLUGIN_ID,
				_("Cannot build session with %s (%u). Unknown error %d.\n"),
				jid, device_id, session_result);
			retval = session_result;
			goto cleanup;
	}

	purple_debug_misc(PLUGIN_ID, _("Session with %s (%u) successfully built\n"), jid, device_id);

cleanup:
	if (store_context) signal_protocol_store_context_destroy(store_context);
	if (builder) session_builder_free(builder);
	if (signal_bundle) SIGNAL_UNREF(signal_bundle);
	if (db) sqlite3_close(db);

	return retval;
}

int decrypt_pre_key_message(PurpleAccount* account,
	guint8** plaintext,
	gsize* len,
	gchar* sender_jid,
	guint32 sid,
	pre_key_signal_message* pre_key_message)
{
	int retval = 0;
	sqlite3* db = NULL;
	signal_protocol_store_context* store_context;
	session_cipher* cipher = NULL;
	signal_buffer* plain_buffer = NULL;
	signal_buffer* identity_key_pub = NULL;
	int err = 0;
	guint8* plain = NULL;
	gsize plain_len = 0;

	get_omemo_db_for_account(&db, account);
	if (!db) {
		purple_debug_error(PLUGIN_ID, _("Cannot get DB handler for account %s\n"),
			purple_account_get_username(account));
		retval = -1;
		goto cleanup;
	}

	store_context = signal_store_context_create(db);
	if (!store_context) {
		purple_debug_error(PLUGIN_ID, _("Cannot create store context\n"));
		retval = -1;
		goto cleanup;
	}

	// Create cipher and decrypt the PreKeySignalMessage
	signal_protocol_address address = {
		sender_jid, strlen(sender_jid), sid
	};

	err = session_cipher_create(&cipher, store_context, &address, global_context);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot create session cipher\n"));
		retval = -1;
		goto cleanup;
	}

	// Retrieving a message from a device id will set that device id to active
	if (!device_tuple_exists(sender_jid, sid, db)) {
		err = add_device_tuple(sender_jid, sid, db);
		if (err) {
			purple_debug_error(PLUGIN_ID, _("Cannot add device tuple (%s, %u)\n"), sender_jid, sid);
			retval = -1;
			goto cleanup;
		}
	}
	err = activate_device(sender_jid, sid, db);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot activate device %u of %s\n"), sid, sender_jid);
		retval = -1;
		goto cleanup;
	}

	// Do save_identity() for Signal
	ec_public_key_serialize(&identity_key_pub,
		pre_key_signal_message_get_identity_key(pre_key_message));
	err = set_device_public_key(sender_jid, sid, signal_buffer_data(identity_key_pub),
		signal_buffer_len(identity_key_pub), db);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot set public key for %s (%u)\n"), sender_jid, sid);
		retval = -1;
		goto cleanup;
	}

	retval = session_cipher_decrypt_pre_key_signal_message(cipher, pre_key_message, NULL,
		&plain_buffer);
	switch (retval) {
		case SG_SUCCESS:
			plain_len = signal_buffer_len(plain_buffer);
			plain = g_memdup(signal_buffer_data(plain_buffer), plain_len);
			purple_debug_misc(PLUGIN_ID, _("PreKeySignalMessage successfully decrypted\n"));
			break;
		case SG_ERR_INVALID_KEY_ID:
			purple_debug_misc(PLUGIN_ID,
				_("There is no local pre_key_record that corresponds to " \
				"the PreKey ID %u in the message\n"),
				pre_key_signal_message_get_pre_key_id(pre_key_message));
			break;
		case SG_ERR_INVALID_KEY:
			purple_debug_warning(PLUGIN_ID, _("PreKeyMessage incorrectly formatted\n"));
			break;
		case SG_ERR_UNTRUSTED_IDENTITY:
			purple_debug_warning(PLUGIN_ID, _("Identity key of PreKeyMessage's " \
				"sender untrusted\n"));
			break;
		case SG_ERR_LEGACY_MESSAGE:
			purple_debug_warning(PLUGIN_ID, _("Deprecated PreKeyMessage format\n"));
			break;
		case SG_ERR_DUPLICATE_MESSAGE:
			purple_debug_info(PLUGIN_ID, _("PreKeyMessage already received\n"));
			break;
		case SG_ERR_INVALID_MESSAGE:
			purple_debug_warning(PLUGIN_ID, _("PreKeyMessage is not a valid ciphertext\n"));
			break;
		default:
			purple_debug_error(PLUGIN_ID, _("Unknown error %d\n"), retval);
			break;
	}

cleanup:
	if (plain_buffer) signal_buffer_bzero_free(plain_buffer);
	if (identity_key_pub) signal_buffer_free(identity_key_pub);
	if (cipher) session_cipher_free(cipher);
	if (store_context) signal_protocol_store_context_destroy(store_context);
	if (db) sqlite3_close(db);

	if (!retval) {
		*plaintext = plain;
		*len = plain_len;
	} else {
		if (plain) {
			memset(plain, 0, plain_len);
			g_free(plain);
		}
	}

	return retval;
}

int decrypt_signal_message(PurpleAccount* account,
	guint8** plaintext,
	gsize* len,
	gchar* sender_jid,
	guint32 sid,
	signal_message* signal_message)
{
	int retval = 0;
	sqlite3* db = NULL;
	signal_protocol_store_context* store_context;
	session_cipher* cipher = NULL;
	signal_buffer* plain_buffer = NULL;
	int err = 0;
	int decryption_result = SG_SUCCESS;
	guint8* plain = NULL;
	gsize plain_len = 0;

	get_omemo_db_for_account(&db, account);
	if (!db) {
		purple_debug_error(PLUGIN_ID, _("Cannot get DB handler for account %s\n"),
			purple_account_get_username(account));
		retval = -1;
		goto cleanup;
	}

	store_context = signal_store_context_create(db);
	if (!store_context) {
		purple_debug_error(PLUGIN_ID, _("Cannot create store context\n"));
		retval = -1;
		goto cleanup;
	}

	// Create cipher and decrypt the PreKeySignalMessage
	signal_protocol_address address = {
		sender_jid, strlen(sender_jid), sid
	};

	err = session_cipher_create(&cipher, store_context, &address, global_context);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot create session cipher\n"));
		retval = -1;
		goto cleanup;
	}

	// Retrieving a message from a device id will set that device id to active
	if (!device_tuple_exists(sender_jid, sid, db)) {
		err = add_device_tuple(sender_jid, sid, db);
		if (err) {
			purple_debug_error(PLUGIN_ID, _("Cannot add device tuple (%s, %u)\n"), sender_jid, sid);
			retval = -1;
			goto cleanup;
		}
	}
	err = activate_device(sender_jid, sid, db);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot activate device %u of %s\n"), sid, sender_jid);
		retval = -1;
		goto cleanup;
	}

	decryption_result = session_cipher_decrypt_signal_message(cipher, signal_message, NULL,
		&plain_buffer);
	switch (decryption_result) {
		case SG_SUCCESS:
			plain_len = signal_buffer_len(plain_buffer);
			plain = g_memdup(signal_buffer_data(plain_buffer), plain_len);
			/*gchar* plain_hex = bytes_to_hex(plain, plain_len);
			purple_debug_info(PLUGIN_ID, _("Decryption key: %s (%u)\n"), plain_hex, (uint32_t) plain_len);
			g_free(plain_hex);*/
			purple_debug_misc(PLUGIN_ID, _("SignalMessage successfully decrypted\n"));
			break;
		case SG_ERR_NO_SESSION:
			purple_debug_warning(PLUGIN_ID, _("No session for %s (%u)\n"), sender_jid, sid);
			// TODO: rebuild_session()
			retval = -1;
			break;
		case SG_ERR_LEGACY_MESSAGE:
			purple_debug_warning(PLUGIN_ID, _("Deprecated SignalMessage format\n"));
			retval = -1;
			break;
		case SG_ERR_DUPLICATE_MESSAGE:
			purple_debug_info(PLUGIN_ID, _("SignalMessage already received\n"));
			retval = -1;
			break;
		case SG_ERR_INVALID_MESSAGE:
			purple_debug_warning(PLUGIN_ID, _("SignalMessage is not a valid ciphertext\n"));
			retval = -1;
			break;
		default:
			purple_debug_error(PLUGIN_ID, _("Unknown error %d\n"), decryption_result);
			retval = -1;
			break;
	}

cleanup:
	if (plain_buffer) signal_buffer_bzero_free(plain_buffer);
	if (cipher) session_cipher_free(cipher);
	if (store_context) signal_protocol_store_context_destroy(store_context);
	if (db) sqlite3_close(db);

	if (!retval) {
		*plaintext = plain;
		*len = plain_len;
	} else {
		if (plain) {
			memset(plain, 0, plain_len);
			g_free(plain);
		}
	}

	return retval;
}

void subscribe_to_devicelist_updates(void)
{
	GList *accounts, *i;
	PurpleAccount* a = NULL;
	gboolean is_any_account_connected = FALSE;

	accounts = purple_accounts_get_all_active();
	for (i = accounts; i; i = i->next) {
		a = (PurpleAccount*) i->data;
		if (purple_strequal(purple_account_get_protocol_id(a), PROTO_XMPP) &&
			purple_account_is_connected(a)) {
				is_any_account_connected = TRUE;
				break;
		}
	}
	if (accounts) g_list_free(accounts);
	if (!is_any_account_connected) {
		jabber_add_feature(OMEMO_FEATURE_VAR, jabber_pep_namespace_only_when_pep_enabled_cb);
		purple_debug_misc(PLUGIN_ID, _("account: Added %s to account features\n"),
			OMEMO_FEATURE_VAR);
	}
}

static void stanza_sending_cb(PurpleConnection* gc, xmlnode** stanza)
{
	if (purple_strequal((*stanza)->name, "message")) {
		message_sending_cb(gc, xmlnode_get_attrib(*stanza, "type"), xmlnode_get_attrib(*stanza, "id"),
			xmlnode_get_attrib(*stanza, "from"), xmlnode_get_attrib(*stanza, "to"), stanza);
	}
	/*char* xml = NULL;
	int xml_len = 0;
	xml = xmlnode_to_formatted_str(*stanza, &xml_len);
	if (xml) {
		purple_debug_misc(PLUGIN_ID, _("Outgoing stanza (%s):\n%s\n"), (*stanza)->name, xml);
		g_free(xml);
	}*/
}

static void message_sending_cb(PurpleConnection* gc,
	const char* type,
	const char* id,
	const char* from,
	const char* to,
	xmlnode** message_ptr)
{
	xmlnode* message = *message_ptr;
	xmlnode* body = NULL;
	xmlnode* omemo_elem = NULL;
	PurpleAccount* account = NULL;
	sqlite3* db = NULL;
	int err = 0;

	body = xmlnode_get_child(message, "body");
	omemo_elem = xmlnode_get_child_with_namespace(message, "encrypted", OMEMO_NS);
	if (body && !omemo_elem) {
		account = purple_connection_get_account(gc);
		get_omemo_db_for_account(&db, account);
		if (encryption_is_enabled(to, db)) {
			err = prepare_encryption(account, from, to);
			if (err) {
				purple_debug_error(PLUGIN_ID, _("Preparation for encryption failed. Not sent\n"));
				// Invalidate message to avoid further processing
				xmlnode_free(body);
				goto cleanup;
			}
			
			err = encrypt_message(account, message);
			if (err) {
				purple_debug_error(PLUGIN_ID, _("Message encryption failed. Not sent\n"));
				// Invalidate message to avoid further processing
				xmlnode_free(body);
				goto cleanup;
			}

			purple_debug_info(PLUGIN_ID, _("Sending OMEMO message to %s\n"), to);

			/*gchar* msg_xml = NULL;
			guint msg_len = 0;
			msg_xml = xmlnode_to_formatted_str(message, &msg_len);
			purple_debug_misc(PLUGIN_ID, _("Encrypted message: %s\n"), msg_xml);
			g_free(msg_xml);*/
		}
	}

cleanup:
	if (db) sqlite3_close(db);
}

static gboolean message_receiving_cb(PurpleConnection* gc,
	const char* type,
	const char* id,
	const char* from,
	const char* to,
	xmlnode* message)
{
	/*char* xml = NULL;
	int xml_len = 0;
	xml = xmlnode_to_formatted_str(message, &xml_len);
	if (xml) {
		purple_debug_misc(PLUGIN_ID, _("Incoming message:\n%s\n"), xml);
		g_free(xml);
	}*/

	xmlnode* omemo_elem = NULL;

	// Catch OMEMO elements
	omemo_elem = xmlnode_get_child_with_namespace(message, "encrypted", OMEMO_NS);
	if (omemo_elem) {
		return decrypt_message(purple_connection_get_account(gc), message);
	}

	return FALSE;
}

static void device_list_update_cb(JabberStream *js, const char *from, xmlnode *items)
{
	PurpleAccount* account = NULL;
	sqlite3* db = NULL;
	gchar* jid = NULL;
	gchar* our_jid = NULL;
	device_list* local_device_list = NULL;
	device_list* remote_device_list = NULL;
	GList* local_devices = NULL;
	GList* remote_ids = NULL;
	GList* i = NULL;
	omemo_device* d = NULL;
	guint32 our_device_id = 0;
	guint32 id = 0;
	gboolean device_found = FALSE;
	gboolean is_own_account = FALSE;
	gboolean our_device_id_is_in_devicelist = FALSE;

	purple_debug_info(PLUGIN_ID, _("Received device list update from %s\n"), from);

	remote_device_list = get_device_list_from_items(items);
	if (!remote_device_list) {
		purple_debug_warning(PLUGIN_ID, _("Cannot parse device list from %s\n"), from);
		goto cleanup;
	}

	account = purple_connection_get_account(js->gc);

	// RFC 6120, Section 8.1.2.1, Rule 3
	if (from) { 
		jid = jabber_get_bare_jid(from);
	}
	else {
		jid = jabber_get_bare_jid(purple_account_get_username(account));
	}

	our_jid = jabber_get_bare_jid(purple_account_get_username(account));
	is_own_account = purple_strequal(jid, our_jid);

	get_omemo_db_for_account(&db, account);

	if (get_local_registration_id(db, &our_device_id)) {
		purple_debug_error(PLUGIN_ID, _("Cannot get own device ID from local storage\n"));
		goto cleanup;
	}

	if (is_own_account) {
		our_device_id_is_in_devicelist = device_list_remove(remote_device_list, our_device_id);
	}

	device_list_create(&local_device_list);
	local_devices = get_all_devices_for_contact(jid, global_context, db);
	for(i = local_devices; i; i = i->next) {
		d = (omemo_device*) i->data;
		device_found = device_list_contains(remote_device_list, d->id);

		if (device_found && d->status == INACTIVE) {
			// A device re-appears
			activate_device(d->jid, d->id, db);
		}
		
		if (!device_found && d->status == ACTIVE) {
			// A device disappears
			deactivate_device(d->jid, d->id, db);
		}
		// Prepare a minimal version of local_devices to make next step more efficient
		device_list_add(local_device_list, d->id);
		d = NULL;
	}

	i = NULL;
	remote_ids = device_list_get_ids(remote_device_list);
	for (i = remote_ids; i; i = i->next) {
		id = GPOINTER_TO_UINT(i->data);
		if (!device_list_contains(local_device_list, id)) {
			// A new device appears
			add_device_tuple(jid, id, db);
		}
	}

	purple_debug_misc(PLUGIN_ID, _("Local & remote device lists for %s synchronized\n"), jid);

	/* this is very noisy, but needed in case someone else adds
	 * us to the device list after a PEP flush
	 */
	if (is_own_account) {
		publish_bundle(account);
	}

	// prevent race condition
	if (is_own_account && !our_device_id_is_in_devicelist) {
		update_device_list(js, from, items);
	}

cleanup:
	if (remote_device_list) device_list_free(remote_device_list);
	if (local_device_list) device_list_free(local_device_list);
	if (remote_ids) g_list_free(remote_ids);
	if (local_devices) g_list_free_full(local_devices, omemo_device_free);
	if (db) sqlite3_close(db);
	if (our_jid) g_free(our_jid);
	if (jid) g_free(jid);
}

static void account_added_cb(PurpleAccount* account)
{
	if (purple_strequal(purple_account_get_protocol_id(account), PROTO_XMPP)) {
		omemo_account_setup(account);
	}
}

static void account_enabled_cb(PurpleAccount* account)
{
	if (purple_strequal(purple_account_get_protocol_id(account), PROTO_XMPP)) {
		omemo_account_setup(account);
	}
}

static void account_removed_cb(PurpleAccount* account)
{
	if (purple_strequal(purple_account_get_protocol_id(account), PROTO_XMPP)) {
		omemo_account_undo_announce(account);
	}
}

static void account_disabled_cb(PurpleAccount* account)
{
	if (purple_strequal(purple_account_get_protocol_id(account), PROTO_XMPP)) {
		omemo_account_undo_announce(account);
	}
}

static void account_signed_on_cb(PurpleAccount* account)
{
	if (purple_strequal(purple_account_get_protocol_id(account), PROTO_XMPP)) {
		publish_bundle(account);
		publish_device(account);
	}
}

static void account_authorization_granted_cb(PurpleAccount* account, const char* user)
{
	if (purple_strequal(purple_account_get_protocol_id(account), PROTO_XMPP)) {
		fetch_device_list(account, user, device_list_update_cb);
	}
}

gboolean decrypt_message(PurpleAccount* account, xmlnode* message)
{
	/*char* xml = NULL;
	int xml_len = 0;
	xml = xmlnode_to_formatted_str(message, &xml_len);
	if (xml) {
		purple_debug_misc(PLUGIN_ID, _("Incoming OMEMO message:\n%s\n"), xml);
		g_free(xml);
	}*/

	xmlnode* xml_omemo_elem = NULL;
	omemo_element* omemo_elem = NULL;
	guint32 recipient_device_id;
	gboolean retval = FALSE;
	gboolean invalid_pre_key_id = FALSE;
	sqlite3* db = NULL;
	gchar* sender_jid = NULL;
	guint8* result = NULL;
	gsize result_len = 0;
	pre_key_signal_message* pre_key_message = NULL;
	signal_message* signal_message = NULL;
	GList* matching_rids = NULL;
	GList* e = NULL;
	omemo_envelope* envelope = NULL;
	guint32 pre_key_count = 0;
	const char* from = NULL;

	from = xmlnode_get_attrib(message, "from");
	purple_debug_info(PLUGIN_ID, _("Receiving OMEMO Message from %s\n"), from);

	xml_omemo_elem = xmlnode_get_child_with_namespace(message, "encrypted", OMEMO_NS);

	omemo_element_deserialize(&omemo_elem, xml_omemo_elem);
	if (!omemo_elem) {
		purple_debug_error(PLUGIN_ID, _("Cannot parse OMEMO element\n"));
		goto cleanup;
	}

	get_omemo_db_for_account(&db, account);
	if (get_local_registration_id(db, &recipient_device_id)) {
		purple_debug_error(PLUGIN_ID, _("Cannot get own device ID from local storage\n"));
		goto cleanup;
	}

	matching_rids = omemo_element_get_matching(recipient_device_id, omemo_elem);
	if (!matching_rids) {
		purple_debug_warning(PLUGIN_ID,
			_("No <key> element wit rid=%u found in OMEMO message from %s\n"),
			recipient_device_id, from);
		goto cleanup;
	}

	sender_jid = jabber_get_bare_jid(from);
	for (e = matching_rids; e; e = e->next) {
		envelope = (omemo_envelope*) e->data;
		if (is_pre_key_message(envelope->data, envelope->data_len, &pre_key_message)) {
			pre_key_count = get_pre_key_count(db);
			if (decrypt_pre_key_message(account, &result, &result_len, sender_jid, omemo_elem->sid,
				pre_key_message) == SG_ERR_INVALID_KEY_ID) {
					invalid_pre_key_id = TRUE;
			}

			if (!result)
				continue;

			purple_debug_misc(PLUGIN_ID, _("Key element was a PreKeySignalMessage\n"));

			if (get_pre_key_count(db) < pre_key_count) {
				// Unpublish used pre-key
				publish_bundle(account);
			}
		}
		else {
			signal_message_deserialize(&signal_message, envelope->data, envelope->data_len,
				global_context);
			if (!signal_message)
				continue;

			decrypt_signal_message(account, &result, &result_len, sender_jid, omemo_elem->sid,
				signal_message);
			if (!result)
				continue;

			purple_debug_misc(PLUGIN_ID, _("Key element was a SignalMessage\n"));
		}
	}

	if (!result && invalid_pre_key_id) {
		rebuild_session(account, sender_jid, omemo_elem->sid);
		purple_debug_warning(PLUGIN_ID, _("Invalid pre-key-id in message from %s (%u)\n"), from,
			omemo_elem->sid);
		goto cleanup;
	}
	else if (!result) {
		purple_debug_warning(PLUGIN_ID,
			_("No matching <key> element with rid=%u in OMEMO message from %s could be successfully"
				" decrypted\n"),
			recipient_device_id, from);
		goto cleanup;
	}

	// XEP-0384 >= version 0.0.2
	/*if (result_len <= OMEMO_PAYLOAD_SECRET_LEN) {*/
	// Legacy
	if (result_len < OMEMO_PAYLOAD_SECRET_LEN) {
		purple_debug_warning(PLUGIN_ID,
			_("Malformed plaintext found after decryption of SignalMessage in OMEMO message "
				"from %s\n"),
			from);
		goto cleanup;
	}

	if (omemo_elem->payload) {
		purple_debug_misc(PLUGIN_ID, _("MessageElement (message contains payload)\n"));
		process_message_element(message, omemo_elem->payload, omemo_elem->payload_len, result,
			result_len, omemo_elem->iv, omemo_elem->iv_len);
	}
	else {
		purple_debug_misc(PLUGIN_ID, _("KeyTransportElement (no payload)\n"));
		retval = TRUE;
	}

cleanup:
	if (signal_message) SIGNAL_UNREF(signal_message);
	if (pre_key_message) SIGNAL_UNREF(pre_key_message);
	if (result) {
		memset(result, 0, result_len);
		g_free(result);
	}
	if (matching_rids) g_list_free(matching_rids);
	if (sender_jid) g_free(sender_jid);
	if (db) sqlite3_close(db);
	if (omemo_elem) omemo_element_free(omemo_elem);

	return retval;
}

void publish_bundle(PurpleAccount* account)
{
	device_bundle* bundle = NULL;

	if (!purple_account_is_connected(account))
		return;

	// Refill if needed before publishing
	refill_pre_keys(account);

	// Do maintenance to signed prekeys if needed
	update_signed_pre_keys(account);

	get_device_bundle(&bundle, account, global_context);
	if (!bundle) {
		purple_debug_error(PLUGIN_ID, _("Cannot construct our device bundle\n"));
		return;
	}

	push_bundle(account, bundle);

	device_bundle_free(bundle);
}

void unpublish_bundle(PurpleAccount* account)
{
	gchar* node_name = NULL;
	sqlite3* db = NULL;
	guint32 device_id = 0;

	if (!purple_account_is_connected(account))
		return;

	get_omemo_db_for_account(&db, account);

	get_local_registration_id(db, &device_id);
	node_name = g_strdup_printf("%s%u", OMEMO_BUNDLES_NS_PREFIX, device_id);

	jabber_pep_delete_node(purple_connection_get_protocol_data(
		purple_account_get_connection(account)), node_name);

	g_free(node_name);
	sqlite3_close(db);
}

void publish_device(PurpleAccount* account)
{
	if (!purple_account_is_connected(account))
		return;

	fetch_device_list(account, NULL, update_device_list);
}

void unpublish_device(PurpleAccount* account)
{
	if (!purple_account_is_connected(account))
		return;

	fetch_device_list(account, NULL, unpublish_device_end);
}

static void unpublish_device_end(JabberStream* js, const char* from, xmlnode* items) {
	PurpleAccount* account = NULL;
	sqlite3* db = NULL;
	guint32 device_id = 0;
	device_list* list = NULL;

	account = purple_connection_get_account(js->gc);

	if (!purple_account_is_connected(account))
		return;

	get_omemo_db_for_account(&db, account);
	if (get_local_registration_id(db, &device_id)) {
		purple_debug_error(PLUGIN_ID, _("Cannot get device ID from local storage\n"));
		goto cleanup;
	}

	list = get_device_list_from_items(items);
	if (!list) {
		purple_debug_misc(PLUGIN_ID, _("No device list found. Skip removing %u (us)\n"), device_id);
		goto cleanup;
	}

	if (!device_list_remove(list, device_id)) {
		purple_debug_misc(PLUGIN_ID, _("%u was not in remote device list. Skip removing\n"),
			device_id);
		goto cleanup;
	}

	purple_debug_info(PLUGIN_ID, _("Removing device %u (us) from remote device list\n"),
		device_id);
	push_device_list(account, list);

	set_own_device_published(FALSE, db);

cleanup:
	if (list) device_list_free(list);
	if (db) sqlite3_close(db);
}

static void update_device_list(JabberStream* js, const char* from, xmlnode* items)
{
	PurpleAccount* account = NULL;
	sqlite3* db = NULL;
	guint32 device_id = 0;
	device_list* list = NULL;
	gboolean first_time_pub = FALSE;
	const gchar* db_file = NULL;
	int err = 0;

	account = purple_connection_get_account(js->gc);

	if (!purple_account_is_connected(account))
		return;

	get_omemo_db_for_account(&db, account);
	if (get_local_registration_id(db, &device_id)) {
		purple_debug_error(PLUGIN_ID, _("Cannot get device ID from local storage\n"));
		goto cleanup;
	}

	first_time_pub = !is_own_device_published(db);

	list = get_device_list_from_items(items);
	// A device list already exists
	if (list) {
		if (device_list_add(list, device_id)) {
			purple_debug_info(PLUGIN_ID, _("Adding device %u (us) to remote device list\n"),
				device_id);
			push_device_list(account, list);

			if (first_time_pub) {
				set_own_device_published(TRUE, db);
			}
		}
		else {
			if (first_time_pub) {
				// Detect device ID conflicts when publishing for the first time
				purple_debug_warning(PLUGIN_ID, _("%u conflicts with another device. Trying to "
					"reinstall account with new ID and keys\n"), device_id);
				db_file = sqlite3_db_filename(db, "main");
				sqlite3_close(db);
				err = g_unlink(db_file);
				if (err) {
					purple_debug_error(PLUGIN_ID, _("Cannot delete %s. Account reinstall failed\n"),
						db_file);
					goto cleanup;
				}

				err = omemo_account_setup(account);
				if (err) {
					purple_debug_error(PLUGIN_ID, _("Account reinstall failed\n"));
					goto cleanup;
				}
			}
			else {
				purple_debug_misc(PLUGIN_ID, _("%u already in remote device list. Not updating\n"),
				device_id);
			}
		}
	}
	// No device list found. Create it
	else {
		device_list_create(&list);
		device_list_add(list, device_id);

		purple_debug_info(PLUGIN_ID, _("Creating remote device list with %u (us) in it\n"),
			device_id);
		push_device_list(account, list);

		if (first_time_pub) {
			set_own_device_published(TRUE, db);
		}
	}

cleanup:
	if (list) device_list_free(list);
	if (db) sqlite3_close(db);
}

static void fetch_device_list(PurpleAccount* account, const gchar* jid, JabberPEPHandler cb)
{
	if (jid) {
		purple_debug_misc(PLUGIN_ID, _("Fetching remote device list of %s\n"), jid);
	}
	else {
		purple_debug_misc(PLUGIN_ID, _("Fetching our remote device list (%s)\n"),
			purple_account_get_username(account));
	}

	jabber_pep_request_item(purple_connection_get_protocol_data(purple_account_get_connection(account)),
		jid, OMEMO_DEVICELIST_NS, NULL, cb);
}

static void push_device_list(PurpleAccount* account, const device_list* list)
{
	xmlnode* publish = NULL;
	xmlnode* item = NULL;
	xmlnode* list_elem = NULL;

	device_list_serialize(&list_elem, list);
	if (!list_elem) {
		purple_debug_error(PLUGIN_ID, _("Cannot serialize device list\n"));
		return;
	}

	publish = xmlnode_new("publish");
	xmlnode_set_attrib(publish, "node", OMEMO_DEVICELIST_NS);

	item = xmlnode_new_child(publish, "item");

	xmlnode_insert_child(item, list_elem);

	purple_debug_info(PLUGIN_ID, _("Publishing device list for account %s\n"),
		purple_account_get_username(account));
	jabber_pep_publish(purple_connection_get_protocol_data(purple_account_get_connection(account)),
		publish);
}

static void fetch_bundle(PurpleAccount* account, const gchar* jid, guint32 device_id, JabberPEPHandler cb)
{
	gchar* node_name = NULL;

	node_name = g_strdup_printf("%s%u", OMEMO_BUNDLES_NS_PREFIX, device_id);

	if (jid) {
		purple_debug_misc(PLUGIN_ID, _("Fetching device bundle %s for (%s)\n"), node_name, jid);
	}
	else {
		purple_debug_misc(PLUGIN_ID, _("Fetching our device bundle %s (%s)\n"), node_name,
			purple_account_get_username(account));
	}

	jabber_pep_request_item(purple_connection_get_protocol_data(purple_account_get_connection(account)),
		jid, node_name, NULL, cb);

	if (node_name) g_free(node_name);
}

static void push_bundle(PurpleAccount* account, const device_bundle* bundle)
{
	sqlite3* db = NULL;
	guint32 device_id = 0;
	gchar* node_name = NULL;
	xmlnode* publish = NULL;
	xmlnode* item = NULL;
	xmlnode* bundle_elem = NULL;

	get_omemo_db_for_account(&db, account);

	device_bundle_serialize(&bundle_elem, bundle, global_context);
	if (!bundle_elem) {
		purple_debug_error(PLUGIN_ID, _("Cannot serialize device bundle\n"));
		goto cleanup;
	}

	get_local_registration_id(db, &device_id);
	node_name = g_strdup_printf("%s%u", OMEMO_BUNDLES_NS_PREFIX, device_id);
	publish = xmlnode_new("publish");
	xmlnode_set_attrib(publish, "node", node_name);

	item = xmlnode_new_child(publish, "item");

	xmlnode_insert_child(item, bundle_elem);

	purple_debug_info(PLUGIN_ID, _("Publishing device bundle %s for account %s\n"), node_name,
		purple_account_get_username(account));
	jabber_pep_publish(purple_connection_get_protocol_data(purple_account_get_connection(account)),
		publish);

cleanup:
	if (node_name) g_free(node_name);
}

gboolean process_message_element(xmlnode* message,
	guint8* ciphertext,
	gsize ciphertext_len,
	guint8* decryption_data,
	gsize decryption_data_len,
	guint8* iv,
	gsize iv_len)
{
	gboolean retval = FALSE;
	guint8* body_buffer = NULL;
	gsize body_buffer_len = 0;
	xmlnode* body = NULL;
	guint8* key = NULL;
	guint8* tag = NULL;
	gsize tag_len = 0;
	gchar* plaintext = NULL;
	gsize plaintext_len = 0;

	key = decryption_data;

	if (decryption_data_len > OMEMO_PAYLOAD_SECRET_LEN) {
		// XEP-0384 >= version 0.0.2
		tag = decryption_data + OMEMO_PAYLOAD_SECRET_LEN;
		tag_len = decryption_data_len - OMEMO_PAYLOAD_SECRET_LEN;
	}
	else {
		// Legacy format
		tag_len = 16;
		tag = ciphertext + ciphertext_len - tag_len;
		ciphertext_len -= tag_len;
		purple_debug_warning(PLUGIN_ID, _("Legacy message format\n"));
	}

	decrypt_aes128_gcm(&body_buffer, &body_buffer_len, key, OMEMO_PAYLOAD_SECRET_LEN, iv, iv_len,
		tag, tag_len, ciphertext, ciphertext_len);

	if (!body_buffer) {
		purple_debug_misc(PLUGIN_ID, _("Cannot decrypt message\n"));
		retval = TRUE;
		goto cleanup;
	}

	body = xmlnode_get_child(message, "body");
	if (body) {
		xmlnode_clear_data(body);
	}
	else {
		body = xmlnode_new_child(message, "body");
		// This is needed for the message to show on the chat window
		xmlnode_set_namespace(body, NS_XMPP_CLIENT);
	}
	plaintext = body_buffer;
	plaintext_len = body_buffer_len;
	xmlnode_insert_data(body, plaintext, plaintext_len);

	/*gchar* msg_xml = NULL;
	guint msg_len = 0;
	msg_xml = xmlnode_to_formatted_str(message, &msg_len);
	purple_debug_misc(PLUGIN_ID, _("Decrypted message: %s\n"), msg_xml);
	g_free(msg_xml);*/

cleanup:
	if (body_buffer) {
		memset(body_buffer, 0, body_buffer_len);
		g_free(body_buffer);
	}

	return retval;
}

int prepare_encryption(PurpleAccount* account, const char* from, const char* to)
{
	sqlite3* db = NULL;
	gchar* bare_from = NULL;
	gchar* bare_to = NULL;
	GList* undecided_devices_to = NULL;
	GList* undecided_devices_from = NULL;
	int err = 0;

	get_omemo_db_for_account(&db, account);
	if (err = !db) {
		purple_debug_error(PLUGIN_ID, _("Cannot get DB handler for account %s\n"),
			purple_account_get_username(account));
		goto cleanup;
	}

	if (from) {
		bare_from = jabber_get_bare_jid(from);
	}
	else {
		bare_from = jabber_get_bare_jid(purple_account_get_username(account));
	}
	bare_to = jabber_get_bare_jid(to);

	// Check trust (TODO: block)
	undecided_devices_to = get_undecided_devices(bare_to, global_context, db);
	if (undecided_devices_to) {
		//TODO: inform user that they have to decide trust before sending encrypted messages to "to"
		purple_debug_warning(PLUGIN_ID, _("Trust decision needed\n"));
		err = 1;
		goto cleanup;
	}
	undecided_devices_from = get_undecided_devices(bare_from, global_context, db);
	if (undecided_devices_from) {
		//TODO: inform user that they have to decide trust before sending encrypted messages
		purple_debug_warning(PLUGIN_ID, _("Trust decision needed (own devices)\n"));
		err = 1;
		goto cleanup;
	}

	// Build missing sessions (TODO: block)
	build_missing_sessions(account, bare_from);
	build_missing_sessions(account, bare_to);

cleanup:
	if (undecided_devices_to) g_list_free_full(undecided_devices_to, omemo_device_free);
	if (undecided_devices_from) g_list_free_full(undecided_devices_from, omemo_device_free);
	if (bare_to) g_free(bare_to);
	if (bare_from) g_free(bare_from);
	if (db) sqlite3_close(db);

	return err;
}

void build_missing_sessions(PurpleAccount* account, const gchar* recipient_jid)
{
	gchar* jid = NULL;
	sqlite3* db = NULL;
	GList* devices = NULL;
	GList* i = NULL;
	omemo_device* d = NULL;

	jid = jabber_get_bare_jid(recipient_jid);
	get_omemo_db_for_account(&db, account);
	if (!db) {
		purple_debug_error(PLUGIN_ID, _("Cannot get DB handler for account %s\n"),
			purple_account_get_username(account));
		goto cleanup;
	}

	devices = get_devices_without_sessions(jid, global_context, db);
	for (i = devices; i != NULL; i = i->next) {
		d = (omemo_device*) i->data;
		fetch_bundle(account, jid, d->id, build_missing_sessions_end);
	}

cleanup:
	if (devices) g_list_free_full(devices, omemo_device_free);
	if (db) sqlite3_close(db);
	if (jid) g_free(jid);
}

static void build_missing_sessions_end(JabberStream *js, const char *from, xmlnode *items)
{
	gchar* jid = NULL;
	int bad_response = 0;
	guint32 device_id = 0;
	device_bundle* bundle = NULL;
	PurpleAccount* account = NULL;
	sqlite3* db = NULL;
	signal_buffer* identity_key_pub = NULL;
	int err = 0;

	account = purple_connection_get_account(js->gc);

	// RFC 6120, Section 8.1.2.1, Rule 3
	if (from) {
		jid = jabber_get_bare_jid(from);
	}
	else {
		jid = jabber_get_bare_jid(purple_account_get_username(account));
	}

	bundle = get_bundle_from_items(items, &device_id);
	if (!bundle) {
		purple_debug_warning(PLUGIN_ID, _("Cannot parse <bundle> element for %s\n"), jid);
		goto cleanup;
	}

	get_omemo_db_for_account(&db, account);
	if (!db) {
		purple_debug_error(PLUGIN_ID, _("Cannot get DB handler for account %s\n"),
			purple_account_get_username(account));
		goto cleanup;
	}

	// Do save_identity() for Signal
	ec_public_key_serialize(&identity_key_pub, bundle->identity_key_pub);
	err = set_device_public_key(jid, device_id, signal_buffer_data(identity_key_pub),
		signal_buffer_len(identity_key_pub), db);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot set public key for %s (%u)\n"), jid, device_id);
		goto cleanup;
	}

	err = build_session(account, jid, device_id, bundle);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot build session for %s (%u)\n"), jid, device_id);
		goto cleanup;
	}

cleanup:
	if (bad_response) {
		purple_debug_warning(PLUGIN_ID, _("Cannot fetch bundle for %s. Bad response\n"), jid);
	}

	if (identity_key_pub) signal_buffer_free(identity_key_pub);
	if (db) sqlite3_close(db);
	if (bundle) device_bundle_free(bundle);
	if (jid) g_free(jid);
}

int encrypt_message(PurpleAccount* account, xmlnode* message)
{
	int err = 0;
	guint8* key = NULL;
	guint8* iv = NULL;
	const gchar* from = NULL;
	const gchar* to = NULL;
	gchar* sender_jid = NULL;
	gchar* recipient_jid = NULL;
	sqlite3* db = NULL;
	xmlnode* body = NULL;
	xmlnode* xml_omemo_elem = NULL;
	xmlnode* hint = NULL;
	xmlnode* eme = NULL;
	xmlnode* html = NULL;
	guint8* plaintext = NULL;
	guint8* ciphertext = NULL;
	guint8* tag = NULL;
	guint8* key_tag = NULL;
	gsize plaintext_len = 0;
	gsize ciphertext_len = 0;
	gsize tag_len = 0;
	gsize key_tag_len = 0;
	guint32 sid = 0;
	GList* sender_devices = NULL;
	GList* recipient_devices = NULL;
	GList* devices = NULL;
	GList* i = NULL;
	omemo_device* d = NULL;
	omemo_element* omemo_elem = NULL;
	guint8* decryption_data = NULL;
	gsize decryption_data_len = 0;
	omemo_envelope* e = NULL;

	from = xmlnode_get_attrib(message, "from");
	to = xmlnode_get_attrib(message, "to");
	if (from) {
		sender_jid = jabber_get_bare_jid(from);
	}
	else {
		sender_jid = jabber_get_bare_jid(purple_account_get_username(account));
	}
	recipient_jid = jabber_get_bare_jid(to);

	get_omemo_db_for_account(&db, account);
	if (err = !db) {
		purple_debug_error(PLUGIN_ID, _("Cannot get DB handler for account %s\n"),
			purple_account_get_username(account));
		goto cleanup;
	}
	err = get_local_registration_id(db, &sid);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot get own device ID from local storage\n"));
		goto cleanup;
	}

	// Read message body
	body = xmlnode_get_child(message, "body");
	if (err = !body) {
		purple_debug_error(PLUGIN_ID, _("Cannot get message <body/>\n"));
		goto cleanup;
	}
	plaintext = xmlnode_get_data(body);
	if (err = !plaintext) {
		purple_debug_error(PLUGIN_ID, _("Cannot get contents of message <body/>\n"));
		goto cleanup;
	}
	plaintext_len = strlen(plaintext);

	// Generate random payload encryption key
	key = random_bytes(OMEMO_PAYLOAD_SECRET_LEN);
	if (err = !key) {
		purple_debug_error(PLUGIN_ID, _("Cannot generate key for encryption\n"));
		goto cleanup;
	}

	// Generate random initialization vector
	iv = random_bytes(OMEMO_PAYLOAD_IV_LEN);
	if (err = !iv) {
		purple_debug_error(PLUGIN_ID, _("Cannot generate initialization vector for encryption\n"));
		goto cleanup;
	}

	// Encrypt message body
	err = encrypt_aes128_gcm(&ciphertext, &ciphertext_len, &tag, &tag_len, key,
		OMEMO_PAYLOAD_SECRET_LEN, iv, OMEMO_PAYLOAD_IV_LEN, plaintext, plaintext_len);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot encrypt message\n"));
		goto cleanup;
	}

	// Create OMEMO element
	omemo_element_create(&omemo_elem, sid, iv, OMEMO_PAYLOAD_IV_LEN);
	omemo_element_set_payload(omemo_elem, ciphertext, ciphertext_len);

	// Encrypt decryption data for all devices
	sender_devices = get_devices_ready_to_receive(sender_jid, global_context, db);
	recipient_devices = get_devices_ready_to_receive(recipient_jid, global_context, db);
	devices = g_list_concat(sender_devices, recipient_devices);
	for (i = devices; i != NULL; i = i->next) {
		d = (omemo_device*) i->data;

		//Concatenate key and tag
		key_tag_len = OMEMO_PAYLOAD_SECRET_LEN + tag_len;
		key_tag = g_malloc(key_tag_len);
		memcpy(key_tag, key, OMEMO_PAYLOAD_SECRET_LEN);
		memcpy(key_tag+OMEMO_PAYLOAD_SECRET_LEN, tag, tag_len);
		
		new_signal_message(&decryption_data, &decryption_data_len, key_tag, key_tag_len, d->jid,
		d->id, db);
		if (!decryption_data) {
			purple_debug_error(PLUGIN_ID, _("Key encryption for %s (%u) failed\n"), sender_jid,
				d->id);
		}
		else {
			omemo_envelope_create(&e, d->id, decryption_data, decryption_data_len,
				purple_strequal(sender_jid, d->jid));
			omemo_element_add_envelope(omemo_elem, e);
			e = NULL;
		}

		memset(key_tag, 0, key_tag_len);
		g_free(key_tag);
		key_tag = NULL;

		d = NULL;
	}

	// Don't send anything if no session was available
	if (omemo_element_own_devices_only(omemo_elem)) {
		err = -1;
		purple_debug_warning(PLUGIN_ID, _("OMEMO element has no <key/> for any of the devices of "
			"%s. Not sending\n"), recipient_jid);
		goto cleanup;
	}

	// Remove original <body/>
	xmlnode_remove(body);
	/*xmlnode_clear_data(body);
	xmlnode_insert_data(body, _("I sent you an OMEMO encrypted message but your client doesn’t "
		"seem to support that. Find more information on https://conversations.im/omemo"), -1);*/

	// Remove <html/> if present
	html = xmlnode_get_child(message, "html");
	if (html) {
		purple_debug_misc(PLUGIN_ID, _("Removing <html/> from <message/>\n"));
		xmlnode_remove(html);
	}

	// Add <encrypted> element
	err = omemo_element_serialize(&xml_omemo_elem, omemo_elem);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot generate <encrypted> element\n"));
		goto cleanup;
	}
	xmlnode_insert_child(message, xml_omemo_elem);

	// Add hint for MAM
	hint = xmlnode_new_child(message, "store");
	xmlnode_set_namespace(hint, NS_HINTS);

	// Mark message with EME (XEP-0380) for unsupporting clients
	eme = xmlnode_new_child(message, "encryption");
	xmlnode_set_namespace(eme, NS_EME);
	xmlnode_set_attrib(eme, "namespace", OMEMO_NS);
	xmlnode_set_attrib(eme, "name", "OMEMO");

cleanup:
	if (devices) g_list_free_full(devices, omemo_device_free);
	if (tag) g_free(tag);
	if (plaintext) {
		memset(plaintext, 0, strlen(plaintext));
		g_free(plaintext);
	}
	if (omemo_elem) omemo_element_free(omemo_elem);
	if (db) sqlite3_close(db);
	if (recipient_jid) g_free(recipient_jid);
	if (sender_jid) g_free(sender_jid);
	if (key) {
		memset(key, 0, OMEMO_PAYLOAD_SECRET_LEN);
		g_free(key);
	}

	return err;
}

int new_signal_message(guint8** data,
	gsize* data_len,
	const guint8* plaintext,
	gsize plaintext_len,
	gchar* jid,
	guint32 device_id,
	sqlite3* db)
{
	int err = 0;
	signal_protocol_store_context* store_context = NULL;
	ciphertext_message* message = NULL;
	session_cipher* cipher = NULL;
	signal_buffer* message_data = NULL;

	store_context = signal_store_context_create(db);
	if (!store_context) {
		purple_debug_error(PLUGIN_ID, _("Cannot create store context\n"));
		goto cleanup;
	}

	// Instantiate a session_builder for a recipient address
	signal_protocol_address address = {
		jid, strlen(jid), device_id
	};
	
	// Create the session cipher and encrypt the plaintext
	err = session_cipher_create(&cipher, store_context, &address, global_context);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot create session cipher for %s (%u)\n"), jid,
			device_id);
		goto cleanup;
	}

	err = session_cipher_encrypt(cipher, plaintext, plaintext_len, &message);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot encrypt with session cipher for %s (%u) \n"), jid,
			device_id);
		goto cleanup;
	}

	// Get the serialized content
	message_data = ciphertext_message_get_serialized(message);

	/*pre_key_signal_message* msg = NULL;
	if (is_pre_key_message(signal_buffer_data(message_data), signal_buffer_len(message_data), &msg)) {
		purple_debug_info(PLUGIN_ID, _("Is a PreKeySignalMessage\n"));
		SIGNAL_UNREF(msg);
	}
	else {
		purple_debug_info(PLUGIN_ID, _("Is NOT a PreKeySignalMessage\n"));
	}
	gchar* plaintext_hex = bytes_to_hex(plaintext, plaintext_len);
	purple_debug_info(PLUGIN_ID, _("Encryption key: %s (%u)\n"), plaintext_hex, (uint32_t) plaintext_len);
	g_free(plaintext_hex);
	gchar* message_hex = bytes_to_hex(signal_buffer_data(message_data), signal_buffer_len(message_data));
	purple_debug_info(PLUGIN_ID, _("Ciphertext message: %s (%u)\n"), message_hex, (uint32_t) signal_buffer_len(message_data));
	g_free(message_hex);*/

	*data = g_memdup(signal_buffer_data(message_data), signal_buffer_len(message_data));
	*data_len = signal_buffer_len(message_data);

cleanup:
	if (message) SIGNAL_UNREF(message);
	if (cipher) session_cipher_free(cipher);
	if (store_context) signal_protocol_store_context_destroy(store_context);

	return err;
}

void refill_pre_keys(PurpleAccount* account)
{
	sqlite3* db = NULL;
	gint missing = 0;
	guint32 last_id = 0;
	guint32 next_id = 0;
	int err = 0;

	get_omemo_db_for_account(&db, account);
	if (!db) {
		purple_debug_error(PLUGIN_ID, _("Cannot get DB handler for account %s\n"),
			purple_account_get_username(account));
		goto cleanup;
	}

	missing = OPTIMAL_PRE_KEY_COUNT - get_pre_key_count(db);
	if (missing > 0) {
		last_id = get_last_pre_key_id(db);
		if (last_id == G_MAXUINT16) {
			next_id = 1;
		}
		else {
			next_id = last_id + 1;
		}

		if (next_id > last_id && G_MAXUINT16 - missing < last_id) {
			err = generate_prekeys(next_id, G_MAXUINT16 - last_id, db);
			if (err) {
				purple_debug_error(PLUGIN_ID, _("PreKey generation failed\n"));
				goto cleanup;
			}

			err = generate_prekeys(1, missing - (G_MAXUINT16 - last_id), db);
			if (err) {
				purple_debug_error(PLUGIN_ID, _("PreKey generation failed\n"));
				goto cleanup;
			}
		}
		else {
			err = generate_prekeys(next_id, missing, db);
			if (err) {
				purple_debug_error(PLUGIN_ID, _("PreKey generation failed\n"));
				goto cleanup;
			}
		}

		purple_debug_misc(PLUGIN_ID, _("Prekey storage refilled with %u new prekeys\n"), missing);
	}

cleanup:
	if (db) sqlite3_close(db);
}

void update_signed_pre_keys(PurpleAccount* account)
{
	sqlite3* db = NULL;
	guint32 elapsed = 0;
	int err = 0;

	get_omemo_db_for_account(&db, account);
	if (!db) {
		purple_debug_error(PLUGIN_ID, _("Cannot get DB handler for account %s\n"),
			purple_account_get_username(account));
		goto cleanup;
	}

	elapsed = get_current_signed_pre_key_age(db);
	if (elapsed > SIGNED_PRE_KEY_DAYS_TO_RENEW) {
		err = generate_signed_pre_key(get_next_signed_pre_key_id(db), db);
		if (err) {
			purple_debug_error(PLUGIN_ID, _("Cannot produce a new signed pre key\n"));
			goto cleanup;
		}
	}

	err = remove_signed_pre_keys_older_than(db, SIGNED_PRE_KEY_DAYS_TO_DELETE);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot remove old signed pre keys\n"));
		goto cleanup;
	}

cleanup:
	if (db) sqlite3_close(db);
}

int generate_signed_pre_key(guint32 id, sqlite3* db)
{
	ratchet_identity_key_pair* identity_key_pair = NULL;
	signal_buffer* buffer = NULL;
	signal_buffer* buffer_pub = NULL;
	signal_buffer* buffer_priv = NULL;
	ec_public_key* public_key = NULL;
	ec_private_key* private_key = NULL;
	session_signed_pre_key* signed_pre_key = NULL;
	int err = 0;

	err = get_identity_key_pair(&buffer_pub, &buffer_priv, db);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot get identity key pair\n"));
		goto cleanup;
	}
	err = curve_decode_point(&public_key, signal_buffer_data(buffer_pub),
		signal_buffer_len(buffer_pub), global_context);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot deserialize public identity key\n"));
		goto cleanup;
	}
	err = curve_decode_private_point(&private_key, signal_buffer_data(buffer_priv),
		signal_buffer_len(buffer_priv), global_context);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot deserialize private identity key\n"));
		goto cleanup;
	}
	err = ratchet_identity_key_pair_create(&identity_key_pair, public_key, private_key);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot deserialize identity key pair\n"));
		goto cleanup;
	}
	err = signal_protocol_key_helper_generate_signed_pre_key(&signed_pre_key, identity_key_pair, id,
		g_get_real_time(), global_context);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot generate signed pre key\n"));
		goto cleanup;
	}
	err = session_signed_pre_key_serialize(&buffer, signed_pre_key);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot serialize signed pre key\n"));
		goto cleanup;
	}
	err = store_signed_pre_key(session_signed_pre_key_get_id(signed_pre_key),
		signal_buffer_data(buffer), signal_buffer_len(buffer), db);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot store signed pre key\n"));
		goto cleanup;
	}

	purple_debug_misc(PLUGIN_ID, _("New signed prekey %u generated\n"), id);

cleanup:
	if (public_key) SIGNAL_UNREF(public_key);
	if (private_key) SIGNAL_UNREF(private_key);
	if (buffer) signal_buffer_bzero_free(buffer);
	if (buffer_pub) signal_buffer_free(buffer_pub);
	if (buffer_priv) signal_buffer_bzero_free(buffer_priv);
	if (signed_pre_key) SIGNAL_UNREF(signed_pre_key);
	if (identity_key_pair) SIGNAL_UNREF(identity_key_pair);

	return err;
}

int generate_prekeys(guint32 from_id, guint32 count, sqlite3* db) {
	int err = 0;
	guint32 stored = 0;
	signal_protocol_key_helper_pre_key_list_node* pre_keys_head = NULL;
	signal_protocol_key_helper_pre_key_list_node* node = NULL;
	session_pre_key* pre_key = NULL;
	signal_buffer* buffer = NULL;

	err = signal_protocol_key_helper_generate_pre_keys(&pre_keys_head, from_id, count,
		global_context);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot generate PreKeys\n"));
		goto cleanup;
	}

	for (node = pre_keys_head; node; node = signal_protocol_key_helper_key_list_next(node)) {
		pre_key = signal_protocol_key_helper_key_list_element(node);
		session_pre_key_serialize(&buffer, pre_key);
		err = store_pre_key(session_pre_key_get_id(pre_key), signal_buffer_data(buffer),
			signal_buffer_len(buffer), db);
		signal_buffer_bzero_free(buffer);
		buffer = NULL;
		if (err) {
			purple_debug_error(PLUGIN_ID, _("Cannot store pre key\n"));
			continue;
		}
		stored++;
	}

	set_last_pre_key_id(from_id + stored - 1, db);

cleanup:
	if (pre_keys_head) signal_protocol_key_helper_key_list_free(pre_keys_head);

	return err;
}

void rebuild_session(PurpleAccount* account, const gchar* jid, guint32 device_id)
{
	fetch_bundle(account, jid, device_id, rebuild_session_end);
}

static void rebuild_session_end(JabberStream *js, const char *from, xmlnode *items)
{
	int err = 0;
	gchar* jid = NULL;
	guint32 device_id = 0;
	device_bundle* bundle = NULL;

	// RFC 6120, Section 8.1.2.1, Rule 3
	if (from) { 
		jid = jabber_get_bare_jid(from);
	}
	else {
		jid = jabber_get_bare_jid(purple_account_get_username(
			purple_connection_get_account(js->gc)));
	}

	bundle = get_bundle_from_items(items, &device_id);
	if (!bundle) {
		purple_debug_warning(PLUGIN_ID, _("Cannot parse <bundle> element for %s (%u)\n"), jid,
			device_id);
		goto cleanup;
	}

	err = build_session(purple_connection_get_account(js->gc), jid, device_id, bundle);
	if (err) {
		purple_debug_warning(PLUGIN_ID, _("Cannot build session with %s (%u)\n"), jid,
			device_id);
		goto cleanup;
	}

	send_ratchet_update_message(purple_connection_get_account(js->gc), from, device_id);

cleanup:
	if (bundle) device_bundle_free(bundle);
	if (jid) g_free(jid);
}

void send_ratchet_update_message(PurpleAccount* account, const gchar* to, guint32 device_id)
{
	gchar* jid = NULL;
	sqlite3* db = NULL;
	guint32 sid = 0;
	xmlnode* msg = NULL;
	xmlnode* xml_omemo_elem = NULL;
	xmlnode* hint = NULL;
	xmlnode* eme = NULL;
	omemo_element* omemo_elem = NULL;
	omemo_envelope* e = NULL;
	guint8* dummy_secret = NULL;
	guint8* data = NULL;
	gsize data_len = 0;

	jid = jabber_get_bare_jid(to);

	get_omemo_db_for_account(&db, account);
	if (!db) {
		purple_debug_error(PLUGIN_ID, _("Cannot get DB handler for account %s\n"),
			purple_account_get_username(account));
		goto cleanup;
	}

	if (get_local_registration_id(db, &sid)) {
		purple_debug_error(PLUGIN_ID, _("Cannot get own device ID from local storage\n"));
		goto cleanup;
	}

	omemo_element_create(&omemo_elem, sid, random_bytes(OMEMO_PAYLOAD_IV_LEN), OMEMO_PAYLOAD_IV_LEN);
	if (!omemo_elem) {
		goto cleanup;
	}

	// Generate dummy Signal message
	dummy_secret = random_bytes(OMEMO_PAYLOAD_SECRET_LEN);
	new_signal_message(&data, &data_len, dummy_secret, OMEMO_PAYLOAD_SECRET_LEN, jid, device_id, db);
	if (!data) {
		goto cleanup;
	}

	omemo_envelope_create(&e, device_id, data, data_len, 0);
	if (!e) {
		goto cleanup;
	}

	omemo_element_add_envelope(omemo_elem, e);

	omemo_element_serialize(&xml_omemo_elem, omemo_elem);
	if (!xml_omemo_elem) {
		goto cleanup;
	}

	msg = xmlnode_new("message");
	xmlnode_set_attrib(msg, "to", to);

	xmlnode_insert_child(msg, xml_omemo_elem);

	// Add hint for MAM
	hint = xmlnode_new_child(msg, "store");
	xmlnode_set_namespace(hint, NS_HINTS);

	// Mark message with EME (XEP-0380) for unsupporting clients
	eme = xmlnode_new_child(msg, "encryption");
	xmlnode_set_namespace(eme, NS_EME);
	xmlnode_set_attrib(eme, "namespace", OMEMO_NS);
	xmlnode_set_attrib(eme, "name", "OMEMO");

	jabber_send(purple_connection_get_protocol_data(purple_account_get_connection(account)), msg);

	purple_debug_info(PLUGIN_ID, _("OMEMO ratchet update message sent to %s (%u)\n"), to, device_id);

cleanup:
	if (omemo_elem) omemo_element_free(omemo_elem);
	if (dummy_secret) g_free(dummy_secret);
	if (msg) xmlnode_free(msg);
	if (db) sqlite3_close(db);
	if (jid) g_free(jid);
}

device_list* get_device_list_from_items(xmlnode *items)
{
	xmlnode* item = NULL;
	xmlnode* list_elem = NULL;
	device_list* list = NULL;

	if (!items) {
		purple_debug_warning(PLUGIN_ID, _("Cannot fetch device list\n"));
		return NULL;
	}

	item = xmlnode_get_child(items, "item");
	if (!item) {
		return NULL;
	}

	list_elem = xmlnode_get_child_with_namespace(item, "list", OMEMO_NS);
	if (!list_elem) {
		return NULL;
	}

	device_list_deserialize(&list, list_elem);

	return list;
}

device_bundle* get_bundle_from_items(xmlnode* items, guint32* device_id)
{
	xmlnode* item = NULL;
	xmlnode* bundle_elem = NULL;
	const gchar* node_name = NULL;
	gchar* device_id_str = NULL;
	device_bundle* bundle = NULL;

	if (!items) {
		purple_debug_warning(PLUGIN_ID, _("Cannot fetch bundle information\n"));
		return NULL;
	}

	node_name = xmlnode_get_attrib(items, "node");
	if (!node_name) {
		return NULL;
	}

	if (device_id) {
		device_id_str = purple_strreplace(node_name, OMEMO_BUNDLES_NS_PREFIX, "");
		*device_id = g_ascii_strtoull(device_id_str, NULL, 10);
		g_free(device_id_str);
	}

	item = xmlnode_get_child(items, "item");
	if (!item) {
		return NULL;
	}

	bundle_elem = xmlnode_get_child_with_namespace(item, "bundle", OMEMO_NS);
	if (!bundle_elem) {
		return NULL;
	}

	device_bundle_deserialize(&bundle, bundle_elem, global_context);

	return bundle;
}

gboolean is_pre_key_message(const guint8* data, gsize len, pre_key_signal_message** message)
{
	pre_key_signal_message* msg = NULL;
	gboolean retval = FALSE;

	pre_key_signal_message_deserialize(&msg, data, len, global_context);
	if (!msg) {
		//purple_debug_misc(PLUGIN_ID, _("Cannot deserialize message\n"));
		goto cleanup;
	}

	if (!pre_key_signal_message_has_pre_key_id(msg)) {
		//purple_debug_misc(PLUGIN_ID, _("Message has no pre key id\n"));
		goto cleanup;
	}

	retval = TRUE;

cleanup:
	if (retval) {
		*message = msg;
	}
	else {
		if (msg) SIGNAL_UNREF(msg);
	}

	return retval;
}

void get_omemo_db_for_account(sqlite3** db, PurpleAccount* account)
{
	gchar* path = NULL;
	char* sql_err = NULL;
	const gchar* db_id = purple_account_get_string(account, SETTINGS_DB_ID, NULL);

	if (!db_id) {
		purple_debug_warning(PLUGIN_ID, _("Cannot get %s from account %s\n"), SETTINGS_DB_ID, purple_account_get_username(account));
		*db = NULL;
		return;
	}

	path = get_db_path(db_id);
	if (sqlite3_open(path, db) != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot open database: %s\n"), sqlite3_errmsg(*db));
		sqlite3_close(*db);
		*db = NULL;
	}

	if (sqlite3_exec(*db, "PRAGMA foreign_keys = ON;", NULL, NULL, &sql_err) != SQLITE_OK) {
		purple_debug_error(PLUGIN_ID, _("Cannot activate PRAGMA foreign_keys: %s\n"), sql_err);
		sqlite3_free(sql_err);
		sqlite3_close(*db);
		*db = NULL;
	}

	g_free(path);
}

gchar* get_db_path(const gchar* db_id)
{
	gchar* db_path = NULL;
	gchar* db_filename = NULL;

	db_filename = g_strconcat(db_id, ".sqlite", NULL);
	db_path = g_build_filename(purple_user_dir(), OMEMO_DIR, db_filename, NULL);
	g_free(db_filename);

	return db_path;
}

static void signal_lock_func(void* user_data)
{
	g_rec_mutex_lock(signal_mutex);
}

static void signal_unlock_func(void* user_data)
{
	g_rec_mutex_unlock(signal_mutex);
}

gchar* rand_string(gsize len)
{
	guint8 r;
	int i, rand_pos;
	gchar* str = g_malloc(sizeof(gchar) * (len + 1));
	const gchar charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";

	for (i = 0; i < len; i++) {
		random_generator(&r, 1, NULL);
		rand_pos = r % (int) (sizeof(charset) - 1);
		str[i] = charset[rand_pos];
	}
	str[len] = '\0';

	return str;
}

void xmlnode_clear_data(xmlnode* node)
{
	xmlnode* data_node = NULL;
	xmlnode* sibling = NULL;

	data_node = node->child;
	while (data_node) {
		if(data_node->type == XMLNODE_TYPE_DATA) {
			if (node->lastchild == data_node) {
				node->lastchild = sibling;
			}

			if (sibling == NULL) {
				node->child = data_node->next;
				xmlnode_free(data_node);
				data_node = node->child;
			}
			else {
				sibling->next = data_node->next;
				xmlnode_free(data_node);
				data_node = sibling->next;
			}
		}
		else {
			sibling = data_node;
			data_node = data_node->next;
		}
	}
}

void xmlnode_remove(xmlnode* node)
{
	xmlnode* parent = NULL;
	xmlnode* next_sibling = NULL;
	xmlnode* prev = NULL;

	parent = node->parent;
	next_sibling = xmlnode_get_next_sibling(node);

	if (parent && node == parent->child) {
		parent->child = next_sibling;
	}
	else if (parent) {
		for (prev = node->parent->child; prev; prev = prev->next) {
			if (prev->next == node) {
				prev->next = next_sibling;
				break;
			}
		}
	}

	if (parent && node == parent->lastchild) {
		parent->lastchild = prev;
	}

	xmlnode_free(node);
}

xmlnode* xmlnode_get_next_sibling(xmlnode* node) {
	xmlnode* n = NULL;

	for (n = node->next; n; n = n->next) {
		if (n->type == XMLNODE_TYPE_TAG)
			return n;
	}

	return NULL;
}

guint8* random_bytes(gsize len) {
	int err = 0;
	guint8* ret = NULL;

	ret = g_malloc(len * sizeof(*ret));
	if (!ret) {
		purple_debug_error(PLUGIN_ID, _("Cannot allocate memory\n"));
		return NULL;
	}
	err = random_generator(ret, len, NULL);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot generate random bytes\n"));
		g_free(ret);
		return NULL;
	}

	return ret;
}

gchar* bytes_to_hex(const guint8* bytes, gsize len) {
	gchar* hex = NULL;
	gchar* i = NULL;
	int j;

	hex = g_malloc(len * 2 + 1);
	i = hex;
	for (j = 0; j < len; j++) {
		sprintf(i, "%02x", bytes[j]);
		i += 2;
	}
	*i = '\0';

	return hex;
}
