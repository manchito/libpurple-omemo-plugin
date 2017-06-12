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
#include <util.h>

#include "../omemo.h"
#include "../store/identity_key_store.h"
#include "../store/pre_key_store.h"
#include "../store/signed_pre_key_store.h"

#include "device_bundle.h"

int get_device_bundle(device_bundle** bundle,
	PurpleAccount* account, 
	signal_context* global_context)
{
	int retval = 0;
	int err = 0;
	device_bundle* dev_bundle = NULL;
	sqlite3* db = NULL;
	signal_buffer* pub_key_buffer = NULL;
	signal_buffer* priv_key_buffer = NULL;
	signal_buffer* key_pair_buffer = NULL;
	session_signed_pre_key* signed_pre_key = NULL;
	GList* prekeys = NULL;
	GList* l = NULL;
	session_pre_key* pre_key = NULL;
	ec_public_key* pre_key_pub = NULL;

	void prekeys_free_full(gpointer data) {
		SIGNAL_UNREF(data);
	}

	dev_bundle = g_new0(device_bundle, 1);
	if (!dev_bundle) {
		purple_debug_error(PLUGIN_ID, _("Cannot allocate device_bundle\n"));
		retval = -1;
		goto cleanup;
	}

	get_omemo_db_for_account(&db, account);
	if (!db) {
		purple_debug_error(PLUGIN_ID, _("Cannot get DB handler for account %s\n"),
			purple_account_get_username(account));
		retval = -1;
		goto cleanup;
	}

	// .identity_key_pub
	err = get_identity_key_pair(&pub_key_buffer, &priv_key_buffer, db);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot find an identity key in local storage\n"));
		retval = -1;
		goto cleanup;
	}
	curve_decode_point(&dev_bundle->identity_key_pub, signal_buffer_data(pub_key_buffer),
		signal_buffer_len(pub_key_buffer), global_context);
	signal_buffer_free(pub_key_buffer);
	pub_key_buffer = NULL;

	// .signed_pre_key_id
	dev_bundle->signed_pre_key_id = get_current_signed_pre_key_id(db);
	if (!dev_bundle->signed_pre_key_id) {
		purple_debug_error(PLUGIN_ID, _("Cannot find current signed pre key id\n"));
		retval = -1;
		goto cleanup;
	}

	// .signed_pre_key_pub
	err = load_signed_pre_key(&key_pair_buffer, dev_bundle->signed_pre_key_id, db);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot find signed pre key %u in local storage\n"),
			dev_bundle->signed_pre_key_id);
		retval = -1;
		goto cleanup;
	}
	session_signed_pre_key_deserialize(&signed_pre_key, signal_buffer_data(key_pair_buffer),
		signal_buffer_len(key_pair_buffer), global_context);

	ec_public_key_serialize(&pub_key_buffer,
		ec_key_pair_get_public(session_signed_pre_key_get_key_pair(signed_pre_key)));
	curve_decode_point(&dev_bundle->signed_pre_key_pub, signal_buffer_data(pub_key_buffer),
		signal_buffer_len(pub_key_buffer), global_context);
	signal_buffer_free(pub_key_buffer);
	pub_key_buffer = NULL;

	// .signed_pre_key_signature
	dev_bundle->signed_pre_key_signature = signal_buffer_create(
		session_signed_pre_key_get_signature(signed_pre_key),
		session_signed_pre_key_get_signature_len(signed_pre_key));
	if (!dev_bundle->signed_pre_key_signature) {
		purple_debug_error(PLUGIN_ID, _("Cannot set signed pre key signature\n"));
		retval = -1;
		goto cleanup;
	}

	// .pre_keys_pub
	dev_bundle->pre_keys_pub = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, prekey_free);
	load_pre_keys(&prekeys, db, global_context);
	for (l = prekeys; l != NULL; l = l->next) {
		pre_key = (session_pre_key*) l->data;

		// copy the public pre key part to a new pre_key_pub
		ec_public_key_serialize(&pub_key_buffer,
			ec_key_pair_get_public(session_pre_key_get_key_pair(pre_key)));
		curve_decode_point(&pre_key_pub, signal_buffer_data(pub_key_buffer),
			signal_buffer_len(pub_key_buffer), global_context);

		g_hash_table_insert(dev_bundle->pre_keys_pub,
			GUINT_TO_POINTER(session_pre_key_get_id(pre_key)),
			pre_key_pub);

		signal_buffer_free(pub_key_buffer);
		pub_key_buffer = NULL;
		pre_key_pub = NULL;
		pre_key = NULL;
	}
	g_list_free_full(prekeys, prekeys_free_full);

	*bundle = dev_bundle;

cleanup:
	if (signed_pre_key) SIGNAL_UNREF(signed_pre_key);
	if (key_pair_buffer) signal_buffer_bzero_free(key_pair_buffer);
	if (pub_key_buffer) signal_buffer_free(pub_key_buffer);
	if (priv_key_buffer) signal_buffer_bzero_free(priv_key_buffer);
	if (db) sqlite3_close(db);
	if (retval && dev_bundle) device_bundle_free(dev_bundle);

	return retval;
}

int device_bundle_serialize(xmlnode** result,
	const device_bundle* bundle,
	signal_context* global_context)
{
	int retval = 0;
	int err = 0;
	xmlnode* xml_bundle = NULL;
	xmlnode* identity_key_elem = NULL;
	xmlnode* signed_pre_key_elem = NULL;
	xmlnode* signed_pre_key_sig_elem = NULL;
	xmlnode* prekeys_elem = NULL;
	xmlnode* pre_key_elem = NULL;
	signal_buffer* pub_key_buffer = NULL;
	guchar* base64 = NULL;
	gchar* id_str = NULL;
	GHashTableIter i;
	gpointer k, v;
	guint32 pre_key_id = 0;
	ec_public_key* pre_key_pub = NULL;

	xml_bundle = xmlnode_new("bundle");
	xmlnode_set_namespace(xml_bundle, OMEMO_NS);

	// <signedPreKeyPublic>
	signed_pre_key_elem = xmlnode_new_child(xml_bundle, "signedPreKeyPublic");
	id_str = g_strdup_printf("%u", bundle->signed_pre_key_id);
	xmlnode_set_attrib(signed_pre_key_elem, "signedPreKeyId", id_str);
	g_free(id_str);
	id_str = NULL;
	err = ec_public_key_serialize(&pub_key_buffer, bundle->signed_pre_key_pub);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot serialize device_bundle->signed_pre_key_pub\n"));
		retval = -1;
		goto cleanup;
	}
	base64 = purple_base64_encode(signal_buffer_data(pub_key_buffer),
		signal_buffer_len(pub_key_buffer));
	xmlnode_insert_data(signed_pre_key_elem, base64, -1);
	signal_buffer_free(pub_key_buffer);
	g_free(base64);
	pub_key_buffer = NULL;
	base64 = NULL;

	// <signedPreKeySignature>
	signed_pre_key_sig_elem = xmlnode_new_child(xml_bundle, "signedPreKeySignature");
	base64 = purple_base64_encode(signal_buffer_data(bundle->signed_pre_key_signature),
		signal_buffer_len(bundle->signed_pre_key_signature));
	xmlnode_insert_data(signed_pre_key_sig_elem, base64, -1);
	g_free(base64);
	base64 = NULL;

	// <identityKey>
	identity_key_elem = xmlnode_new_child(xml_bundle, "identityKey");
	err = ec_public_key_serialize(&pub_key_buffer, bundle->identity_key_pub);
	if (err) {
		purple_debug_error(PLUGIN_ID, _("Cannot serialize device_bundle->identity_key_pub\n"));
		retval = -1;
		goto cleanup;
	}
	base64 = purple_base64_encode(signal_buffer_data(pub_key_buffer),
		signal_buffer_len(pub_key_buffer));
	xmlnode_insert_data(identity_key_elem, base64, -1);
	signal_buffer_free(pub_key_buffer);
	g_free(base64);
	pub_key_buffer = NULL;
	base64 = NULL;

	// <prekeys>
	prekeys_elem = xmlnode_new_child(xml_bundle, "prekeys");
	g_hash_table_iter_init (&i, bundle->pre_keys_pub);
	while (g_hash_table_iter_next(&i, &k, &v)) {
		pre_key_id = GPOINTER_TO_UINT(k);
		pre_key_pub = (ec_public_key*) v;
		pre_key_elem = xmlnode_new_child(prekeys_elem, "preKeyPublic");
		id_str = g_strdup_printf("%u", pre_key_id);
		xmlnode_set_attrib(pre_key_elem, "preKeyId", id_str);
		ec_public_key_serialize(&pub_key_buffer, pre_key_pub);
		base64 = purple_base64_encode(signal_buffer_data(pub_key_buffer),
			signal_buffer_len(pub_key_buffer));
		xmlnode_insert_data(pre_key_elem, base64, -1);
		g_free(base64);
		signal_buffer_free(pub_key_buffer);
		g_free(id_str);
		base64 = NULL;
		pub_key_buffer = NULL;
		id_str = NULL;
	}

	*result = xml_bundle;

cleanup:
	if (id_str) g_free(id_str);
	if (base64) g_free(base64);
	if (pub_key_buffer) signal_buffer_free(pub_key_buffer);
	if (retval && xml_bundle) xmlnode_free(xml_bundle);

	return retval;
}

int device_bundle_deserialize(device_bundle** result,
	const xmlnode* xml_bundle,
	signal_context* global_context)
{
	int retval = 0;
	device_bundle* dev_bundle = NULL;
	xmlnode* identity_key_elem = NULL;
	xmlnode* signed_pre_key_elem = NULL;
	xmlnode* signed_pre_key_signature_elem = NULL;
	xmlnode* prekeys_elem = NULL;
	xmlnode* pre_key_elem = NULL;
	gchar* base64 = NULL;
	guint8* data = NULL;
	gsize data_len = 0;
	const gchar* id_str = NULL;
	guint32 pre_key_id = 0;
	ec_public_key* pre_key = NULL;
	

	dev_bundle = g_new0(device_bundle, 1);
	if (!dev_bundle) {
		purple_debug_error(PLUGIN_ID, _("Cannot allocate device_bundle\n"));
		retval = -1;
		goto cleanup;
	}

	// <identityKey>
	identity_key_elem = xmlnode_get_child(xml_bundle, "identityKey");
	if (!identity_key_elem) {
		purple_debug_error(PLUGIN_ID, _("Cannot find <identityKey/>\n"));
		retval = -1;
		goto cleanup;
	}
	base64 = xmlnode_get_data(identity_key_elem);
	if (!base64) {
		purple_debug_error(PLUGIN_ID, _("Cannot find data in <identityKey/>\n"));
		retval = -1;
		goto cleanup;
	}
	data = purple_base64_decode(base64, &data_len);
	curve_decode_point(&dev_bundle->identity_key_pub, data, data_len, global_context);
	g_free(data);
	g_free(base64);
	data = NULL;
	data_len = 0;
	base64 = NULL;

	// <signedPreKeyPublic>
	signed_pre_key_elem = xmlnode_get_child(xml_bundle, "signedPreKeyPublic");
	if (!signed_pre_key_elem) {
		purple_debug_error(PLUGIN_ID, _("Cannot find <signedPreKeyPublic/>\n"));
		retval = -1;
		goto cleanup;
	}
	id_str = xmlnode_get_attrib(signed_pre_key_elem, "signedPreKeyId");
	if (!id_str) {
		purple_debug_error(PLUGIN_ID,
			_("Cannot find attribute signedPreKeyId of <signedPreKeyPublic/>\n"));
		retval = -1;
		goto cleanup;
	}
	dev_bundle->signed_pre_key_id = g_ascii_strtoull(id_str, NULL, 10);
	id_str = NULL;

	base64 = xmlnode_get_data(signed_pre_key_elem);
	if (!base64) {
		purple_debug_error(PLUGIN_ID, _("Cannot find data in <signedPreKeyPublic/>\n"));
		retval = -1;
		goto cleanup;
	}
	data = purple_base64_decode(base64, &data_len);
	curve_decode_point(&dev_bundle->signed_pre_key_pub, data, data_len, global_context);
	g_free(data);
	g_free(base64);
	data = NULL;
	data_len = 0;
	base64 = NULL;

	// <signedPreKeySignature>
	signed_pre_key_signature_elem = xmlnode_get_child(xml_bundle, "signedPreKeySignature");
	if (!signed_pre_key_signature_elem) {
		purple_debug_error(PLUGIN_ID, _("Cannot find <signedPreKeySignature/>\n"));
		retval = -1;
		goto cleanup;
	}
	base64 = xmlnode_get_data(signed_pre_key_signature_elem);
	if (!base64) {
		purple_debug_error(PLUGIN_ID, _("Cannot find data in <signedPreKeySignature/>\n"));
		retval = -1;
		goto cleanup;
	}
	data = purple_base64_decode(base64, &data_len);
	dev_bundle->signed_pre_key_signature = signal_buffer_create(data, data_len);
	if (!dev_bundle->signed_pre_key_signature) {
		purple_debug_error(PLUGIN_ID, _("Cannot create buffer for signed_pre_key_signature\n"));
		retval = -1;
		goto cleanup;
	}
	g_free(data);
	g_free(base64);
	data = NULL;
	data_len = 0;
	base64 = NULL;

	// <prekeys>
	prekeys_elem = xmlnode_get_child(xml_bundle, "prekeys");
	if (!prekeys_elem) {
		purple_debug_error(PLUGIN_ID, _("Cannot find <prekeys/>\n"));
		retval = -1;
		goto cleanup;
	}
	pre_key_elem = xmlnode_get_child(prekeys_elem, "preKeyPublic");
	dev_bundle->pre_keys_pub = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, prekey_free);
	while (pre_key_elem) {
		id_str = xmlnode_get_attrib(pre_key_elem, "preKeyId");
		if (!id_str) {
			purple_debug_error(PLUGIN_ID, _("Cannot find attribute preKeyId of <PreKeyPublic/>\n"));
			retval = -1;
			goto cleanup;
		}
		pre_key_id = g_ascii_strtoull(id_str, NULL, 10);
		id_str = NULL;

		base64 = xmlnode_get_data(pre_key_elem);
		if (!base64) {
			purple_debug_error(PLUGIN_ID, _("Cannot find data in <PreKeyPublic/> with id=%s\n"),
				id_str);
			retval = -1;
			goto cleanup;
		}
		data = purple_base64_decode(base64, &data_len);
		curve_decode_point(&pre_key, data, data_len, global_context);
		g_free(data);
		g_free(base64);
		data = NULL;
		data_len = 0;
		base64 = NULL;

		g_hash_table_insert(dev_bundle->pre_keys_pub, GUINT_TO_POINTER(pre_key_id), pre_key);
		pre_key_id = 0;
		pre_key = NULL;

		pre_key_elem = xmlnode_get_next_twin(pre_key_elem);
	}

	*result = dev_bundle;

cleanup:
	if (retval && dev_bundle) device_bundle_free(dev_bundle);

	return retval;
}

void device_bundle_free(gpointer b)
{
	device_bundle* bundle = (device_bundle*) b;
	if (bundle->identity_key_pub) SIGNAL_UNREF(bundle->identity_key_pub);
	if (bundle->signed_pre_key_pub) SIGNAL_UNREF(bundle->signed_pre_key_pub);
	if (bundle->signed_pre_key_signature) signal_buffer_free(bundle->signed_pre_key_signature);
	if (bundle->pre_keys_pub) g_hash_table_destroy(bundle->pre_keys_pub);
	g_free(bundle);
}

static void prekey_free(gpointer data)
{
	SIGNAL_UNREF(data);
}
