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

#include "omemo_envelope.h"

int omemo_envelope_create(omemo_envelope** envelope,
	guint32 rid,
	guint8* data,
	gsize data_len,
	gboolean is_own_device)
{
	int retval = 0;
	omemo_envelope* env = NULL;

	env = g_new0(omemo_envelope, 1);
	if (!env) {
		purple_debug_error(PLUGIN_ID, _("Cannot allocate omemo_envelope\n"));
		retval = -1;
		goto cleanup;
	}

	env->rid = rid;
	env->data = data;
	env->data_len = data_len;
	env->is_own_device = is_own_device;

	*envelope = env;

cleanup:
	if (retval && env) omemo_envelope_free(env);

	return retval;
}

int omemo_envelope_serialize(xmlnode** result, const omemo_envelope* envelope)
{
	xmlnode* xml_envelope = NULL;
	guchar* base64 = NULL;
	gchar* rid_str = NULL;

	xml_envelope = xmlnode_new("key");

	rid_str = g_strdup_printf("%u", envelope->rid);
	xmlnode_set_attrib(xml_envelope, "rid", rid_str);
	g_free(rid_str);
	rid_str = NULL;

	base64 = purple_base64_encode(envelope->data, envelope->data_len);
	xmlnode_insert_data(xml_envelope, base64, -1);
	g_free(base64);
	base64 = NULL;

	*result = xml_envelope;

	return 0;
}

int omemo_envelope_deserialize(omemo_envelope** result, const xmlnode* xml_envelope)
{
	int retval = 0;
	omemo_envelope* envelope = NULL;
	gchar* base64 = NULL;
	guint8* data = NULL;
	gsize data_len = 0;
	const gchar* rid_str = NULL;

	envelope = g_new0(omemo_envelope, 1);
	if (!envelope) {
		purple_debug_error(PLUGIN_ID, _("Cannot allocate omemo_envelope\n"));
		retval = -1;
		goto cleanup;
	}

	rid_str = xmlnode_get_attrib(xml_envelope, "rid");
	if (!rid_str) {
		purple_debug_error(PLUGIN_ID,
			_("Cannot find attribute rid of <key/>\n"));
		retval = -1;
		goto cleanup;
	}
	envelope->rid = g_ascii_strtoull(rid_str, NULL, 10);
	rid_str = NULL;

	base64 = xmlnode_get_data(xml_envelope);
	if (!base64) {
		purple_debug_error(PLUGIN_ID, _("Cannot find data in <key/>\n"));
		retval = -1;
		goto cleanup;
	}
	data = purple_base64_decode(base64, &data_len);
	envelope->data = data;
	envelope->data_len = data_len;
	g_free(base64);
	data = NULL;
	data_len = 0;
	base64 = NULL;

	*result = envelope;

cleanup:
	if (retval && envelope) omemo_envelope_free(envelope);

	return retval;
}

int omemo_envelope_copy(omemo_envelope** new_e, const omemo_envelope* e)
{
	int retval = 0;
	omemo_envelope* envelope = NULL;

	envelope = g_new0(omemo_envelope, 1);
	if (!envelope) {
		purple_debug_error(PLUGIN_ID, _("Cannot allocate omemo_envelope\n"));
		retval = -1;
		goto cleanup;
	}

	envelope->rid = e->rid;
	envelope->is_own_device = e->is_own_device;
	envelope->data = g_memdup(e->data, e->data_len);
	envelope->data_len = e->data_len;

	*new_e = envelope;

cleanup:
	if (retval && envelope) omemo_envelope_free(envelope);

	return retval;
}

void omemo_envelope_free(gpointer e)
{
	omemo_envelope* envelope = (omemo_envelope*) e;
	if (envelope->data) g_free(envelope->data);
	g_free(envelope);
}
