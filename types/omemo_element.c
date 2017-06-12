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

#include "omemo_element.h"

int omemo_element_create(omemo_element** element, guint32 sid, guint8* iv, gsize iv_len)
{
	int retval = 0;
	omemo_element* elem = NULL;

	elem = g_new0(omemo_element, 1);
	if (!elem) {
		purple_debug_error(PLUGIN_ID, _("Cannot allocate omemo_element\n"));
		retval = -1;
		goto cleanup;
	}

	elem->sid = sid;
	elem->iv = iv;
	elem->iv_len = iv_len;

	*element = elem;

cleanup:
	if (retval && elem) omemo_element_free(elem);

	return retval;
}

int omemo_element_serialize(xmlnode** result, const omemo_element* element)
{
	int retval = 0;
	xmlnode* xml_element = NULL;
	xmlnode* header_elem = NULL;
	xmlnode* key_elem = NULL;
	xmlnode* iv_elem = NULL;
	xmlnode* payload_elem = NULL;
	guchar* base64 = NULL;
	gchar* sid_str = NULL;
	GList* e = NULL;
	const omemo_envelope* envelope = NULL;

	xml_element = xmlnode_new("encrypted");
	xmlnode_set_namespace(xml_element, OMEMO_NS);

	// <header>
	header_elem = xmlnode_new_child(xml_element, "header");
	sid_str = g_strdup_printf("%u", element->sid);
	xmlnode_set_attrib(header_elem, "sid", sid_str);
	g_free(sid_str);
	sid_str = NULL;

	// <key>s
	for (e = element->envelopes; e; e = e->next) {
		envelope = (omemo_envelope*) e->data;
		omemo_envelope_serialize(&key_elem, envelope);
		if (!key_elem) {
			purple_debug_error(PLUGIN_ID, _("Cannot serialize omemo_element->envelopes\n"));
			retval = -1;
			goto cleanup;
		}
		xmlnode_insert_child(header_elem, key_elem);
		key_elem = NULL;
	}

	// <iv>
	iv_elem = xmlnode_new_child(header_elem, "iv");
	base64 = purple_base64_encode(element->iv, element->iv_len);
	xmlnode_insert_data(iv_elem, base64, -1);
	g_free(base64);
	base64 = NULL;

	// <payload>
	if (element->payload) {
		payload_elem = xmlnode_new_child(xml_element, "payload");
		base64 = purple_base64_encode(element->payload, element->payload_len);
		xmlnode_insert_data(payload_elem, base64, -1);
		g_free(base64);
		base64 = NULL;
	}

	*result = xml_element;

cleanup:
	if (retval && xml_element) xmlnode_free(xml_element);

	return retval;
}

int omemo_element_deserialize(omemo_element** result, const xmlnode* xml_element)
{
	int retval = 0;
	omemo_element* element = NULL;
	xmlnode* header_elem = NULL;
	xmlnode* iv_elem = NULL;
	xmlnode* payload_elem = NULL;
	xmlnode* key_elem = NULL;
	gchar* base64 = NULL;
	guint8* data = NULL;
	gsize data_len = 0;
	const gchar* sid_str = NULL;
	omemo_envelope* envelope = NULL;

	element = g_new0(omemo_element, 1);
	if (!element) {
		purple_debug_error(PLUGIN_ID, _("Cannot allocate omemo_element\n"));
		retval = -1;
		goto cleanup;
	}

	header_elem = xmlnode_get_child(xml_element, "header");
	if (!header_elem) {
		purple_debug_error(PLUGIN_ID, _("Cannot find <header>\n"));
		retval = -1;
		goto cleanup;
	}

	// sid
	sid_str = xmlnode_get_attrib(header_elem, "sid");
	if (!sid_str) {
		purple_debug_error(PLUGIN_ID,
			_("Cannot find attribute sid of <header/>\n"));
		retval = -1;
		goto cleanup;
	}
	element->sid = g_ascii_strtoull(sid_str, NULL, 10);
	sid_str = NULL;

	// iv
	iv_elem = xmlnode_get_child(header_elem, "iv");
	if (!iv_elem) {
		purple_debug_error(PLUGIN_ID, _("Cannot find <iv/>\n"));
		retval = -1;
		goto cleanup;
	}
	base64 = xmlnode_get_data(iv_elem);
	if (!base64) {
		purple_debug_error(PLUGIN_ID, _("Cannot find data in <iv/>\n"));
		retval = -1;
		goto cleanup;
	}
	data = purple_base64_decode(base64, &data_len);
	element->iv = data;
	element->iv_len = data_len;
	g_free(base64);
	data = NULL;
	data_len = 0;
	base64 = NULL;

	// payload
	payload_elem = xmlnode_get_child(xml_element, "payload");
	if (payload_elem) {
		base64 = xmlnode_get_data(payload_elem);
		if (!base64) {
			purple_debug_error(PLUGIN_ID, _("Cannot find data in <payload/>\n"));
			retval = -1;
			goto cleanup;
		}
		data = purple_base64_decode(base64, &data_len);
		element->payload = data;
		element->payload_len = data_len;
		g_free(base64);
		data = NULL;
		data_len = 0;
		base64 = NULL;
	}

	// envelopes
	for (key_elem = xmlnode_get_child(header_elem, "key"); key_elem;
		key_elem = xmlnode_get_next_twin(key_elem)) {
		omemo_envelope_deserialize(&envelope, key_elem);
		if (!envelope) {
			purple_debug_error(PLUGIN_ID, _("Cannot deserialize <key> element\n"));
			retval = -1;
			goto cleanup;
		}
		element->envelopes = g_list_prepend(element->envelopes, envelope);
	}
	element->envelopes = g_list_reverse(element->envelopes);

	*result = element;

cleanup:
	if (retval && element) omemo_element_free(element);

	return retval;
}

GList* omemo_element_get_matching(guint32 rid, const omemo_element* element)
{
	GList* result = NULL;
	GList* e = NULL;
	omemo_envelope* envelope = NULL;

	for (e = element->envelopes; e; e = e->next) {
		envelope = (omemo_envelope*) e->data;
		if (envelope->rid == rid) {
			result = g_list_prepend(result, envelope);
		}
	}
	result = g_list_reverse(result);

	return result;
}

void omemo_element_add_envelope(omemo_element* element, omemo_envelope* envelope)
{
	element->envelopes = g_list_prepend(element->envelopes, envelope);
}

void omemo_element_set_payload(omemo_element* element, guint8* payload, gsize payload_len)
{
	element->payload = payload;
	element->payload_len = payload_len;
}

gboolean omemo_element_own_devices_only(const omemo_element* element)
{
	GList* e = NULL;
	omemo_envelope* envelope = NULL;

	for (e = element->envelopes; e; e = e->next) {
		envelope = (omemo_envelope*) e->data;
		if (!envelope->is_own_device)
			return FALSE;
	}

	return TRUE;
}

void omemo_element_free(gpointer e)
{
	omemo_element* element = (omemo_element*) e;
	if (element->iv) g_free(element->iv);
	if (element->payload) g_free(element->payload);
	if (element->envelopes) g_list_free_full(element->envelopes, omemo_envelope_free);
	g_free(element);
}
