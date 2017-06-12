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

#include "device_list.h"

int device_list_create(device_list** list)
{
	int retval = 0;
	device_list* l = NULL;

	l = g_new0(device_list, 1);
	if (!l) {
		purple_debug_error(PLUGIN_ID, _("Cannot allocate device_list\n"));
		retval = -1;
		goto cleanup;
	}

	l->ids = g_hash_table_new(g_direct_hash, g_direct_equal);

	*list = l;

cleanup:
	if (retval && l) device_list_free(l);

	return retval;
}

int device_list_serialize(xmlnode** result, const device_list* list)
{
	int retval = 0;
	xmlnode* xml_list = NULL;
	xmlnode* device_elem = NULL;
	gchar* id_str = NULL;
	GList* start = NULL;
	GList* i = NULL;
	guint32 id = 0;

	xml_list = xmlnode_new("list");
	xmlnode_set_namespace(xml_list, OMEMO_NS);

	start = g_hash_table_get_keys(list->ids);
	for (i = start; i != NULL; i = i->next) {
		id = GPOINTER_TO_UINT(i->data);
		id_str = g_strdup_printf("%u", id);
		device_elem = xmlnode_new_child(xml_list, "device");
		xmlnode_set_attrib(device_elem, "id", id_str);
		g_free(id_str);
		id_str = NULL;
		id = 0;
	}

	*result = xml_list;

cleanup:
	if (start) g_list_free(start);
	if (retval && xml_list) xmlnode_free(xml_list);

	return retval;
}

int device_list_deserialize(device_list** result, const xmlnode* xml_list)
{
	int retval = 0;
	device_list* list = NULL;
	xmlnode* device_elem = NULL;
	const gchar* id_str = NULL;

	device_list_create(&list);
	if (!list) {
		purple_debug_error(PLUGIN_ID, _("Cannot create device_list\n"));
		retval = -1;
		goto cleanup;
	}

	for (device_elem = xmlnode_get_child(xml_list, "device"); device_elem;
		device_elem = xmlnode_get_next_twin(device_elem)) {
		id_str = xmlnode_get_attrib(device_elem, "id");
		if (!id_str) {
			purple_debug_error(PLUGIN_ID, _("Cannot find attribute id of <device/>\n"));
			retval = -1;
			goto cleanup;
		}
		device_list_add(list, g_ascii_strtoull(id_str, NULL, 10));
		id_str = NULL;
	}

	*result = list;

cleanup:
	if (retval && list) device_list_free(list);

	return retval;
}

gboolean device_list_add(device_list* list, guint32 id)
{
	return g_hash_table_add(list->ids, GUINT_TO_POINTER(id));
}

gboolean device_list_remove(device_list* list, guint32 id)
{
	return g_hash_table_remove(list->ids, GUINT_TO_POINTER(id));
}

gboolean device_list_contains(const device_list* list, guint32 id)
{
	return g_hash_table_contains(list->ids, GUINT_TO_POINTER(id));
}

GList* device_list_get_ids(const device_list* list)
{
	/* This is inefficient (we iterate over the IDs here and the caller might iterate again on the
	 * returned list), but consistent with hiding the underlying GHashTable of device_list
	 */
	return g_hash_table_get_keys(list->ids);
}

void device_list_free(gpointer l)
{
	device_list* list = (device_list*) l;
	if (list->ids) g_hash_table_destroy(list->ids);
	g_free(list);
}
