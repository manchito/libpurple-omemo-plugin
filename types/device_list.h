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
#ifndef DEVICE_LIST_H
#define DEVICE_LIST_H

#include <glib.h>
#include <xmlnode.h>

typedef struct device_list {
	GHashTable* ids;
} device_list;

/**
 * @brief Creates an empty device_list
 * @param element a newly allocated device_list or unset on error. Must be freed with
 * device_list_free()
 * @return 0 on success
 */
int device_list_create(device_list** list);

/**
 * @brief Creates a <list> element in the OMEMO_NS namespace out of a device_list
 * @param result a newly allocated XML node which must be xmlnode_free'd by the caller. Unset if
 * serialization fails
 * @param list the device_list to serialize
 * @return 0 on success
 */
int device_list_serialize(xmlnode** result, const device_list* list);

/**
 * @brief Creates an omemo_element out of a <list> element in the OMEMO_NS namespace
 * @param result a newly allocated device_list which must be freed with device_list_free()
 * by the caller. Unset if deserialization fails
 * @param xml_list the <list/> to deserialize
 * @return 0 on success
 */
int device_list_deserialize(device_list** result, const xmlnode* xml_list);

/**
 * @brief Adds a device ID to the list
 * @param list the device list to add the ID to
 * @param id the ID to add
 * @return TRUE if the ID did not exist yet
 */
gboolean device_list_add(device_list* list, guint32 id);

/**
 * @brief Removes a device ID from the list
 * @param list the device list to remove the ID from
 * @param id the ID to remove
 * @return TRUE if the ID was found and removed from the list
 */
gboolean device_list_remove(device_list* list, guint32 id);

/**
 * @brief Checks if a given device ID is in the list
 * @param list the device list to look into
 * @param id the ID to look for
 * @return TRUE if the ID is in the list. FALSE otherwise.
 */
gboolean device_list_contains(const device_list* list, guint32 id);

/**
 * @brief Gets the Device IDs contained in list
 * @param list the device list
 * 
 * Use this if you want to iterate over the elements in the device list.
 * Modifications on the returned list have no effect upon the original device_list.
 * 
 * @return a newly allocated list of guint32 in form of pointers. Must be g_freed.
 */
GList* device_list_get_ids(const device_list* list);

void device_list_free(gpointer l);

#endif
