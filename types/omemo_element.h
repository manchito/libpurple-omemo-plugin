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
#ifndef OMEMO_ELEMENT_H
#define OMEMO_ELEMENT_H

#include <glib.h>
#include <xmlnode.h>

#include "omemo_envelope.h"

typedef struct omemo_element {
	guint32 sid;
	guint8* iv;
	gsize iv_len;
	guint8* payload;
	gsize payload_len;
	/**
	 * A list of omemo_envelopes
	 */
	GList* envelopes;
} omemo_element;

/**
 * @brief Creates an omemo_element
 * @param element a newly allocated omemo_element or unset on error. Must be freed with
 * omemo_element_free()
 * @param sid the device ID of the sender
 * @param iv the initialization vector
 * @param iv_len size of the initialization vector
 * @return 0 on success
 */
int omemo_element_create(omemo_element** element, guint32 sid, guint8* iv, gsize iv_len);

/**
 * @brief Creates an <encrypted> element in the OMEMO_NS namespace out of an omemo_element
 * @param result a newly allocated XML node which must be xmlnode_free'd by the caller. Unset if
 * serialization fails
 * @param element the omemo_element to serialize
 * @return 0 on success
 */
int omemo_element_serialize(xmlnode** result, const omemo_element* element);

/**
 * @brief Creates an omemo_element out of an <encrypted> element in the OMEMO_NS namespace
 * @param result a newly allocated omemo_envelope which must be freed with omemo_element_free()
 * by the caller. Unset if deserialization fails
 * @param xml_element the <encrypted/> to deserialize
 * @return 0 on success
 */
int omemo_element_deserialize(omemo_element** result, const xmlnode* xml_element);

/**
 * @brief Gets a list of matching envelopes (<key> elements) in an OMEMO element for a given
 * recipient ID
 * @param rid the recipient ID
 * @param element the OMEMO element in which to look for matches
 * 
 * The returned list should be used as a read-only data structure. Only freeing the list (not its
 * elements!) is allowed, as they are direct references to the envelopes in the omemo_element.
 * 
 * @return a newly allocated list of omemo_envelope which musst be freed by the caller with
 * g_list_free()
 */
GList* omemo_element_get_matching(guint32 rid, const omemo_element* element);

/**
 * @brief Adds an envelope to the element
 * @param element the element
 * @param envelope the envelope
 */
void omemo_element_add_envelope(omemo_element* element, omemo_envelope* envelope);

/**
 * @brief Setst the payload
 * @param element the element
 * @param payload the encrypted payload
 */
void omemo_element_set_payload(omemo_element* element, guint8* payload, gsize payload_len);

/**
 * @brief Whether all envelopes are for other devices of the sender's account
 * @param element the OMEMO element
 * 
 * Utility method to determine whether an <message> is worth sending. If there aren't any devices
 * belonging to the intended recipient it doesn't make sense to send
 * 
 * @return TRUE if all the envelopes in element are for devices belonging to the sender or there are
 * no envelopes. FALSE otherwise
 */
gboolean omemo_element_own_devices_only(const omemo_element* element);

void omemo_element_free(gpointer e);

#endif
