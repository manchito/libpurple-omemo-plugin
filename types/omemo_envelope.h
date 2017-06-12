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
#ifndef OMEMO_ENVELOPE_H
#define OMEMO_ENVELOPE_H

#include <glib.h>
#include <xmlnode.h>

typedef struct omemo_envelope {
	guint32 rid;
	guint8* data;
	gsize data_len;
	/**
	 * TRUE if this is an envelope intended for a recipeint device of 
	 * the same account as the sender's. FALSE (unset) if unknown.
	 */
	gboolean is_own_device;
} omemo_envelope;

/**
 * @brief Creates an omemo_envelope
 * @param envelope a newly allocated omemo_envelope or unset on error. Must be freed with
 * omemo_envelope_free()
 * @param rid the device ID
 * @param data the binary data
 * @param data_len size of data
 * @param is_own_device TRUE if this is an envelope intended for a recipient device of the same
 * account as the sender's. FALSE (unset) if unknown
 * @return 0 on success
 */
int omemo_envelope_create(omemo_envelope** envelope,
	guint32 rid,
	guint8* data,
	gsize data_len,
	gboolean is_own_device);

/**
 * @brief Creates a <key> element out of an omemo_envelope
 * @param result a newly allocated XML node which must be xmlnode_free'd by the caller. Unset if
 * serialization fails
 * @param envelope the omemo_envelope to serialize
 * @return 0 on success
 */
int omemo_envelope_serialize(xmlnode** result, const omemo_envelope* envelope);

/**
 * @brief Creates an omemo_envelope out of a <key> element
 * @param result a newly allocated omemo_envelope which must be freed with omemo_envelope_free() 
 * by the caller. Unset if deserialization fails
 * @param xml_envelope the <key/> to deserialize
 * @return 0 on success
 */
int omemo_envelope_deserialize(omemo_envelope** result, const xmlnode* xml_envelope);

/**
 * @brief Copies an omemo_envelope
 * @param new_e a newly allocated copy of e. It muss be freed by
 * the caller with omemo_envelope_free()
 * @param e the envelope to duplicate
 * @return 0 on success
 */
int omemo_envelope_copy(omemo_envelope** new_e, const omemo_envelope* e);

void omemo_envelope_free(gpointer e);

#endif
