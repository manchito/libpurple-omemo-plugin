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
#ifndef DEVICE_BUNDLE_H
#define DEVICE_BUNDLE_H

#include <glib.h>
#include <signal_protocol.h>
#include <xmlnode.h>

typedef struct device_bundle {
	ec_public_key* identity_key_pub;
	guint32 signed_pre_key_id;
	ec_public_key* signed_pre_key_pub;
	signal_buffer* signed_pre_key_signature;
	GHashTable* pre_keys_pub;
} device_bundle;

/**
 * @brief Creates a device_bundle out of the current local storage of an account
 * @param bundle a newly allocated device_bundle which must be freed with device_bundle_free() by
 * the caller. Unset if creation fails
 * @param account the account to create the bundle for
 * @param global_context the Signal context
 * @return 0 on success
 */
int get_device_bundle(device_bundle** bundle,
	PurpleAccount* account,
	signal_context* global_context);

/**
 * @brief Creates a <bundle> element in the OMEMO_NS namespace out of a device_bundle
 * @param result a newly allocated XML node which must be xmlnode_free'd by the caller. Unset if
 * serialization fails
 * @param bundle the device_bundle to serialize
 * @param global_context the Signal context
 * @return 0 on success
 */
int device_bundle_serialize(xmlnode** result,
	const device_bundle* bundle,
	signal_context* global_context);

/**
 * @brief Creates a device_bundle out of a <bundle> element in the OMEMO_NS namespace
 * @param result a newly allocated device_bundle which must be freed by the caller. Unset if
 * deserialization fails
 * @param xml_bundle the <bundle/> to deserialize
 * @param global_context the Signal context
 * @return 0 on success
 */
int device_bundle_deserialize(device_bundle** result,
	const xmlnode* xml_bundle,
	signal_context* global_context);

void device_bundle_free(gpointer b);

static void prekey_free(gpointer data);

#endif
