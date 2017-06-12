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
#ifndef OMEMO_DEVICE_H
#define OMEMO_DEVICE_H

#include <glib.h>
#include <signal_protocol.h>

typedef enum {
	UNDECIDED = 2,
	TRUSTED = 1,
	UNTRUSTED = 0
} device_trust;

typedef enum {
	ACTIVE = 1,
	INACTIVE = 0
} device_status;

typedef struct omemo_device {
	guint32 id;
	gchar* jid;
	ec_public_key* identity_key_pub;
	session_record* session;
	device_trust trust;
	device_status status;
} omemo_device;

/**
 * @brief Creates a device
 * @param device a newly allocated omemo_device or unset on error. Must be freed with
 * omemo_device_free()
 * @param id the device ID
 * @param jid the Jabber ID of the device owner
 * @param pub_key the public identity key of the device in binary format. May be NULL
 * @param pub_key_len the size of the public identity key record
 * @param session_record the session of the device in binary format. May be NULL
 * @param session_record_len the size of the session record
 * @param trust the trust of the device
 * @param status the status of the device
 * @param global_context the Signal context for deserialization pub_key and session_record
 * @return 0 on success
 */
int omemo_device_create(omemo_device** device,
	guint32 id,
	const gchar* jid,
	const guint8* pub_key,
	gsize pub_key_len,
	const guint8* session_record,
	gsize session_record_len,
	device_trust trust,
	device_status status,
	signal_context* global_context);

void omemo_device_free(gpointer device);

#endif
