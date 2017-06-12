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

#include "omemo_device.h"

int omemo_device_create(omemo_device** device,
	guint32 id,
	const gchar* jid,
	const guint8* pub_key,
	gsize pub_key_len,
	const guint8* session_record,
	gsize session_record_len,
	device_trust trust,
	device_status status,
	signal_context* global_context)
{
	int retval = 0;
	omemo_device* dev = NULL;

	dev = g_new0(omemo_device, 1);
	if (!dev) {
		purple_debug_error(PLUGIN_ID, _("Cannot allocate memory for device\n"));
		retval = -1;
		goto cleanup;
	}

	dev->id = id;
	dev->jid = g_strdup_printf("%s", jid);

	dev->identity_key_pub = NULL;
	if (pub_key) {
		curve_decode_point(&dev->identity_key_pub, pub_key, pub_key_len, global_context);
	}

	dev->session = NULL;
	if (session_record) {
		session_record_deserialize(&dev->session, session_record, session_record_len,
			global_context);
	}

	dev->trust = trust;
	dev->status = status;

	*device = dev;

cleanup:
	if (retval && dev) omemo_device_free(dev);

	return retval;
}

void omemo_device_free(gpointer d)
{
	omemo_device* device = (omemo_device*) d;
	if (device->jid) g_free(device->jid);
	if (device->identity_key_pub) SIGNAL_UNREF(device->identity_key_pub);
	if (device->session) SIGNAL_UNREF(device->session);
	g_free(device);
}
