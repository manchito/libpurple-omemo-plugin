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
#ifndef SESSION_STORE_H
#define SESSION_STORE_H

#include <signal_protocol.h>

int load_session(signal_buffer** record, const signal_protocol_address* address, void* user_data);

int get_sub_device_sessions(signal_int_list** sessions,
	const char* name,
	size_t name_len,
	void* user_data);

int store_session(const signal_protocol_address* address,
	uint8_t* record,
	size_t record_len,
	void* user_data);

int contains_session(const signal_protocol_address* address, void* user_data);

int delete_session(const signal_protocol_address* address, void* user_data);

int delete_all_sessions(const char* name, size_t name_len, void* user_data);

void session_store_destroy(void* user_data);

#endif
