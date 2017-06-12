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
#ifndef OMEMO_STORE_H
#define OMEMO_STORE_H

#include <glib.h>
#include <sqlite3.h>

/**
 * @brief Stores own identity in local storage
 * @param registration_id the generated registration ID
 * @param identity_key_pair the key pair to be used for the current device, consisting of a public and a private key
 * @param db a valid SQLite3 DB handle
 * 
 * Stores the indentity keys in the DB. This function is meant to be called once at Signal install time only.
 * 
 * @return 0 on success. Not 0 otherwise
 */
int store_local_identity_key_pair(uint32_t registration_id, ratchet_identity_key_pair* identity_key_pair, sqlite3* db);

/**
 * @brief Inserts a new contact to the local storage
 * @param jid device owner
 * @param db a valid SQLite handler
 * 
 * @return 0 on success
 */
int add_contact(gchar* jid, sqlite3* db);

/**
 * @brief Inserts a new device tuple to the local storage
 * @param jid device owner
 * @param id device ID
 * @param db a valid SQLite handler
 * 
 * @return 0 on success
 */
int add_device_tuple(gchar* jid, guint32 id, sqlite3* db);

/**
 * @brief Checks whether encryption with a contact is active
 * @param jid the Jabber ID of the contact (full or bare)
 * @param db a valid SQLite handler
 * 
 * @return TRUE if active, FALSE otherwise
 */
gboolean encryption_is_enabled(const gchar* jid, sqlite3* db);

/**
 * @brief Checks whether a JID is present in the local storage
 * @param jid device owner
 * @param db a valid SQLite handler
 */
gboolean contact_exists(gchar* jid, sqlite3* db);

/**
 * @brief Checks whether a device tuple (active or not) is in local storage
 * @param jid device owner
 * @param id device ID
 * @param db a valid SQLite handler
 */
gboolean device_tuple_exists(gchar* jid, guint32 id, sqlite3* db);

/**
 * @brief Sets the public key for a device
 * @param jid device owner
 * @param id device ID
 * @param key the public key
 * @param key_len the length of the public key in bytes
 * @param db a valid SQLite handler
 * @return 0 on success
 */
int set_device_public_key(gchar* jid, guint32 id, guint8* key, gsize key_len, sqlite3* db);

/**
 * @brief Sets the status of a device
 * @param jid device owner
 * @param id device ID
 * @param status the new status to set (ACTIVE or INACTIVE)
 * @param db a valid SQLite handler
 * @return 0 on success
 */
static int set_device_status(gchar* jid, guint32 id, device_status status, sqlite3* db);

/**
 * @brief Marks a device as active
 * @param jid device owner
 * @param id device ID
 * @param db a valid SQLite handler
 * @return 0 on success
 */
int activate_device(gchar* jid, guint32 id, sqlite3* db);

/**
 * @brief Marks a device as inactive
 * @param jid device owner
 * @param id device ID
 * @param db a valid SQLite handler
 * @return 0 on success
 */
int deactivate_device(gchar* jid, guint32 id, sqlite3* db);

/**
 * @brief Gets a list of active devices whose status in local storage is UNDECIDED for a given JID
 * @param jid owner of the devices to look for
 * @param global_context the Signal context
 * @param db a valid SQLite handler
 * @return a list of omemo_device which must be freed by the caller. If none is found or an error
 * occurs the list will be empty (NULL). The contained devices must also be freed when they are not
 * needed anymore.
 */
GList* get_undecided_devices(gchar* jid, signal_context* global_context, sqlite3* db);

/**
 * @brief Gets a list of active devices without a session for a given JID
 * @param jid owner of the devices to look for
 * @param global_context the Signal context
 * @param db a valid SQLite handler
 * @return a list of omemo_device which must be freed by the caller. If none is found or an error
 * occurs the list will be empty (NULL). The contained devices must also be freed when they are not
 * needed anymore.
 */
GList* get_devices_without_sessions(gchar* jid, signal_context* global_context, sqlite3* db);

/**
 * @brief Gets a list of active trusted devices with a session established for a given JID
 * @param jid owner of the devices to look for
 * @param global_context the Signal context
 * @param db a valid SQLite handler
 * @return a list of omemo_device which must be freed by the caller. If none is found or an error
 * occurs the list will be empty (NULL). The contained devices must also be freed when they are not
 * needed anymore.
 */
GList* get_devices_ready_to_receive(gchar* jid, signal_context* global_context, sqlite3* db);

/**
 * @brief Gets a list of ALL devices for a given JID
 * @param jid owner of the devices to look for
 * @param global_context the Signal context
 * @param db a valid SQLite handler
 * 
 * It returns all of the devices under the given Jabber ID no matter their status, trust or session
 * 
 * @return a list of omemo_device which must be freed by the caller. If none is found or an error
 * occurs the list will be empty (NULL). The contained devices must also be freed when they are not
 * needed anymore.
 */
GList* get_all_devices_for_contact(gchar* jid, signal_context* global_context, sqlite3* db);

/**
 * @brief Whether the local device is published
 * @param db a valid SQLite handler
 * 
 * The device is considered published if its ID has been uploaded to the remote device list. It is
 * considered unpublished after initialization of the DB and before the first time it is published.
 * Also after being removed from the remote device list (e.g. after unpublish_device).
 * 
 * @return TRUE if the local device is published. FALSE otherwise
 */
gboolean is_own_device_published(sqlite3* db);

/**
 * @brief Mark the local device as published/unpublished
 * @param published TRUE if the local device should be marked as published. FALSE if it should be
 * marked as unpublished
 * @param db a valid SQLite handler
 * 
 * @return 0 on success
 */
int set_own_device_published(gboolean published, sqlite3* db);

/**
 * @brief Gets the current version of the DB schema of the local store
 * @param db a valid SQLite handler
 * 
 * @return the value of the user-version SQLite3 pragma as a positive integer. Negative on failure
 */
int get_db_version(sqlite3* db);

#endif
