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
#ifndef OMEMO_H
#define OMEMO_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef PURPLE_PLUGINS
#define PURPLE_PLUGINS
#endif

#include <glib.h>

#define GETTEXT_PACKAGE "core-mancho-omemo"
#include <glib/gi18n-lib.h>

#ifndef G_GNUC_NULL_TERMINATED
#if __GNUC__ >= 4
#define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#else
#define G_GNUC_NULL_TERMINATED
#endif
#endif

#include <account.h>
#include <connection.h>
#include <plugin.h>
#include <signal_protocol.h>
#include <sqlite3.h>
#include <xmlnode.h>

#include "jabber/jabber.h"
#include "jabber/pep.h"
#include "types/omemo_device.h"
#include "types/device_bundle.h"
#include "types/device_list.h"

#define PLUGIN_ID "core-mancho-omemo"
#define PLUGIN_AUTHOR "Germán Márquez Mejía <marquez.mejia@fu-berlin.de>"
#define PROTO_XMPP "prpl-jabber"
#define OMEMO_DIR "omemo"
#define DB_SCHEMA "2"
#define DB_ID_LEN 16
#define OPTIMAL_PRE_KEY_COUNT 100
#define SETTINGS_DB_ID "omemo-db-id"
//#define OMEMO_NS "urn:xmpp:omemo:0"
//#define OMEMO_DEVICELIST_NS OMEMO_NS ":devicelist"
//#define OMEMO_BUNDLES_NS_PREFIX OMEMO_NS ":bundles:"
#define OMEMO_NS "eu.siacs.conversations.axolotl"
#define OMEMO_DEVICELIST_NS OMEMO_NS ".devicelist"
#define OMEMO_BUNDLES_NS_PREFIX OMEMO_NS ".bundles:"
#define OMEMO_FEATURE_VAR OMEMO_DEVICELIST_NS "+notify"
#define NS_HINTS "urn:xmpp:hints"
#define NS_EME "urn:xmpp:eme:0"
#define CIPHER_MODE_GCM 3562
#define OMEMO_PAYLOAD_SECRET_LEN 16 // AES-128-GCM
#define OMEMO_PAYLOAD_IV_LEN 16 // AES blocksize
#define SIGNED_PRE_KEY_DAYS_TO_RENEW 7
#define SIGNED_PRE_KEY_DAYS_TO_DELETE 30

// Plugin API
static void init_plugin(PurplePlugin* plugin);

static gboolean plugin_load(PurplePlugin* plugin);

static gboolean plugin_unload(PurplePlugin* plugin);

// Signal
/**
 * @brief Create a Signal data store context and add all the callbacks to it
 * @param db a valid SQLite3 DB handle
 * @return a newly allocated store context or NULL on failure. Must be freed the caller with
 * signal_protocol_store_context_destroy() when not needed anymore
 */
static signal_protocol_store_context* signal_store_context_create(sqlite3* db);

/**
 * @brief Installs OMEMO for an account if needed
 * @param a the account
 * @return 0 on success
 */
int omemo_account_setup(PurpleAccount* a);

/**
 * @brief Deactivates an account removing its PEP information
 * @param a the account
 * 
 * This functions doesn't delete or alter the OMEMO local storage
 * 
 * @return 0 on success
 */
int omemo_account_undo_announce(PurpleAccount* a);

/**
 * @brief Creates and initializes the OMEMO DB
 * @param account the account for which the DB will be created
 * @param db_id the the ID with which to create the DB
 * 
 * Initializes Signal elements (key pair, prekeys, signed prekeys, etc.), stores them in a newly
 * created database and announces this new device over PEP for the first time
 * 
 * @return 0 on success
 */
int omemo_install(PurpleAccount* account, const char* db_id);

/**
 * @brief Checks if a DB migration is necessary and if so performs it
 * @param account the account for which the DB will be checked/migrated
 * 
 * @return 0 on success
 */
int migrate_db(PurpleAccount* account);

/**
 * @brief Builds a Signal session
 * @param account the current account
 * @param jid the Jabber ID of the session partner
 * @param device_id the device ID of the session partner
 * @param omemo_bundle the pre key bundle to build the session from
 * @return 0 on success
 */
int build_session(PurpleAccount* account,
	gchar* jid,
	guint32 device_id,
	device_bundle* omemo_bundle);

/**
 * @brief Decrypts a pre key message using a newly built session for a given sender device
 * @param account the account receiving the message
 * @param plaintext newly allocated plaintext containing the result of the decryption. Unset if
 * decryption fails. It must be g_freed by the caller
 * @param len size of plaintext
 * @param sender_jid the Jabber ID of the sender
 * @param sid device ID of the sender
 * @param pre_key_message the pre key message to decrypt
 * @return 0 on success. If the actual decryption process fails, the error codes are the ones thrown
 * by session_cipher_decrypt_pre_key_signal_message(). See the Signal documentation.
 */
int decrypt_pre_key_message(PurpleAccount* account,
	guint8** plaintext,
	gsize* len,
	gchar* sender_jid,
	guint32 sid,
	pre_key_signal_message* pre_key_message);

/**
 * @brief Decrypts a Signal message using the session in store for a given sender device
 * @param account the account receiving the message
 * @param plaintext newly allocated plaintext containing the result of the decryption. Unset if
 * decryption fails. It must be g_freed by the caller
 * @param len size of plaintext
 * @param sender_jid the Jabber ID of the sender
 * @param sid device ID of the sender
 * @param signal_message the Signal message to decrypt
 * @return 
 */
int decrypt_signal_message(PurpleAccount* account,
	guint8** plaintext,
	gsize* len,
	gchar* sender_jid,
	guint32 sid,
	signal_message* signal_message);

/**
 * @brief Subscribe to PEP notifications from contacts
 * 
 * Adds a feature to the entity capabilities reported to the server. If called after at least one
 * Jabber account is connected, it will have no effect.
 */
void subscribe_to_devicelist_updates(void);

// Callbacks
/**
 * @brief Intercepts only outgoing message stanzas
 */
static void stanza_sending_cb(PurpleConnection* gc, xmlnode** stanza);

static void message_sending_cb(PurpleConnection* gc,
	const char* type,
	const char* id,
	const char* from,
	const char* to,
	xmlnode** message);

static gboolean message_receiving_cb(PurpleConnection* gc,
	const char* type,
	const char* id,
	const char* from,
	const char* to,
	xmlnode* message);

/**
 * @brief Action on receiving PEP device list updates
 * 
 * If a local device ID is no longer in the received list this function will set it to inactive.
 * If it is, this function will either add it to local storage or set it to active if it is a known
 * device that re-appears.
 */
static void device_list_update_cb(JabberStream *js, const char *from, xmlnode *items);

static void account_added_cb(PurpleAccount* account);

static void account_enabled_cb(PurpleAccount* account);

static void account_removed_cb(PurpleAccount* account);

static void account_disabled_cb(PurpleAccount* account);

static void account_signed_on_cb(PurpleAccount* account);

static void account_authorization_granted_cb(PurpleAccount* account, const char* user);


/**
 * @brief Transforms am OMEMO message into a normal plaintext <message/>
 * @param account the account
 * @param message a <message> element with an <encrypted/> OMEMO Element
 * 
 * Adds a <body/> containing the decrypted plaintext found in the payload of the <encrypted> OMEMO
 * element. When receiving as part of an emitted signal, if this function returns TRUE, the caller
 * should make sure that the message Stanza is not processed further
 * 
 * @return TRUE if the function processed this stanza and *nobody else* should process it. FALSE
 * otherwise
 */
gboolean decrypt_message(PurpleAccount* account, xmlnode* message);

// PEP
/**
 * @brief Publish device bundle via PEP
 * @param account the bundle's account
 * 
 * Publishes/Updates the PEP node for this device's bundle.
 * 
 * This function works asynchronously.
 */
void publish_bundle(PurpleAccount* account);

/**
 * @brief Remove own bundle node from PEP
 * @param account the bundle's account
 * 
 * This function works asynchronously.
 */
void unpublish_bundle(PurpleAccount* account);

/**
 * @brief Publish the current device onto the device list of account via PEP
 * @param account the device's account
 * 
 * Publishes/Updates a device list with the device ID for this account. This function modifies
 * the device list only if the device ID to be added is not already on it.
 * If no PEP device list node is found, it will be created.
 * 
 * This function works asynchronously.
 */
void publish_device(PurpleAccount* account);

/**
 * @brief Remove the current device from the remote device list
 * @param account the device's account
 * 
 * Removes the device ID for this account, efectively making it inactive. This function modifies
 * the device list only if it contains the device ID to be removed. If no PEP device list node is
 * found, nothing is done.
 * 
 * This function works asynchronously.
 */
void unpublish_device(PurpleAccount* account);

/**
 * @brief Callback for publish_device()
 */
static void unpublish_device_end(JabberStream* js, const char* from, xmlnode* items);

/**
 * @brief Adds the own device ID to the remote device list if necessary
 * @param js the stream of the own account
 * @param from the own Jabber ID
 * @param items the currently published device list
 * 
 * This function modifies the device list only if the device ID to be added is not already on it.
 * If items is NULL a new device list containing only the own device ID will be published.
 * 
 * This function checks whether it is publishing a freshly generated Device ID for the first time.
 * If so, it detects possible ID conflicts and triggers a complete new account setup if necessary. 
 */
static void update_device_list(JabberStream *js, const char *from, xmlnode* items);

/**
 * @brief Fetches the PEP node with the device list for a given contact
 * @param account the account on behalf of which to send the request
 * @param jid the Jabber ID of the list's owner. NULL for the account's server
 * @param cb a callback function to process the list
 * 
 * Usually the callback function will want to parse the <items> element with
 * get_device_list_from_items()
 */
static void fetch_device_list(PurpleAccount* account, const gchar* jid, JabberPEPHandler cb);

/**
 * @brief Publishes a device_list via PEP
 * @param account the account to which the PEP node will belong
 * @param list the device list to publish
 */
static void push_device_list(PurpleAccount* account, const device_list* list);

/**
 * @brief Fetches the PEP node with the bundle for a given device
 * @param account the account on behalf of which to send the request
 * @param jid the Jabber ID of the bundle's owner. NULL for the account's server
 * @param device_id the device ID of the requested bundle
 * @param cb a callback function to process the bundle
 * 
 * Usually the callback function will want to parse the <items> element with get_bundle_from_items()
 */
static void fetch_bundle(PurpleAccount* account, const gchar* jid, guint32 device_id, JabberPEPHandler cb);

/**
 * @brief Publishes a device_bundle via PEP
 * @param account the account to which the PEP node will belong
 * @param bundle the bundle to publish
 */
static void push_bundle(PurpleAccount* account, const device_bundle* bundle);

/**
 * @brief Generates the plaintext <body/> of a MessageElement
 * @param message the <message> element
 * @param ciphertext the encrypted payload
 * @param ciphertext_len the length of the encrypted payload in bytes
 * @param decryption_data containing a 128 bits decryption key and an authentication tag appended to
 * it
 * @param decryption_data_len the length of the decryption data in bytes if this is <= 16 the
 * behavior is undefined
 * @param iv the initialization vector to be used when decrypting
 * @param iv_len the length of the initialization vector
 * 
 * Modifies the <message> element including the resulting plaintext <body/>. Overwrites any
 * existent <body/> in <message/>
 * 
 * @return TRUE if the message should be discarded. FALSE otherwise
 */
gboolean process_message_element(xmlnode* message,
	guint8* ciphertext,
	gsize ciphertext_len,
	guint8* decryption_data,
	gsize decryption_data_len,
	guint8* iv,
	gsize iv_len);

/**
 * @brief Prepares devices and session prior to sending an encrypted message
 * @param account the account sending the message
 * @param from Jabber ID of the sender (us)
 * @param to Jabber ID of the intended recipient
 * 
 * Checks whether there are trust decisions to make before sending a message and triggers the
 * building of missing sessions with trusted devices
 * 
 * @return 0 on success
 */
int prepare_encryption(PurpleAccount* account, const char* from, const char* to);

/**
 * @brief Builds missing Signal sessions
 * @param account the sender's account
 * @param recipient_jid the Jabber ID of the intended recipient (may even be the account owner)
 * 
 * For a given contact, this function acts asynchronously fetching the bundles of its devices which
 * do not have an active Signal session yet and then establishing one.
 */
void build_missing_sessions(PurpleAccount* account, const gchar* recipient_jid);

/**
 * @brief Callback for build_missing_sessions()
 */
static void build_missing_sessions_end(JabberStream *js, const char *from, xmlnode *items);

/**
 * @brief Transforms a normal <message/> in an OMEMO message
 * @param account the account
 * @param message a <message> element with <body/>
 * 
 * Removes the <body/> and adds an <encrypted> OMEMO element with the encrypted payload and a
 * corresponding <header/>. If this function fails, the caller should make sure that the message
 * Stanza is not sent.
 * 
 * @return 0 on success
 */
int encrypt_message(PurpleAccount* account, xmlnode* message);

/**
 * @brief Encrypts a plaintext into a (PreKey)SignalMessage using the corresponding Signal session
 * for a given device
 * @param data a newly allocated binary serialized (PreKey)SignalMessage or unset on error. Mus be
 * g_freed by the caller
 * @param data_len size of the resulting Signal message
 * @param plaintext the data to be encrypted into the message
 * @param plaintext_len size of the data
 * @param jid the Jabber ID of the intended recipient
 * @param device the device ID of the intended recipient
 * @param db a valid SQLite3 DB handle
 * @return 0 on success
 */
int new_signal_message(guint8** data,
	gsize* data_len,
	const guint8* plaintext,
	gsize plaintext_len,
	gchar* jid,
	guint32 device_id,
	sqlite3* db);

/**
 * @brief Generate new prekeys if necessary
 * @param account the account for which to generate the prekeys
 */
void refill_pre_keys(PurpleAccount* account);

/**
 * @brief Generate a new signed prekey and delete old ones if necessary
 * @param account the account for which to perform the signed prekey update
 */
void update_signed_pre_keys(PurpleAccount* account);

/**
 * @brief Generates a new signed prekey
 * @param id the id of the new signed prekey
 * @param db a valid SQLite3 DB handle
 * 
 * @return 0 on success
 */
int generate_signed_pre_key(guint32 id, sqlite3* db);

/**
 * @brief Generates and stores new prekeys
 * @param from_id the id of the first prekey
 * @param count the number of prekeys to generate
 * @param db a valid SQLite3 DB handle
 * 
 * If (from_id + count - 1 > G_MAXUINT16) the behavior is undefined
 * 
 * @return 0 on success
 */
int generate_prekeys(guint32 from_id, guint32 count, sqlite3* db);

/**
 * @brief Rebuilds an otherwise invalid session notifies the affected device
 * @param account the account
 * @param jid the Jabber ID of the device owner
 * @param device_id the device ID with which to rebuild the session
 * 
 * Notifies the device sending a key transport element with a pre-key-envelope in a <message/>
 * 
 * This function works asynchronously
 */
void rebuild_session(PurpleAccount* account, const gchar* jid, guint32 device_id);

/**
 * @brief Callback for rebuild_session()
 */
static void rebuild_session_end(JabberStream *js, const char *from, xmlnode *items);

/**
 * @brief Sends an OMEMO ratchet update message to a specific device of a contact
 * @param account the account to send the message from
 * @param to the intended recipient
 * @param device_id the ID of the intended device
 */
void send_ratchet_update_message(PurpleAccount* account, const gchar* to, guint32 device_id);

// Utility functions
/**
 * @brief Parses a PEP response into a device_list
 * @param items the <items> element of a PEP response containing the device list node
 * @return the device_list or NULL if parsing failed
 */
device_list* get_device_list_from_items(xmlnode *items);

/**
 * @brief Parses a PEP response into a device_bundle
 * @param items the <items> element of a PEP response containing the device bundle node
 * @device_id if not NULL, the device ID of the bundle will be returned here
 * @return the device_bundle or NULL if parsing failed
 */
device_bundle* get_bundle_from_items(xmlnode *items, guint32* device_id);

/**
 * @brief Checks whether a key element content is a PreKeyMessage
 * @param data the key element content
 * @param len size of data
 * @param message the deserialized PreKeyMessage. Unset if data is not a PreKeyMessage
 * 
 * @return TRUE if data is a PreKeyMessage
 */
gboolean is_pre_key_message(const guint8* data, gsize len, pre_key_signal_message** message);

/**
 * @brief Get an open database handle for an account
 * @param db pointer that will be allocated to a valid DB handle. It must be closed by the caller
 * 	when it's not needed anymore
 * @param account the account
 * 
 * After calling this function db will point to a valid database handle unless Signal has not yet
 * been installed for the account or an error occurs, in which case db will be NULL
 */
void get_omemo_db_for_account(sqlite3** db, PurpleAccount* account);

/**
 * @brief Get the path of the OMEMO DB for a given ID
 * @param db_id the database ID from SETTINGS_DB_ID
 * @return a newly allocated path of the form <purple_user_dir>/omemo/<db_id>.sqlite which must be
 * freed with g_free()
 */
gchar* get_db_path(const gchar* db_id);

static void signal_lock_func(void* user_data);

static void signal_unlock_func(void* user_data);

/**
 * @brief Generates a random alphanumeric null terminated string
 * @param len the number of alphanumeric characters to generate
 * 
 * @return a newly allocated string of len random alphanumeric characters ([a-z][0-9]).
 * Must be g_free'd by the caller
 */
gchar* rand_string(gsize len);

/**
 * @brief Empty data of a node
 * @param node the node
 * 
 * This function is not offered by xmlnode.h.
 * Taken from https://github.com/segler-alex/Pidgin-GPG/blob/master/src/pidgin-gpg.c
 */
void xmlnode_clear_data(xmlnode* node);

/**
 * @brief Detaches a node from its parent and frees it
 * @param node the node to be removed
 * 
 * Like xmlnode_free() but removes the node from its parent before that.
 * 
 * This function is not offered by xmlnode.h.
 */
void xmlnode_remove(xmlnode* node);

/**
 * @brief Gets the next node on the same level as node
 * @param node the node for which to look for a sibling
 * @return the next sibling of node or NULL
 * 
 * This function is not offered by xmlnode.h. 
 */
xmlnode* xmlnode_get_next_sibling(xmlnode* node);

/**
 * @brief Random generator using the crypto provider
 * @param len number of random bytes to generate
 * @return the newly allocated random bytes, which must be g_freed by the caller. NULL on failure
 */
guint8* random_bytes(gsize len);

/**
 * @brief Get the representation of a byte array as hex string
 * @param bytes the byte array
 * @param len number of bytes in the byte array
 * 
 * @return a newly allocated string which must be g_free'd by the caller
 * 
 * Example: [00000100, 10110010] -> 04b2
 */
gchar* bytes_to_hex(const guint8* bytes, gsize len);

#endif
