/*
 * This file is just to keep count of the used symbols from the Jabber Plug-in "API". It could
 * however eventually become a replacement (with some adjustments) for the entire "jabber"
 * directory where it lies. It would make comparison easier when struggling with new versions of
 * libpurple, i.e. of the Jabber Plug-in.
 */

#ifndef EXTERNAL_H
#define EXTERNAL_H

#include <glib.h>

#define NS_XMPP_CLIENT "jabber:client"

typedef void(JabberPEPHandler) (JabberStream* js, const char* from, xmlnode* items);
extern char* jabber_get_bare_jid(const char* jid);
extern gboolean jabber_pep_namespace_only_when_pep_enabled_cb(JabberStream* js, const gchar* namespace);
extern void jabber_send(JabberStream* js, xmlnode* data);
extern void jabber_pep_delete_node(JabberStream* js, const gchar* node);
extern void jabber_add_feature(const gchar *namespace, JabberFeatureEnabled cb);

#endif
