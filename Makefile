CC := gcc
LIBTOOL := libtool

ifeq ($(PREFIX),)
  LIB_INSTALL_DIR = $(HOME)/.purple/plugins
else
  LIB_INSTALL_DIR = $(PREFIX)/lib/purple-2/
endif

PLUGIN_NAME = omemo

PURPLE_LDFLAGS = $(shell pkg-config purple --cflags)
PURPLE_LDLIBS  = $(shell pkg-config purple --libs) -L$(shell pkg-config --variable=plugindir purple) \
	-Wl,-R$(shell pkg-config --variable=plugindir purple) -ljabber

GCRYPT_LDFLAGS = $(shell libgcrypt-config --cflags)
GCRYPT_LDLIBS  = $(shell libgcrypt-config --libs)

SQLITE_LDFLAGS = $(shell pkg-config sqlite3 --cflags)
SQLITE_LDLIBS  = $(shell pkg-config sqlite3 --libs)

XML_LDFLAGS = $(shell xml2-config --cflags)
XML_LDLIBS = $(shell xml2-config --libs)

SIGNAL_LDFLAGS = -I/usr/include/signal
SIGNAL_LDLIBS  = -lsignal-protocol-c

LDFLAGS        = $(PURPLE_LDFLAGS) $(GCRYPT_LDFLAGS) $(SQLITE_LDFLAGS) $(SIGNAL_LDFLAGS) $(XML_LDFLAGS)
LDLIBS         = $(PURPLE_LDLIBS) $(GCRYPT_LDLIBS) $(SQLITE_LDLIBS) $(SIGNAL_LDLIBS) $(XML_LDLIBS)

OBJS = $(PLUGIN_NAME).o \
	types/omemo_device.o \
	types/omemo_element.o \
	types/omemo_envelope.o \
	types/device_bundle.o \
	types/device_list.o \
	store/omemo_store.o \
	store/session_store.o \
	store/pre_key_store.o \
	store/signed_pre_key_store.o \
	store/identity_key_store.o \
	crypto/provider_gcrypt.o
	#change the former line to an alternative crypto-provider (e.g. \
	#OpenSSL's crypto) implementing crypto/provider.h

all: $(PLUGIN_NAME).so

install: all
	mkdir -p $(LIB_INSTALL_DIR)
	cp $(PLUGIN_NAME).so $(LIB_INSTALL_DIR)

$(PLUGIN_NAME).so: $(OBJS)
	$(CC) -shared $(CFLAGS) -DDEBUG -g $(OBJS) -o $@ $(LDLIBS) -Wl,--export-dynamic -Wl,-soname

%.o: %.c 
	$(CC) $(CFLAGS) -DDEBUG -g -Wunused-variable -fPIC -c $< -o $@ $(LDFLAGS)

SUBDIRS = . crypto store types
SUBDIRSCLEAN=$(addsuffix clean,$(SUBDIRS))

clean: $(SUBDIRSCLEAN)

clean_curdir:
	rm -rvf *.o *.c~ *.h~ *.so *.la .libs

%clean: %
	$(MAKE) -C $< -f $(PWD)/Makefile clean_curdir

