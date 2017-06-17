## About

This is a prototype plug-in for Jabber/XMPP accounts to support 1:1 end-to-end encryption with [OMEMO](https://conversations.im/omemo/) ([XEP-0384](https://xmpp.org/extensions/xep-0384.html)) in Pidgin and other compatible clients using libpurple.
It doesn't have graphical trust management yet. See [Usage](#usage) on how to activate and configure it "by hand".

It allows Pidgin to be OMEMO-compatible with [Conversations](https://conversations.im/) (Android), [ChatSecure](https://chatsecure.org/) (iOS), [Gajim](https://gajim.org/) (desktop - with OMEMO plug-in) and riba's Pidgin OMEMO plug-in.

**DISCLAIMER: This plug-in is in experimental state and in constant development. It is not intended to be used on production environments. Do not rely on this plug-in to protect sensitive information. If you use it you are on your own and I take no resposibility for any damage, harm or loss you, your system, your data or your cat might suffer.**

## Background

This plug-in was the result of academic research. You can find a couple of thoughts about it as well as OMEMO itself [here](https://userpage.fu-berlin.de/mancho/OMEMO.pdf) (in German).

## Runtime dependencies

Tested with the following versions:

- libpurple 2.10.12 (Ubuntu: libpurple0)
- libgcrypt 1.6.5 (Ubuntu: libgcrypt20)
- libsqlite 3.11.0 (Ubuntu: libsqlite3-0)
- libsignal-protocol-c git@e0e778d (see below)


## Build dependencies

- libpurple development headers (Ubuntu: libpurple-dev)
- libgcrypt development headers (Ubuntu: libgcrypt20-dev)
- libsqlite3 development headers (Ubuntu: libsqlite3-dev)
- libxml2 development headers (Ubuntu: libxml2-dev)
- libsignal-protocol-c:

    ```
    git clone https://github.com/WhisperSystems/libsignal-protocol-c.git
    cd libsignal-protocol-c
    git checkout e0e778d6df18020a478d5fd316bde604f2e2fd10
    mkdir build
    cd build
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug ..
    make
    sudo make install
    ```

    (This will install the shared library as well as the development headers)

## Build

    $ make

## Install

	$ make install

Will copy omemo.so to the user's plugin directory ($HOME/.purple/plugins). After
that you should see the plugin appear in Tools->Plugins. Restart Pidgin after activation.

## Testing

After building the plugin:

```
cd tests
make
./test
```

## Usage

The following assumes that the plug-in is installed and activated, Pidgin restarted and the Jabber account was online at least once.

Before using the plug-in you have to enable encryption for the contacts you want to communicate with, then you have to define trust for every device of each contact.

##### Step one: Locate the OMEMO DB file
If you have only one Jabber account just open the SQLite DB found under $HOME/.purple/omemo/ (or wherever you purple home is). If you have multiple accounts go to $HOME/.purple/accounts.xml and look for *omemo-db-id* under the *settings* section of the account you want to configure and edit the corresponding file under $HOME/.purple/omemo/.

##### Step two: Enable encryption
Encryption is disabled by default. To enable it set the value of *encryption* in the table *contacts* to 1. If the table has no entries try restarting Pidgin.

##### Step three: Trust devices (or not)
Now you are able to receive encrypted messages. However, in order to send you need to define **for every device of your contact** whether you trust it or not. Go to the table *devices* and set *trust* to 1 (trusted) or 0 (not trusted) accordingly. Do the same for your own devices.

## Troubleshooting
You won't get any feedback from the plug-in in the chat window. If something doesn't work as expected open the Pidgin debug console (Help->Debug window) and filter after *core-mancho-omemo*.

## Known issues
- On sending the first message to a contact the Signal sessions are built asynchronously. Depending on how fast the servers are it could be that the first message or messages are discarded, so don't wonder if they are not delivered to your counterpart. Wait a second and try again.
- A very large etc.

## Road map
- Notifications in chat window
- Configuration GUI (activation and trust management)
- Group chat support
- New build system
