Qt Cryptographic Architecture (QCA)
-----------------------------------


This is a fork
--------------

This is a fork of https://invent.kde.org/libraries/qca.
Unfortunately it's not possible to keep development under the hood of KDE project since KDE developers are very conservative and do not accept new applications to the KDE developers. Approximately the same can be said about any new feature brought into the project.
Previously QCA was developed by Justin Karneges, same developer who invented Psi IM where QCA was heavily used. At some moment the QCA maintenance has been moved to KDE and it's mostly inactive there. Currently Psi IM needs a set of features from QCA and to quicken the implementation this fork was born.

Changes to mainstream:
* Fixed a few issues in keystore leading to hard lock on QCA initialization
* Applied a few patches from various distros mostly fixing compilation (libressl, Android etc)
* Added a few hash algorithms like SHA3 and Blake2b
* Added DTLS support

Planned features:
* TLS channel binding
* SRTP support (see "use_srtp" in RFC5764)

Any changes from upstream are regularly merged back to this fork. So it has all the best from both worlds.

If anyone desires to split the fork into smaller changes and make pull requests to the upstream, Psi IM team will support this as much as possible. Feel free to join our [XMPP chat](xmpp:psi-dev@conference.jabber.ru?join).

Description
-----------

QCA is a library that provides an easy API for a range of cryptographic
features, including SSL/TLS, X.509 certificates, SASL, OpenPGP, smartcards,
and much more.

Functionality is supplied via plugins.  This is useful for avoiding
dependence on a particular crypto library and makes upgrading easier,
as there is no need to recompile your application when adding or
upgrading a crypto plugin.

In order for QCA to be of much use, you'll want to install some plugins.


Install
-------
For installation or compiling instructions, see the INSTALL file.


License
-------
This library is licensed under the Lesser GNU General Public License.
See the COPYING file for more information.


History
-------

QCA was originally created to support the security needs of the
[Psi XMPP/Jabber client project](http://psi-im.org/).


Old Changes list
----------------

New in 2.1.0
- Ported to Qt5 (Qt4 also supported)
- New building system. CMake instead of qmake
- Added CTR symetric cipher support to qca core
- Added no padding encryption algorithm to qca core
- qcatool2 renamed to qcatool
- fixed crash in qcatool when only options provided on command line without any commands
- Use plugins installation path as hard-coded runtime plugins search path
- Added new functiion pluginPaths
- Added functions to get runtime QCA version
- Fixed 'no watch file' warnings in FileWatch
- Added EME_PKCS1v15_SSL Encryption Algorithm
- New implementation of SafeTimer to prevent crashes
- Updated certificates for unittests
- RSA Keys are permutable, can encrypt with private and decrypt with public
- Add unloadProvider() function for symmetry with insertProvider()
- Overloaded "makeKey" to derive a password depending on a time factor
- Remove pointer to deinit() routine from QCoreApplication at deinitialization
- Fix a couple of crashes where all plugins might not be available
- Fix operating on keys with unrelated expired subkeys
- Fixed timers in Synchronizer class
- Dropped randomunittest
- Fixed many unittests
- qca-gnupg: internal refactoring
- qca-gnupg: try both gpg and gpg2 to find gnupg executable
- qca-gnupg: fixed some encodings problem
- qca-ossl: no DSA_* dl groups in FIPS specification
- qca-ossl: added missed signatures to CRLContext
- qca-ossl: fixed certs time zone
- qca-nss: fixed KeyLenght for Cipher
- qca-botan: fixed getting result size for ciphers

New in 2.0.3
- Bugfix release, forward and backward compatible with 2.0.x
- Fix compilation when using Qt/Windows SDK

New in 2.0.2
- Bugfix release, forward and backward compatible with 2.0.x
- Fix compatibility with Qt 4.5 when QCA::Initializer appears before QApp
- Don't convert to secure memory when Hash::update(QByteArray) is used
- Use configure.exe instead of configwin.bat

New in 2.0.1
- Bugfix release, forward and backward compatible with 2.0.x
- Ability to build as a Mac framework (and build this way by default)
- On non-Mac Unix, the pkgconfig file is always qca2.pc, even in debug mode
- Certificates containing wildcards are now matched properly
- DirWatch/FileWatch now work
- Keystore writes now work
- Don't delete objects in their event handler (prevents Qt 4.4 warnings)
- Fix potential hang with TLS in server mode
- Windows version can be configured/installed using paths with spaces


Old Developer list
------------------

Project Lead/Maintainer (2003-2012):
Justin Karneges <justin@affinix.com>
(March 2007 - August 2007 under Barracuda Networks employment)

Development, Documentation, Unittests (2004-2009):
Brad Hards <bradh@frogmouth.net>

Development (2013-2017)
Ivan Romanov <drizt@land.ru>

Special Thanks:
Portugal Telecom (SAPO division), for sponsorship
Alon Bar-Lev, for smart card and design assistance
Jack Lloyd, for Botan and X.509 mentoring
L. Peter Deutsch, for the public domain MD5 implementation
Steve Reid, for the public domain SHA1 implementation
Jason Kim, for the CMS Signer graphics
