// SPDX-License-Identifier: LGPL-2.1-or-later
// OpenSSL is an independent test peer, never a dependency of qca-wincrypto.
#include <QQueue>
#include <QTest>
#include <QtCrypto>
#include <cstring>
#include <memory>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

namespace {
const QString Provider = QStringLiteral("qca-wincrypto");
struct Packets
{
    QQueue<QByteArray> input, output;
    int                mtu = 1200;
};
int readPacket(BIO *bio, char *out, int size)
{
    BIO_clear_retry_flags(bio);
    auto &packets = *static_cast<Packets *>(BIO_get_data(bio));
    if (packets.input.isEmpty()) {
        BIO_set_retry_read(bio);
        return -1;
    }
    const auto packet = packets.input.dequeue();
    const int  count  = qMin(size, int(packet.size()));
    if (count > 0)
        std::memcpy(out, packet.constData(), std::size_t(count));
    return count;
}
int writePacket(BIO *bio, const char *data, int size)
{
    BIO_clear_retry_flags(bio);
    static_cast<Packets *>(BIO_get_data(bio))->output.enqueue(QByteArray(data, size));
    return size;
}
long controlPacket(BIO *bio, int operation, long value, void *)
{
    auto &packets = *static_cast<Packets *>(BIO_get_data(bio));
    switch (operation) {
    case BIO_CTRL_FLUSH:
    case BIO_CTRL_DGRAM_SET_CONNECTED:
    case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
        return 1;
    case BIO_CTRL_DGRAM_QUERY_MTU:
    case BIO_CTRL_DGRAM_GET_MTU:
        return packets.mtu;
    case BIO_CTRL_DGRAM_SET_MTU:
        packets.mtu = int(value);
        return value;
    case BIO_CTRL_PENDING:
        return packets.input.isEmpty() ? 0 : packets.input.head().size();
    default:
        return 0;
    }
}
struct PacketMethod
{
    BIO_METHOD *value = BIO_meth_new(BIO_TYPE_DGRAM, "QCA independent datagram peer");
    PacketMethod()
    {
        BIO_meth_set_write(value, writePacket);
        BIO_meth_set_read(value, readPacket);
        BIO_meth_set_ctrl(value, controlPacket);
        BIO_meth_set_create(value, [](BIO *bio) {
            BIO_set_init(bio, 1);
            BIO_set_data(bio, new Packets);
            return 1;
        });
        BIO_meth_set_destroy(value, [](BIO *bio) {
            delete static_cast<Packets *>(BIO_get_data(bio));
            return 1;
        });
    }
    ~PacketMethod()
    {
        BIO_meth_free(value);
    }
};
}
class WinCryptoOpenSSLTest : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void initTestCase()
    {
        qInfo() << "Independent DTLS peer:" << OpenSSL_version(OPENSSL_VERSION);
    }
    void interoperability_data();
    void interoperability();

private:
    QCA::Initializer _qca;
};
void WinCryptoOpenSSLTest::interoperability_data()
{
    QTest::addColumn<bool>("nativeServer");
    QTest::addColumn<QString>("profile");
    for (bool server : {false, true})
        for (const auto &profile : {QString(),
                                    QStringLiteral("SRTP_AES128_CM_HMAC_SHA1_80"),
                                    QStringLiteral("SRTP_AES128_CM_HMAC_SHA1_32"),
                                    QStringLiteral("SRTP_AEAD_AES_128_GCM"),
                                    QStringLiteral("SRTP_AEAD_AES_256_GCM")}) {
            const auto name =
                (server ? QByteArray("native-server:") : QByteArray("native-client:")) + profile.toLatin1();
            QTest::newRow(name.constData()) << server << profile;
        }
}
void WinCryptoOpenSSLTest::interoperability()
{
    QFETCH(bool, nativeServer);
    QFETCH(QString, profile);
    auto ctx = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(SSL_CTX_new(DTLS_method()), SSL_CTX_free);
    QVERIFY(ctx);
    QVERIFY(SSL_CTX_set_min_proto_version(ctx.get(), DTLS1_2_VERSION));
    QVERIFY(SSL_CTX_set_max_proto_version(ctx.get(), DTLS1_2_VERSION));
    QVERIFY(SSL_CTX_set_cipher_list(ctx.get(), "ECDHE-RSA-AES128-GCM-SHA256"));
    QVERIFY(SSL_CTX_use_certificate_file(ctx.get(), "dtlssrtp-certs/default.crt", SSL_FILETYPE_PEM));
    QVERIFY(SSL_CTX_use_PrivateKey_file(ctx.get(), "dtlssrtp-certs/default.key", SSL_FILETYPE_PEM));
    QVERIFY(SSL_CTX_check_private_key(ctx.get()));
    // Make a self-signed fixture with both EKUs in memory. The older shared
    // certificate fixture is server-only and cannot authenticate a DTLS client.
    auto peerCertificate = std::unique_ptr<X509, decltype(&X509_free)>(X509_new(), X509_free);
    QVERIFY(peerCertificate);
    QVERIFY(X509_set_version(peerCertificate.get(), 2));
    QVERIFY(ASN1_INTEGER_set(X509_get_serialNumber(peerCertificate.get()), 42));
    QVERIFY(X509_gmtime_adj(X509_getm_notBefore(peerCertificate.get()), -60));
    QVERIFY(X509_gmtime_adj(X509_getm_notAfter(peerCertificate.get()), 86400));
    QVERIFY(X509_set_pubkey(peerCertificate.get(), SSL_CTX_get0_privatekey(ctx.get())));
    auto subject = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>(X509_NAME_new(), X509_NAME_free);
    QVERIFY(subject);
    QVERIFY(X509_NAME_add_entry_by_txt(
        subject.get(), "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("openssl.test"), -1, -1, 0));
    QVERIFY(X509_set_subject_name(peerCertificate.get(), subject.get()));
    auto eku = std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>(
        X509V3_EXT_conf_nid(nullptr, nullptr, NID_ext_key_usage, "serverAuth,clientAuth"), X509_EXTENSION_free);
    QVERIFY(eku);
    QVERIFY(X509_add_ext(peerCertificate.get(), eku.get(), -1));
    QVERIFY(X509_set_issuer_name(peerCertificate.get(), X509_get_subject_name(peerCertificate.get())));
    QVERIFY(X509_sign(peerCertificate.get(), SSL_CTX_get0_privatekey(ctx.get()), EVP_sha256()) > 0);
    QVERIFY(SSL_CTX_use_certificate(ctx.get(), peerCertificate.get()));
    // Each side pins the other side's exact test certificate.
    SSL_CTX_set_verify(
        ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, [](int, X509_STORE_CTX *) { return 1; });
    const auto opensslProfile = QString(profile).replace(QStringLiteral("_HMAC_SHA1_"), QStringLiteral("_SHA1_"));
    if (!profile.isEmpty() && SSL_CTX_set_tlsext_use_srtp(ctx.get(), opensslProfile.toLatin1().constData()) != 0)
        QSKIP("The independent OpenSSL peer does not provide this SRTP profile");
    PacketMethod method;
    auto         ssl = std::unique_ptr<SSL, decltype(&SSL_free)>(SSL_new(ctx.get()), SSL_free);
    QVERIFY(ssl);
    auto bio = BIO_new(method.value);
    QVERIFY(bio);
    auto &packets = *static_cast<Packets *>(BIO_get_data(bio));
    SSL_set_bio(ssl.get(), bio, bio);
    SSL_set_mtu(ssl.get(), 1200);
    if (nativeServer)
        SSL_set_connect_state(ssl.get());
    else
        SSL_set_accept_state(ssl.get());
    QCA::TLS native(QCA::TLS::Datagram, nullptr, Provider);
    native.setPacketMTU(1200);
    const auto key = QCA::KeyGenerator().createRSA(2048, 65537, Provider);
    QVERIFY(!key.isNull());
    QCA::CertificateOptions options;
    QCA::CertificateInfo    info;
    info.insert(QCA::CommonName, QStringLiteral("qca.test"));
    options.setInfo(info);
    options.setSerialNumber(QCA::BigInteger(42));
    const auto now = QDateTime::currentDateTimeUtc();
    options.setValidityPeriod(now.addSecs(-60), now.addDays(1));
    options.setConstraints({QCA::DigitalSignature, QCA::KeyEncipherment, QCA::ClientAuth, QCA::ServerAuth});
    const QCA::Certificate certificate(options, key, Provider);
    QVERIFY(!certificate.isNull());
    QCA::CertificateChain chain;
    chain += certificate;
    native.setCertificate(chain, key);
    QCA::CertificateCollection trust;
    const int                  peerLength = i2d_X509(peerCertificate.get(), nullptr);
    QByteArray                 peerDER(peerLength, 0);
    auto                       peerOutput = reinterpret_cast<unsigned char *>(peerDER.data());
    QCOMPARE(i2d_X509(peerCertificate.get(), &peerOutput), peerLength);
    trust.addCertificate(QCA::Certificate::fromDER(peerDER, nullptr, Provider));
    native.setTrustedCertificates(trust);
    QVERIFY(native.setSRTPProfiles(profile.isEmpty() ? QStringList() : QStringList {profile}));
    bool complete = false, failed = false;
    connect(&native, &QCA::TLS::handshaken, &native, [&] {
        complete = true;
        native.continueAfterStep();
    });
    connect(&native, &QCA::TLS::peerCertificateAvailable, &native, &QCA::TLS::continueAfterStep);
    connect(&native, &QCA::TLS::error, &native, [&] { failed = true; });
    const auto transferToOpenSSL = [&] {
        QCoreApplication::processEvents();
        while (native.packetsOutgoingAvailable()) {
            const auto packet = native.readOutgoing();
            packets.input.enqueue(packet);
        }
    };
    const auto transferToNative = [&] {
        while (!packets.output.isEmpty())
            native.writeIncoming(packets.output.dequeue());
        QCoreApplication::processEvents();
    };
    if (nativeServer)
        native.startServer();
    else
        native.startClient();
    bool peerDone = false;
    for (int round = 0; round < 1000 && !(complete && peerDone) && !failed; ++round) {
        transferToOpenSSL();
        if (!peerDone) {
            const int result = SSL_do_handshake(ssl.get());
            if (result == 1)
                peerDone = true;
            else {
                const int error = SSL_get_error(ssl.get(), result);
                QVERIFY2(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE,
                         ERR_error_string(ERR_peek_last_error(), nullptr));
            }
        }
        transferToNative();
    }
    QVERIFY(!failed);
    QVERIFY(complete);
    QVERIFY(peerDone);
    QCOMPARE(native.peerIdentityResult(), QCA::TLS::Valid);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    auto remote = std::unique_ptr<X509, decltype(&X509_free)>(SSL_get1_peer_certificate(ssl.get()), X509_free);
#else
    auto remote = std::unique_ptr<X509, decltype(&X509_free)>(SSL_get_peer_certificate(ssl.get()), X509_free);
#endif
    QVERIFY(remote);
    const int  certLength = i2d_X509(remote.get(), nullptr);
    QByteArray remoteDER(certLength, 0);
    auto       derOutput = reinterpret_cast<unsigned char *>(remoteDER.data());
    QCOMPARE(i2d_X509(remote.get(), &derOutput), certLength);
    QCOMPARE(remoteDER, certificate.toDER());
    QCOMPARE(native.selectedSRTPProfile(), profile);
    if (profile.isEmpty()) {
        native.write(QByteArray("native datagram"));
        for (int round = 0; round < 10; ++round)
            transferToOpenSSL();
        char      plain[64] {};
        const int length = SSL_read(ssl.get(), plain, sizeof(plain));
        QCOMPARE(QByteArray(plain, length > 0 ? length : 0), QByteArray("native datagram"));
        QCOMPARE(SSL_write(ssl.get(), "OpenSSL reply", 13), 13);
        for (int round = 0; round < 10; ++round)
            transferToNative();
        QCOMPARE(native.packetsAvailable(), 1);
        QCOMPARE(native.read(), QByteArray("OpenSSL reply"));
    } else {
        const auto selected = SSL_get_selected_srtp_profile(ssl.get());
        QVERIFY(selected);
        QCOMPARE(QString::fromLatin1(selected->name), opensslProfile);
        const int        keyLength  = profile == QLatin1String("SRTP_AEAD_AES_256_GCM") ? 32 : 16;
        const int        saltLength = profile.contains(QLatin1String("GCM")) ? 12 : 14;
        QCA::SecureArray exported(2 * (keyLength + saltLength));
        const char       label[] = "EXTRACTOR-dtls_srtp";
        QVERIFY(SSL_export_keying_material(ssl.get(),
                                           reinterpret_cast<unsigned char *>(exported.data()),
                                           exported.size(),
                                           label,
                                           sizeof(label) - 1,
                                           nullptr,
                                           0,
                                           0));
        const auto material = native.srtpKeyingMaterial();
        const auto matches  = [&](const QCA::SecureArray &value, int offset) {
            return value.size() && std::memcmp(value.constData(), exported.constData() + offset, value.size()) == 0;
        };
        const int local = nativeServer ? 1 : 0, peer = 1 - local;
        QVERIFY(matches(material.localMasterKey(), local * keyLength));
        QVERIFY(matches(material.remoteMasterKey(), peer * keyLength));
        QVERIFY(matches(material.localMasterSalt(), 2 * keyLength + local * saltLength));
        QVERIFY(matches(material.remoteMasterSalt(), 2 * keyLength + peer * saltLength));
    }
}
QTEST_GUILESS_MAIN(WinCryptoOpenSSLTest)
#include "wincryptoopensslunittest.moc"
