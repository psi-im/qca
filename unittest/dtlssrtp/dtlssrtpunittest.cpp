/**
 * Copyright (C) 2026 QCA contributors
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 */

#include <QEventLoop>
#include <QTest>
#include <QTimer>
#include <QtCrypto>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

namespace {

const QString aes128CmProfile = QStringLiteral("SRTP_AES128_CM_HMAC_SHA1_80");

struct ProfileLengths
{
    const char *name;
    int         masterKeyLength;
    int         masterSaltLength;
};

static const ProfileLengths profileLengths[] = {
    {"SRTP_AES128_CM_HMAC_SHA1_80", 16, 14},
    {"SRTP_AES128_CM_HMAC_SHA1_32", 16, 14},
    {"SRTP_AEAD_AES_128_GCM", 16, 12},
    {"SRTP_AEAD_AES_256_GCM", 32, 12},
    {"DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM", 32, 24},
    {"DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM", 64, 24},
    {"SRTP_ARIA_128_CTR_HMAC_SHA1_80", 16, 14},
    {"SRTP_ARIA_128_CTR_HMAC_SHA1_32", 16, 14},
    {"SRTP_ARIA_256_CTR_HMAC_SHA1_80", 32, 14},
    {"SRTP_ARIA_256_CTR_HMAC_SHA1_32", 32, 14},
    {"SRTP_AEAD_ARIA_128_GCM", 16, 12},
    {"SRTP_AEAD_ARIA_256_GCM", 32, 12},
};

QStringList srtpProviders()
{
    QStringList result;
    const auto  providers = QCA::providers();
    for (const QCA::Provider *provider : providers) {
        if (QCA::isSupported("dtls-srtp", provider->name()))
            result += provider->name();
    }
    return result;
}

class DTLSSRTPPair : public QObject
{
public:
    DTLSSRTPPair(const QCA::Certificate &certificate, const QCA::PrivateKey &privateKey, const QString &provider)
        : m_client(QCA::TLS::Datagram, this, provider)
        , m_server(QCA::TLS::Datagram, this, provider)
    {
        QCA::CertificateCollection trusted;
        trusted.addCertificate(certificate);
        m_client.setTrustedCertificates(trusted);

        QCA::CertificateChain chain;
        chain.append(certificate);
        m_server.setCertificate(chain, privateKey);

        connect(&m_client, &QCA::TLS::readyReadOutgoing, this, [this]() { transfer(m_client, m_server); });
        connect(&m_server, &QCA::TLS::readyReadOutgoing, this, [this]() { transfer(m_server, m_client); });
        connect(&m_client, &QCA::TLS::handshaken, this, [this]() { handshaken(m_client, true); });
        connect(&m_server, &QCA::TLS::handshaken, this, [this]() { handshaken(m_server, false); });
        connect(&m_client, &QCA::TLS::error, this, [this]() { failed(QStringLiteral("client"), m_client); });
        connect(&m_server, &QCA::TLS::error, this, [this]() { failed(QStringLiteral("server"), m_server); });
    }

    bool setProfiles(const QStringList &clientProfiles, const QStringList &serverProfiles)
    {
        return m_client.setSRTPProfiles(clientProfiles) && m_server.setSRTPProfiles(serverProfiles);
    }

    bool run(int timeout = 5000)
    {
        QEventLoop loop;
        QTimer     timer;
        timer.setSingleShot(true);
        connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);

        m_loop = &loop;
        timer.start(timeout);
        m_server.startServer();
        m_client.startClient();
        if ((!m_clientHandshaken || !m_serverHandshaken) && m_errorString.isEmpty())
            loop.exec();
        m_loop = nullptr;

        if (!m_clientHandshaken || !m_serverHandshaken) {
            if (m_errorString.isEmpty())
                m_errorString = QStringLiteral("Timed out during the local DTLS-SRTP handshake");
            return false;
        }
        return true;
    }

    QString errorString() const
    {
        return m_errorString;
    }

    QString clientProfile() const
    {
        return m_clientProfile;
    }

    QString serverProfile() const
    {
        return m_serverProfile;
    }

    QCA::TLS::SRTPKeyingMaterial clientMaterial() const
    {
        return m_clientMaterial;
    }

    QCA::TLS::SRTPKeyingMaterial serverMaterial() const
    {
        return m_serverMaterial;
    }

private:
    static void transfer(QCA::TLS &source, QCA::TLS &destination)
    {
        QByteArray datagram;
        while (!(datagram = source.readOutgoing()).isEmpty())
            destination.writeIncoming(datagram);
    }

    void handshaken(QCA::TLS &tls, bool client)
    {
        if (client) {
            m_clientProfile    = tls.selectedSRTPProfile();
            m_clientMaterial   = tls.srtpKeyingMaterial();
            m_clientHandshaken = true;
        } else {
            m_serverProfile    = tls.selectedSRTPProfile();
            m_serverMaterial   = tls.srtpKeyingMaterial();
            m_serverHandshaken = true;
        }

        tls.continueAfterStep();
        if (m_clientHandshaken && m_serverHandshaken && m_loop)
            m_loop->quit();
    }

    void failed(const QString &side, const QCA::TLS &tls)
    {
        if (m_errorString.isEmpty()) {
            m_errorString =
                QStringLiteral("%1-side DTLS error %2").arg(side, QString::number(static_cast<int>(tls.errorCode())));
        }
        if (m_loop)
            m_loop->quit();
    }

    QCA::TLS                     m_client;
    QCA::TLS                     m_server;
    QEventLoop                  *m_loop             = nullptr;
    bool                         m_clientHandshaken = false;
    bool                         m_serverHandshaken = false;
    QString                      m_errorString;
    QString                      m_clientProfile;
    QString                      m_serverProfile;
    QCA::TLS::SRTPKeyingMaterial m_clientMaterial;
    QCA::TLS::SRTPKeyingMaterial m_serverMaterial;
};

} // namespace

class DTLSSRTPUnitTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void apiValidation();
    void negotiateAndExport_data();
    void negotiateAndExport();

private:
    QCA::Initializer *m_init = nullptr;
};

void DTLSSRTPUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
}

void DTLSSRTPUnitTest::cleanupTestCase()
{
    delete m_init;
    m_init = nullptr;
}

void DTLSSRTPUnitTest::apiValidation()
{
    const QStringList providers = srtpProviders();
    if (providers.isEmpty())
        QSKIP("No DTLS-SRTP capable QCA provider is available");

    for (const QString &provider : providers) {
        QVERIFY2(QCA::isSupported("dtls", provider), qPrintable(provider));

        QCA::TLS streamTls(QCA::TLS::Stream, nullptr, provider);
        QVERIFY2(streamTls.supportedSRTPProfiles().isEmpty(), qPrintable(provider));
        QVERIFY2(!streamTls.setSRTPProfiles(QStringList {aes128CmProfile}), qPrintable(provider));

        QCA::TLS          datagramTls(QCA::TLS::Datagram, nullptr, provider);
        const QStringList supported = datagramTls.supportedSRTPProfiles();
        QVERIFY2(!supported.isEmpty(), qPrintable(provider));
        QVERIFY2(!datagramTls.setSRTPProfiles(QStringList {QStringLiteral("SRTP_UNKNOWN_PROFILE")}),
                 qPrintable(provider));

        const QString profile = supported.constFirst();
        QVERIFY2(datagramTls.setSRTPProfiles(QStringList {profile, profile}), qPrintable(provider));
        QVERIFY2(datagramTls.selectedSRTPProfile().isEmpty(), qPrintable(provider));
        QVERIFY2(datagramTls.srtpKeyingMaterial().isNull(), qPrintable(provider));
    }
}

void DTLSSRTPUnitTest::negotiateAndExport_data()
{
    QTest::addColumn<QString>("provider");
    QTest::addColumn<QString>("profile");
    QTest::addColumn<int>("masterKeyLength");
    QTest::addColumn<int>("masterSaltLength");

    int               rows      = 0;
    const QStringList providers = srtpProviders();
    for (const QString &provider : providers) {
        // The negotiation test needs to load its certificate and private key
        // through the provider under test.  Providers exposing only the generic
        // DTLS-SRTP API are still covered by apiValidation().
        if (!QCA::isSupported("cert", provider) || !QCA::isSupported("pkey", provider))
            continue;

        QCA::TLS          probe(QCA::TLS::Datagram, nullptr, provider);
        const QStringList supported = probe.supportedSRTPProfiles();
        for (const ProfileLengths &profile : profileLengths) {
            const QString name = QString::fromLatin1(profile.name);
            if (!supported.contains(name))
                continue;

            const QByteArray rowName = (provider + QLatin1Char(':') + name).toLatin1();
            QTest::newRow(rowName.constData())
                << provider << name << profile.masterKeyLength << profile.masterSaltLength;
            ++rows;
        }
    }

    if (rows == 0)
        QTest::newRow("no-provider") << QString() << QString() << 0 << 0;
}

void DTLSSRTPUnitTest::negotiateAndExport()
{
    QFETCH(QString, provider);
    QFETCH(QString, profile);
    QFETCH(int, masterKeyLength);
    QFETCH(int, masterSaltLength);

    if (provider.isEmpty())
        QSKIP("No DTLS-SRTP provider with certificate and private-key support is available");

    QCA::ConvertResult     certificateResult = QCA::ErrorDecode;
    QCA::ConvertResult     keyResult         = QCA::ErrorDecode;
    const QCA::Certificate certificate =
        QCA::Certificate::fromPEMFile(QStringLiteral("dtlssrtp-certs/default.crt"), &certificateResult, provider);
    const QCA::PrivateKey privateKey = QCA::PrivateKey::fromPEMFile(
        QStringLiteral("dtlssrtp-certs/default.key"), QCA::SecureArray(), &keyResult, provider);

    QCOMPARE(certificateResult, QCA::ConvertGood);
    QCOMPARE(keyResult, QCA::ConvertGood);
    QVERIFY(!certificate.isNull());
    QVERIFY(!privateKey.isNull());

    DTLSSRTPPair pair(certificate, privateKey, provider);
    QVERIFY(pair.setProfiles(QStringList {profile}, QStringList {profile}));
    QVERIFY2(pair.run(), qPrintable(pair.errorString()));

    QCOMPARE(pair.clientProfile(), profile);
    QCOMPARE(pair.serverProfile(), profile);

    const QCA::TLS::SRTPKeyingMaterial client = pair.clientMaterial();
    const QCA::TLS::SRTPKeyingMaterial server = pair.serverMaterial();
    QVERIFY(!client.isNull());
    QVERIFY(!server.isNull());
    QCOMPARE(client.profile(), profile);
    QCOMPARE(server.profile(), profile);

    QCOMPARE(client.localMasterKey().size(), masterKeyLength);
    QCOMPARE(client.remoteMasterKey().size(), masterKeyLength);
    QCOMPARE(client.localMasterSalt().size(), masterSaltLength);
    QCOMPARE(client.remoteMasterSalt().size(), masterSaltLength);

    QVERIFY(client.localMasterKey() == server.remoteMasterKey());
    QVERIFY(client.localMasterSalt() == server.remoteMasterSalt());
    QVERIFY(client.remoteMasterKey() == server.localMasterKey());
    QVERIFY(client.remoteMasterSalt() == server.localMasterSalt());
}

QTEST_MAIN(DTLSSRTPUnitTest)

#include "dtlssrtpunittest.moc"
