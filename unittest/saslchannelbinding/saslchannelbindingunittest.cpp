/*
 * Copyright (C) 2026 QCA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <QtCrypto>

#include <QSignalSpy>
#include <QtTest/QtTest>

class SaslChannelBindingUnitTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void scramSha256PlusClient();
    void scramSha256PlusClientAfterParams();

private:
    QCA::Initializer *m_init = nullptr;
};

void SaslChannelBindingUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
}

void SaslChannelBindingUnitTest::cleanupTestCase()
{
    delete m_init;
    m_init = nullptr;
}

void SaslChannelBindingUnitTest::scramSha256PlusClient()
{
    const QString provider = QStringLiteral("qca-cyrus-sasl");
    if (!QCA::isSupported("sasl", provider))
        QSKIP("qca-cyrus-sasl is not available");

    QCA::SASL sasl(nullptr, provider);
    if (!sasl.supportsChannelBinding())
        QSKIP("The installed Cyrus SASL does not provide SASL_CHANNEL_BINDING");

    const QByteArray channelBindingData(32, '\x5a');
    QVERIFY(sasl.setChannelBinding(QStringLiteral("tls-exporter"), channelBindingData, true));

    sasl.setUsername(QStringLiteral("user"));
    sasl.setPassword(QCA::SecureArray("pencil"));

    QSignalSpy startedSpy(&sasl, &QCA::SASL::clientStarted);
    QSignalSpy errorSpy(&sasl, &QCA::SASL::error);

    sasl.startClient(
        QStringLiteral("xmpp"), QStringLiteral("example.test"), QStringList {QStringLiteral("SCRAM-SHA-256-PLUS")});

    QTRY_VERIFY_WITH_TIMEOUT(!startedSpy.isEmpty() || !errorSpy.isEmpty(), 5000);
    if (!errorSpy.isEmpty() && sasl.authCondition() == QCA::SASL::NoMechanism)
        QSKIP("The Cyrus SASL SCRAM-SHA-256 plugin is not installed");

    QVERIFY2(errorSpy.isEmpty(), "Unable to start SCRAM-SHA-256-PLUS");
    QCOMPARE(startedSpy.size(), 1);
    QCOMPARE(sasl.mechanism(), QStringLiteral("SCRAM-SHA-256-PLUS"));

    const QList<QVariant> arguments = startedSpy.constFirst();
    QVERIFY(arguments.at(0).toBool());
    QVERIFY(arguments.at(1).toByteArray().startsWith("p=tls-exporter,,"));
}

void SaslChannelBindingUnitTest::scramSha256PlusClientAfterParams()
{
    const QString provider = QStringLiteral("qca-cyrus-sasl");
    if (!QCA::isSupported("sasl", provider))
        QSKIP("qca-cyrus-sasl is not available");

    QCA::SASL sasl(nullptr, provider);
    if (!sasl.supportsChannelBinding())
        QSKIP("The installed Cyrus SASL does not provide SASL_CHANNEL_BINDING");

    const QByteArray channelBindingData(32, '\x5a');
    QVERIFY(sasl.setChannelBinding(QStringLiteral("tls-exporter"), channelBindingData, true));

    QSignalSpy paramsSpy(&sasl, &QCA::SASL::needParams);
    QSignalSpy startedSpy(&sasl, &QCA::SASL::clientStarted);
    QSignalSpy errorSpy(&sasl, &QCA::SASL::error);

    connect(&sasl, &QCA::SASL::needParams, &sasl, [&sasl](const QCA::SASL::Params &) {
        sasl.setUsername(QStringLiteral("user"));
        sasl.setPassword(QCA::SecureArray("pencil"));
        sasl.continueAfterParams();
    });

    sasl.startClient(
        QStringLiteral("xmpp"), QStringLiteral("example.test"), QStringList {QStringLiteral("SCRAM-SHA-256-PLUS")});

    QTRY_VERIFY_WITH_TIMEOUT(!paramsSpy.isEmpty() || !errorSpy.isEmpty(), 5000);
    if (!errorSpy.isEmpty() && sasl.authCondition() == QCA::SASL::NoMechanism)
        QSKIP("The Cyrus SASL SCRAM-SHA-256 plugin is not installed");

    QCOMPARE(paramsSpy.size(), 1);
    QTRY_VERIFY_WITH_TIMEOUT(!startedSpy.isEmpty() || !errorSpy.isEmpty(), 5000);
    QVERIFY2(errorSpy.isEmpty(), "Unable to start SCRAM-SHA-256-PLUS after supplying parameters");
    QCOMPARE(startedSpy.size(), 1);
    QCOMPARE(sasl.mechanism(), QStringLiteral("SCRAM-SHA-256-PLUS"));

    const QList<QVariant> arguments = startedSpy.constFirst();
    QVERIFY(arguments.at(0).toBool());
    QVERIFY(arguments.at(1).toByteArray().startsWith("p=tls-exporter,,"));
}

QTEST_MAIN(SaslChannelBindingUnitTest)

#include "saslchannelbindingunittest.moc"
