/*
 Copyright (C) 2007 Justin Karneges <justin@affinix.com>

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "tlssocket.h"

#include <QTimer>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

void SimpleLogger::logTextMessage(const QString &message, QCA::Logger::Severity severity)
{
    Q_UNUSED(severity)
    qDebug() << message;
}

void SimpleLogger::logBinaryMessage(const QByteArray &blob, QCA::Logger::Severity severity)
{
    Q_UNUSED(severity)
    qDebug() << "data: " << blob;
}

class TLSSocket::Private : public QObject
{
    Q_OBJECT
public:
    TLSSocket        *q;
    QTcpSocket       *sock;
    QCA::TLS         *tls;
    QString           host;
    bool              encrypted;
    bool              error, done;
    QByteArray        readbuf, writebuf;
    QCA::Synchronizer sync;
    bool              waiting;

    Private(TLSSocket *_q)
        : QObject(_q)
        , q(_q)
        , sync(_q)
    {
        sock = new QTcpSocket(this);
        connect(sock, &QTcpSocket::connected, this, &TLSSocket::Private::sock_connected);
        connect(sock, &QTcpSocket::readyRead, this, &TLSSocket::Private::sock_readyRead);
        connect(sock, &QTcpSocket::bytesWritten, this, &TLSSocket::Private::sock_bytesWritten);
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
        connect(sock, &QTcpSocket::errorOccurred, this, &TLSSocket::Private::sock_error);
#else
        connect(sock,
                QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::error),
                this,
                &TLSSocket::Private::sock_error);
#endif

        tls = new QCA::TLS(this);
        connect(tls, &QCA::TLS::certificateRequested, tls, &QCA::TLS::continueAfterStep);
        connect(tls, &QCA::TLS::handshaken, this, &TLSSocket::Private::tls_handshaken);
        connect(tls, &QCA::TLS::readyRead, this, &TLSSocket::Private::tls_readyRead);
        connect(tls, &QCA::TLS::readyReadOutgoing, this, &TLSSocket::Private::tls_readyReadOutgoing);
        connect(tls, &QCA::TLS::closed, this, &TLSSocket::Private::tls_closed);
        connect(tls, &QCA::TLS::error, this, &TLSSocket::Private::tls_error);
        tls->setTrustedCertificates(QCA::systemStore());
        encrypted = false;
        error     = false;
        waiting   = false;
        done      = false;
    }

    bool waitForReadyRead(int msecs)
    {
        waiting = true;
        bool ok = sync.waitForCondition(msecs);
        // while(1)
        //    QCoreApplication::instance()->processEvents();
        waiting = false;
        if (error || done)
            return false;
        return ok;
    }

private Q_SLOTS:
    void sock_connected()
    {
        // printf("sock connected\n");
        tls->startClient(host);
    }

    void sock_readyRead()
    {
        // printf("sock ready read\n");
        QByteArray buf = sock->readAll();
        // printf("%d bytes\n", buf.size());
        tls->writeIncoming(buf);
    }

    void sock_bytesWritten(qint64 x)
    {
        Q_UNUSED(x);
        // printf("sock bytes written: %d\n", (int)x);
    }

    void sock_error(QAbstractSocket::SocketError x)
    {
        // printf("sock error: %d\n", x);
        Q_UNUSED(x);
        // if ssl resultsReady() was alreay enquued we have to stop after it
        QTimer::singleShot(0, this, SLOT(setSocketClosed()));
    }

    void setSocketClosed()
    {
        done = true;
        if (waiting)
            sync.conditionMet();
    }

    void tls_handshaken()
    {
        // printf("tls handshaken\n");
        if (tls->peerIdentityResult() != QCA::TLS::Valid) {
            printf("not valid\n");
            sock->abort();
            tls->reset();
            error = true;
        } else {
            // printf("valid\n");
            encrypted = true;
            tls->continueAfterStep();
            // printf("%d bytes in writebuf\n", writebuf.size());
            if (!writebuf.isEmpty()) {
                // printf("[%s]\n", writebuf.data());
                tls->write(writebuf);
                writebuf.clear();
            }
        }
        if (waiting)
            sync.conditionMet();
    }

    void tls_readyRead()
    {
        // printf("tls ready read\n");
        if (waiting)
            sync.conditionMet();
        QByteArray a = tls->read();
        printf("%s", a.data());
    }

    void tls_readyReadOutgoing()
    {
        // printf("tls ready read outgoing\n");
        QByteArray buf = tls->readOutgoing();
        // printf("%d bytes\n", buf.size());
        sock->write(buf);
    }

    void tls_closed()
    {
        // printf("tls closed\n");
    }

    void tls_error()
    {
        // printf("tls error\n");
    }
};

TLSSocket::TLSSocket(QObject *parent)
    : QTcpSocket(parent)
{
    d = new Private(this);
}

TLSSocket::~TLSSocket()
{
    delete d;
}

void TLSSocket::connectToHostEncrypted(const QString &host, quint16 port)
{
    d->host = host;
    setOpenMode(QIODevice::ReadWrite);
    d->sock->connectToHost(host, port);
}

QCA::TLS *TLSSocket::tls()
{
    return d->tls;
}

bool TLSSocket::waitForReadyRead(int msecs)
{
    /*if(d->readbuf.isEmpty())
            return false;

    if(d->tls->bytesAvailable() == 0)
            return false;*/

    return d->waitForReadyRead(msecs);
}

qint64 TLSSocket::readData(char *data, qint64 maxlen)
{
    if (!d->error)
        d->readbuf += d->tls->read();
    unsigned char *p        = (unsigned char *)d->readbuf.data();
    int            size     = d->readbuf.size();
    int            readsize = qMin(size, (int)maxlen);
    int            newsize  = size - readsize;
    memcpy(data, p, readsize);
    memmove(p, p + readsize, newsize);
    d->readbuf.resize(newsize);
    return readsize;
}

qint64 TLSSocket::writeData(const char *data, qint64 len)
{
    // printf("write %d bytes\n", (int)len);
    QByteArray buf(data, len);
    if (d->encrypted)
        d->tls->write(buf);
    else
        d->writebuf += buf;
    return len;
}

#include "tlssocket.moc"
