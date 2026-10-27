#include "ed25519key.h"

#ifdef EVP_PKEY_ED25519

namespace opensslQCAPlugin {

Ed25519Key::Ed25519Key(QCA::Provider *provider, EVP_PKEY *key, bool isPrivate)
    : PKeyBase(provider, QStringLiteral("ed25519"))
    , _key(key)
    , _private(isPrivate)
{
}

Ed25519Key::~Ed25519Key()
{
    EVP_PKEY_free(_key);
}

QCA::Provider::Context *Ed25519Key::clone() const
{
    if (_key)
        EVP_PKEY_up_ref(_key);
    return new Ed25519Key(provider(), _key, _private);
}

bool Ed25519Key::isNull() const
{
    return !_key;
}

QCA::PKey::Type Ed25519Key::type() const
{
    return QCA::PKey::Ed25519;
}

bool Ed25519Key::isPrivate() const
{
    return _private;
}

bool Ed25519Key::canExport() const
{
    return !isNull();
}

void Ed25519Key::convertToPublic()
{
    if (!_key || !_private)
        return;

    unsigned char publicBytes[32];
    size_t size = sizeof(publicBytes);
    if (EVP_PKEY_get_raw_public_key(_key, publicBytes, &size) != 1 || size != sizeof(publicBytes))
        return;
    EVP_PKEY *publicKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, publicBytes, size);
    if (!publicKey)
        return;

    EVP_PKEY_free(_key);
    _key = publicKey;
    _private = false;
    _message.clear();
    _operation = Operation::Idle;
}

int Ed25519Key::bits() const
{
    return _key ? EVP_PKEY_bits(_key) : 0;
}

void Ed25519Key::startSign(QCA::SignatureAlgorithm alg, QCA::SignatureFormat)
{
    _message.clear();
    _operation = _private && _key && alg.scheme == QCA::SignatureScheme::Ed25519
                         && alg.digest == QCA::SignatureDigest::None
        ? Operation::Signing : Operation::Error;
}

void Ed25519Key::startVerify(QCA::SignatureAlgorithm alg, QCA::SignatureFormat)
{
    _message.clear();
    _operation = _key && alg.scheme == QCA::SignatureScheme::Ed25519
                      && alg.digest == QCA::SignatureDigest::None
        ? Operation::Verifying : Operation::Error;
}

void Ed25519Key::update(const QCA::MemoryRegion &message)
{
    if (_operation == Operation::Signing || _operation == Operation::Verifying)
        _message.append(message.data(), message.size());
}

QByteArray Ed25519Key::endSign()
{
    if (_operation != Operation::Signing)
        return {};
    _operation = Operation::Idle;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        _message.clear();
        return {};
    }
    QByteArray signature;
    size_t size = 0;
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, _key) == 1
        && EVP_DigestSign(ctx, nullptr, &size,
                          reinterpret_cast<const unsigned char *>(_message.constData()),
                          static_cast<size_t>(_message.size())) == 1
        && size == 64) {
        signature.resize(static_cast<int>(size));
        if (EVP_DigestSign(ctx, reinterpret_cast<unsigned char *>(signature.data()), &size,
                           reinterpret_cast<const unsigned char *>(_message.constData()),
                           static_cast<size_t>(_message.size())) != 1 || size != 64) {
            signature.clear();
        }
    }
    _message.clear();
    EVP_MD_CTX_free(ctx);
    return signature;
}

bool Ed25519Key::endVerify(const QByteArray &signature)
{
    if (_operation != Operation::Verifying)
        return false;
    _operation = Operation::Idle;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool verified = false;
    if (ctx && signature.size() == 64 && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, _key) == 1) {
        verified = EVP_DigestVerify(ctx,
                      reinterpret_cast<const unsigned char *>(signature.constData()),
                      static_cast<size_t>(signature.size()),
                      reinterpret_cast<const unsigned char *>(_message.constData()),
                      static_cast<size_t>(_message.size())) == 1;
    }
    _message.clear();
    EVP_MD_CTX_free(ctx);
    return verified;
}

} // namespace opensslQCAPlugin
#endif
