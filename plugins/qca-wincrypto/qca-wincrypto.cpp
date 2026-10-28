/*
 * Copyright (C) 2008  Michael Leupold <lemma@confuego.org>
 * Copyright (C) 2026  Psi IM Team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 */

// QCA provider on the Windows Cryptography API: Next Generation (CNG,
// bcrypt.dll): random numbers, hashes, HMAC, PBKDF2, HKDF and AES ciphers.
// Only CNG functions available since Windows 7 are used; SHA-3 is offered
// when the running Windows has it.

#include "aesmodes.h"

#include <QtCrypto>
#include <QtPlugin>

#include <QElapsedTimer>
#include <QMutex>
#include <QMutexLocker>

#include <windows.h>

#include <bcrypt.h>

#include <array>

using namespace QCA;

namespace wincryptoQCAPlugin {

namespace {

bool ok(NTSTATUS status)
{
    return BCRYPT_SUCCESS(status);
}

PUCHAR bytes(const void *data)
{
    // CNG takes non-const pointers even for input.
    return static_cast<PUCHAR>(const_cast<void *>(data));
}

// A valid pointer for empty input: CNG may reject a null one.
UCHAR *emptyInput()
{
    static UCHAR none = 0;
    return &none;
}

}

//----------------------------------------------------------------------------
// Algorithm handles
//----------------------------------------------------------------------------
enum class Algorithm
{
    MD5,
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    HmacMD5,
    HmacSHA1,
    HmacSHA256,
    HmacSHA384,
    HmacSHA512,
    AES,
    Count
};

class WinCryptoProvider : public Provider
{
public:
    ~WinCryptoProvider() override
    {
        for (auto &handle : _handles)
            if (handle)
                BCryptCloseAlgorithmProvider(handle, 0);
    }

    int qcaVersion() const override
    {
        return QCA_VERSION;
    }

    QString name() const override
    {
        return QStringLiteral("qca-wincrypto");
    }

    QStringList features() const override;
    Context    *createContext(const QString &type) override;

    // Opened on first use and kept until the provider goes away. CNG
    // algorithm handles may be used from several threads at once.
    BCRYPT_ALG_HANDLE handle(Algorithm algorithm) const
    {
        QMutexLocker locker(&_mutex);
        const int    index = int(algorithm);
        if (!_opened[index]) {
            _opened[index]  = true;
            _handles[index] = open(algorithm);
        }
        return _handles[index];
    }

    // The digest length of a hash or HMAC algorithm, in bytes.
    int hashLength(Algorithm algorithm) const
    {
        BCRYPT_ALG_HANDLE alg    = handle(algorithm);
        DWORD             length = 0, written = 0;
        if (!alg ||
            !ok(BCryptGetProperty(
                alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&length), sizeof(length), &written, 0)))
            return 0;
        return int(length);
    }

private:
    static BCRYPT_ALG_HANDLE open(Algorithm algorithm)
    {
        const wchar_t *id    = nullptr;
        ULONG          flags = 0;
        switch (algorithm) {
        case Algorithm::MD5:
            id = BCRYPT_MD5_ALGORITHM;
            break;
        case Algorithm::SHA1:
            id = BCRYPT_SHA1_ALGORITHM;
            break;
        case Algorithm::SHA256:
            id = BCRYPT_SHA256_ALGORITHM;
            break;
        case Algorithm::SHA384:
            id = BCRYPT_SHA384_ALGORITHM;
            break;
        case Algorithm::SHA512:
            id = BCRYPT_SHA512_ALGORITHM;
            break;
        // SHA-3 came with Windows 11 24H2; older versions fail to open it.
        case Algorithm::SHA3_256:
            id = L"SHA3-256";
            break;
        case Algorithm::SHA3_384:
            id = L"SHA3-384";
            break;
        case Algorithm::SHA3_512:
            id = L"SHA3-512";
            break;
        case Algorithm::HmacMD5:
            id    = BCRYPT_MD5_ALGORITHM;
            flags = BCRYPT_ALG_HANDLE_HMAC_FLAG;
            break;
        case Algorithm::HmacSHA1:
            id    = BCRYPT_SHA1_ALGORITHM;
            flags = BCRYPT_ALG_HANDLE_HMAC_FLAG;
            break;
        case Algorithm::HmacSHA256:
            id    = BCRYPT_SHA256_ALGORITHM;
            flags = BCRYPT_ALG_HANDLE_HMAC_FLAG;
            break;
        case Algorithm::HmacSHA384:
            id    = BCRYPT_SHA384_ALGORITHM;
            flags = BCRYPT_ALG_HANDLE_HMAC_FLAG;
            break;
        case Algorithm::HmacSHA512:
            id    = BCRYPT_SHA512_ALGORITHM;
            flags = BCRYPT_ALG_HANDLE_HMAC_FLAG;
            break;
        case Algorithm::AES:
            id = BCRYPT_AES_ALGORITHM;
            break;
        case Algorithm::Count:
            return nullptr;
        }
        BCRYPT_ALG_HANDLE alg = nullptr;
        if (!ok(BCryptOpenAlgorithmProvider(&alg, id, nullptr, flags)))
            return nullptr;
        if (algorithm == Algorithm::AES) {
            // The modes are implemented in aesmodes.cpp on whole blocks.
            if (!ok(BCryptSetProperty(alg,
                                      BCRYPT_CHAINING_MODE,
                                      bytes(BCRYPT_CHAIN_MODE_ECB),
                                      ULONG(sizeof(BCRYPT_CHAIN_MODE_ECB)),
                                      0))) {
                BCryptCloseAlgorithmProvider(alg, 0);
                return nullptr;
            }
        }
        return alg;
    }

    mutable QMutex                                                       _mutex;
    mutable std::array<BCRYPT_ALG_HANDLE, std::size_t(Algorithm::Count)> _handles {};
    mutable std::array<bool, std::size_t(Algorithm::Count)>              _opened {};
};

namespace {

WinCryptoProvider *cng(Provider *provider)
{
    return static_cast<WinCryptoProvider *>(provider);
}

// A CNG hash or HMAC object, with the data hashed so far.
class HashObject
{
public:
    HashObject()                              = default;
    HashObject(const HashObject &)            = delete;
    HashObject &operator=(const HashObject &) = delete;
    ~HashObject()
    {
        reset();
    }

    bool create(BCRYPT_ALG_HANDLE alg, const SecureArray *secret)
    {
        reset();
        if (!alg)
            return false;
        PUCHAR key    = nullptr;
        ULONG  length = 0;
        if (secret) {
            // HMAC pads its key with zeros, so an empty key is the same as
            // one zero byte, which CNG accepts.
            key    = secret->isEmpty() ? emptyInput() : bytes(secret->constData());
            length = secret->isEmpty() ? 1 : ULONG(secret->size());
        }
        return ok(BCryptCreateHash(alg, &_hash, nullptr, 0, key, length, 0));
    }

    bool duplicate(const HashObject &other)
    {
        reset();
        return other._hash && ok(BCryptDuplicateHash(other._hash, &_hash, nullptr, 0, 0));
    }

    void update(const char *data, int size)
    {
        if (_hash && size > 0)
            BCryptHashData(_hash, bytes(data), ULONG(size), 0);
    }

    SecureArray finish(int length)
    {
        SecureArray result(length);
        if (!_hash || length <= 0 ||
            !ok(BCryptFinishHash(_hash, reinterpret_cast<PUCHAR>(result.data()), ULONG(length), 0)))
            result.clear();
        // A finished CNG hash cannot be used again.
        reset();
        return result;
    }

    bool isValid() const
    {
        return _hash;
    }

private:
    void reset()
    {
        if (_hash)
            BCryptDestroyHash(_hash);
        _hash = nullptr;
    }

    BCRYPT_HASH_HANDLE _hash = nullptr;
};

// HMAC(key, data) in one call, for HKDF.
SecureArray hmac(WinCryptoProvider *provider, Algorithm algorithm, const SecureArray &key, const QByteArray &data)
{
    HashObject object;
    if (!object.create(provider->handle(algorithm), &key))
        return {};
    object.update(data.constData(), data.size());
    return object.finish(provider->hashLength(algorithm));
}

}

//----------------------------------------------------------------------------
// Random
//----------------------------------------------------------------------------
class WinCryptoRandomContext : public RandomContext
{
    Q_OBJECT
public:
    WinCryptoRandomContext(Provider *p)
        : RandomContext(p)
    {
    }

    Context *clone() const override
    {
        return new WinCryptoRandomContext(*this);
    }

    SecureArray nextBytes(int size) override
    {
        SecureArray buffer(qMax(0, size));
        if (size > 0 &&
            !ok(BCryptGenRandom(
                nullptr, reinterpret_cast<PUCHAR>(buffer.data()), ULONG(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
            buffer.clear();
        return buffer;
    }
};

//----------------------------------------------------------------------------
// Hash
//----------------------------------------------------------------------------
class WinCryptoHashContext : public HashContext
{
    Q_OBJECT
public:
    WinCryptoHashContext(Algorithm algorithm, Provider *p, const QString &type)
        : HashContext(p, type)
        , _algorithm(algorithm)
    {
        clear();
    }

    WinCryptoHashContext(const WinCryptoHashContext &other)
        : HashContext(other)
        , _algorithm(other._algorithm)
    {
        _hash.duplicate(other._hash);
    }

    Context *clone() const override
    {
        return new WinCryptoHashContext(*this);
    }

    void clear() override
    {
        _hash.create(cng(provider())->handle(_algorithm), nullptr);
    }

    void update(const MemoryRegion &a) override
    {
        _hash.update(a.constData(), a.size());
    }

    MemoryRegion final() override
    {
        const SecureArray result = _hash.finish(cng(provider())->hashLength(_algorithm));
        clear();
        return result;
    }

private:
    Algorithm  _algorithm;
    HashObject _hash;
};

//----------------------------------------------------------------------------
// HMAC
//----------------------------------------------------------------------------
class WinCryptoHMACContext : public MACContext
{
    Q_OBJECT
public:
    WinCryptoHMACContext(Algorithm algorithm, Provider *p, const QString &type)
        : MACContext(p, type)
        , _algorithm(algorithm)
    {
    }

    WinCryptoHMACContext(const WinCryptoHMACContext &other)
        : MACContext(other)
        , _algorithm(other._algorithm)
        , _key(other._key)
    {
        _hash.duplicate(other._hash);
    }

    Context *clone() const override
    {
        return new WinCryptoHMACContext(*this);
    }

    void setup(const SymmetricKey &key) override
    {
        _key = key;
        _hash.create(cng(provider())->handle(_algorithm), &_key);
    }

    KeyLength keyLength() const override
    {
        return anyKeyLength();
    }

    void update(const MemoryRegion &in) override
    {
        _hash.update(in.constData(), in.size());
    }

    void final(MemoryRegion *out) override
    {
        *out = _hash.finish(cng(provider())->hashLength(_algorithm));
        // Ready for the same key again.
        _hash.create(cng(provider())->handle(_algorithm), &_key);
    }

private:
    Algorithm   _algorithm;
    SecureArray _key;
    HashObject  _hash;
};

//----------------------------------------------------------------------------
// PBKDF2
//----------------------------------------------------------------------------
class WinCryptoPbkdf2Context : public KDFContext
{
    Q_OBJECT
public:
    WinCryptoPbkdf2Context(Algorithm hmacAlgorithm, Provider *p, const QString &type)
        : KDFContext(p, type)
        , _algorithm(hmacAlgorithm)
    {
    }

    Context *clone() const override
    {
        return new WinCryptoPbkdf2Context(*this);
    }

    SymmetricKey makeKey(const SecureArray          &secret,
                         const InitializationVector &salt,
                         unsigned int                keyLength,
                         unsigned int                iterationCount) override
    {
        SecureArray       out(static_cast<int>(keyLength));
        BCRYPT_ALG_HANDLE prf = cng(provider())->handle(_algorithm);
        if (!prf || !keyLength ||
            !ok(BCryptDeriveKeyPBKDF2(prf,
                                      secret.isEmpty() ? emptyInput() : bytes(secret.constData()),
                                      ULONG(secret.size()),
                                      salt.isEmpty() ? emptyInput() : bytes(salt.constData()),
                                      ULONG(salt.size()),
                                      ULONGLONG(iterationCount),
                                      reinterpret_cast<PUCHAR>(out.data()),
                                      ULONG(keyLength),
                                      0)))
            return SymmetricKey();
        return out;
    }

    SymmetricKey makeKey(const SecureArray          &secret,
                         const InitializationVector &salt,
                         unsigned int                keyLength,
                         int                         msecInterval,
                         unsigned int               *iterationCount) override
    {
        Q_ASSERT(iterationCount != nullptr);
        // As the OpenSSL provider: count single iterations for the given
        // time, then derive the key with that many.
        QElapsedTimer timer;
        *iterationCount = 0;
        timer.start();
        while (timer.elapsed() < msecInterval) {
            makeKey(secret, salt, keyLength, 1u);
            ++(*iterationCount);
        }
        return makeKey(secret, salt, keyLength, *iterationCount);
    }

private:
    Algorithm _algorithm;
};

//----------------------------------------------------------------------------
// HKDF (RFC 5869) on CNG's HMAC
//----------------------------------------------------------------------------
class WinCryptoHkdfContext : public HKDFContext
{
    Q_OBJECT
public:
    WinCryptoHkdfContext(Algorithm hmacAlgorithm, Provider *p, const QString &type)
        : HKDFContext(p, type)
        , _algorithm(hmacAlgorithm)
    {
    }

    Context *clone() const override
    {
        return new WinCryptoHkdfContext(*this);
    }

    SymmetricKey makeKey(const SecureArray          &secret,
                         const InitializationVector &salt,
                         const InitializationVector &info,
                         unsigned int                keyLength) override
    {
        WinCryptoProvider *p      = cng(provider());
        const int          length = p->hashLength(_algorithm);
        if (length <= 0 || keyLength == 0 || keyLength > 255u * unsigned(length))
            return SymmetricKey();

        // Extract: a missing salt is a string of zeros as long as the hash.
        const SecureArray prk =
            hmac(p, _algorithm, salt.isEmpty() ? SecureArray(length, 0) : SecureArray(salt), secret.toByteArray());
        if (prk.size() != length)
            return SymmetricKey();

        // Expand.
        SecureArray out;
        SecureArray previous;
        for (unsigned char counter = 1; unsigned(out.size()) < keyLength; ++counter) {
            QByteArray input = previous.toByteArray() + info.toByteArray();
            input.append(char(counter));
            previous = hmac(p, _algorithm, prk, input);
            if (previous.size() != length)
                return SymmetricKey();
            out.append(previous);
        }
        out.resize(int(keyLength));
        return out;
    }

private:
    Algorithm _algorithm;
};

//----------------------------------------------------------------------------
// AES
//----------------------------------------------------------------------------
namespace {

// AES on whole blocks with a CNG key in ECB mode.
class CngAes final : public BlockCipher
{
public:
    static std::unique_ptr<CngAes> create(BCRYPT_ALG_HANDLE alg, const SecureArray &key)
    {
        if (!alg)
            return nullptr;
        BCRYPT_KEY_HANDLE handle = nullptr;
        if (!ok(BCryptGenerateSymmetricKey(alg, &handle, nullptr, 0, bytes(key.constData()), ULONG(key.size()), 0)))
            return nullptr;
        return std::unique_ptr<CngAes>(new CngAes(handle));
    }

    ~CngAes() override
    {
        if (_key)
            BCryptDestroyKey(_key);
    }

    std::unique_ptr<BlockCipher> clone() const override
    {
        BCRYPT_KEY_HANDLE copy = nullptr;
        if (!ok(BCryptDuplicateKey(_key, &copy, nullptr, 0, 0)))
            return nullptr;
        return std::unique_ptr<BlockCipher>(new CngAes(copy));
    }

    bool encrypt(const std::uint8_t *in, std::uint8_t *out, std::size_t blocks) override
    {
        ULONG       written = 0;
        const ULONG size    = ULONG(blocks * BlockSize);
        return ok(BCryptEncrypt(_key, bytes(in), size, nullptr, nullptr, 0, out, size, &written, 0)) && written == size;
    }

    bool decrypt(const std::uint8_t *in, std::uint8_t *out, std::size_t blocks) override
    {
        ULONG       written = 0;
        const ULONG size    = ULONG(blocks * BlockSize);
        return ok(BCryptDecrypt(_key, bytes(in), size, nullptr, nullptr, 0, out, size, &written, 0)) && written == size;
    }

private:
    explicit CngAes(BCRYPT_KEY_HANDLE key)
        : _key(key)
    {
    }

    BCRYPT_KEY_HANDLE _key = nullptr;
};

Bytes toBytes(const MemoryRegion &region)
{
    const auto *data = reinterpret_cast<const std::uint8_t *>(region.constData());
    return Bytes(data, data + region.size());
}

}

class WinCryptoCipherContext : public CipherContext
{
    Q_OBJECT
public:
    // type: "aes128-cbc-pkcs7" and the like.
    WinCryptoCipherContext(int keyBytes, CipherMode mode, bool pkcs7, Provider *p, const QString &type)
        : CipherContext(p, type)
        , _keyBytes(keyBytes)
        , _mode(mode)
        , _pkcs7(pkcs7)
    {
    }

    WinCryptoCipherContext(const WinCryptoCipherContext &other)
        : CipherContext(other)
        , _keyBytes(other._keyBytes)
        , _mode(other._mode)
        , _pkcs7(other._pkcs7)
        , _engine(other._engine ? new ModeEngine(*other._engine) : nullptr)
        , _tag(other._tag)
    {
    }

    Context *clone() const override
    {
        return new WinCryptoCipherContext(*this);
    }

    void setup(Direction dir, const SymmetricKey &key, const InitializationVector &iv, const AuthTag &tag) override
    {
        _tag = tag;
        _engine.reset();
        if (key.size() != _keyBytes)
            return;
        auto aes = CngAes::create(cng(provider())->handle(Algorithm::AES), key);
        if (!aes)
            return;
        Bytes ivBytes  = toBytes(iv);
        Bytes tagBytes = toBytes(tag);
        _engine.reset(new ModeEngine(_mode, _pkcs7, dir == Encode, std::move(aes), ivBytes, tagBytes));
        secureWipe(ivBytes);
        secureWipe(tagBytes);
    }

    KeyLength keyLength() const override
    {
        return KeyLength(_keyBytes, _keyBytes, 1);
    }

    int blockSize() const override
    {
        return int(ModeEngine::blockSize(_mode));
    }

    AuthTag tag() const override
    {
        return _tag;
    }

    bool update(const SecureArray &in, SecureArray *out) override
    {
        if (!_engine)
            return false;
        Bytes      result;
        const bool done = _engine->update(
            reinterpret_cast<const std::uint8_t *>(in.constData()), std::size_t(qMax(0, in.size())), result);
        *out = SecureArray(QByteArray(reinterpret_cast<const char *>(result.data()), int(result.size())));
        secureWipe(result);
        return done;
    }

    bool final(SecureArray *out) override
    {
        if (!_engine)
            return false;
        Bytes      result;
        const bool done = _engine->final(result);
        *out            = SecureArray(QByteArray(reinterpret_cast<const char *>(result.data()), int(result.size())));
        secureWipe(result);
        if (done && _mode == CipherMode::GCM && !_engine->tag().empty())
            _tag = AuthTag(SecureArray(
                QByteArray(reinterpret_cast<const char *>(_engine->tag().data()), int(_engine->tag().size()))));
        return done;
    }

private:
    int                         _keyBytes;
    CipherMode                  _mode;
    bool                        _pkcs7;
    std::unique_ptr<ModeEngine> _engine;
    AuthTag                     _tag;
};

//----------------------------------------------------------------------------
// Provider
//----------------------------------------------------------------------------
namespace {

struct HashType
{
    const char *name;
    Algorithm   hash;
    Algorithm   hmac;
};

// HMAC and PBKDF2 are offered for the hashes that have a CNG HMAC handle.
const HashType hashTypes[] = {
    {"md5", Algorithm::MD5, Algorithm::HmacMD5},
    {"sha1", Algorithm::SHA1, Algorithm::HmacSHA1},
    {"sha256", Algorithm::SHA256, Algorithm::HmacSHA256},
    {"sha384", Algorithm::SHA384, Algorithm::HmacSHA384},
    {"sha512", Algorithm::SHA512, Algorithm::HmacSHA512},
};

struct Sha3Type
{
    const char *name;
    Algorithm   hash;
};

const Sha3Type sha3Types[] = {
    {"sha3_256", Algorithm::SHA3_256},
    {"sha3_384", Algorithm::SHA3_384},
    {"sha3_512", Algorithm::SHA3_512},
};

struct ModeType
{
    const char *name;
    CipherMode  mode;
    bool        pkcs7;
};

const ModeType modeTypes[] = {
    {"ecb", CipherMode::ECB, false},
    {"cbc", CipherMode::CBC, false},
    {"cbc-pkcs7", CipherMode::CBC, true},
    {"cfb", CipherMode::CFB, false},
    {"ofb", CipherMode::OFB, false},
    {"ctr", CipherMode::CTR, false},
    {"gcm", CipherMode::GCM, false},
};

const int aesKeyBits[] = {128, 192, 256};

QString aesType(int bits, const ModeType &mode)
{
    return QStringLiteral("aes%1-%2").arg(bits).arg(QLatin1String(mode.name));
}

}

QStringList WinCryptoProvider::features() const
{
    QStringList list;
    list += QStringLiteral("random");
    for (const auto &type : hashTypes)
        list += QLatin1String(type.name);
    for (const auto &type : sha3Types)
        if (handle(type.hash))
            list += QLatin1String(type.name);
    for (const auto &type : hashTypes)
        list += QStringLiteral("hmac(%1)").arg(QLatin1String(type.name));
    list += QStringLiteral("pbkdf2(sha1)");
    list += QStringLiteral("pbkdf2(sha256)");
    list += QStringLiteral("pbkdf2(sha512)");
    list += QStringLiteral("hkdf(sha256)");
    for (int bits : aesKeyBits)
        for (const auto &mode : modeTypes)
            list += aesType(bits, mode);
    return list;
}

Provider::Context *WinCryptoProvider::createContext(const QString &type)
{
    if (type == QLatin1String("random"))
        return new WinCryptoRandomContext(this);
    for (const auto &hash : hashTypes) {
        if (type == QLatin1String(hash.name))
            return new WinCryptoHashContext(hash.hash, this, type);
        if (type == QStringLiteral("hmac(%1)").arg(QLatin1String(hash.name)))
            return new WinCryptoHMACContext(hash.hmac, this, type);
    }
    for (const auto &sha3 : sha3Types)
        if (type == QLatin1String(sha3.name) && handle(sha3.hash))
            return new WinCryptoHashContext(sha3.hash, this, type);
    if (type == QLatin1String("pbkdf2(sha1)"))
        return new WinCryptoPbkdf2Context(Algorithm::HmacSHA1, this, type);
    if (type == QLatin1String("pbkdf2(sha256)"))
        return new WinCryptoPbkdf2Context(Algorithm::HmacSHA256, this, type);
    if (type == QLatin1String("pbkdf2(sha512)"))
        return new WinCryptoPbkdf2Context(Algorithm::HmacSHA512, this, type);
    if (type == QLatin1String("hkdf(sha256)"))
        return new WinCryptoHkdfContext(Algorithm::HmacSHA256, this, type);
    for (int bits : aesKeyBits)
        for (const auto &mode : modeTypes)
            if (type == aesType(bits, mode))
                return new WinCryptoCipherContext(bits / 8, mode.mode, mode.pkcs7, this, type);
    return nullptr;
}

}

//----------------------------------------------------------------------------
// Plugin
//----------------------------------------------------------------------------
class qca_wincrypto : public QObject, public QCAPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
    Q_INTERFACES(QCAPlugin)
public:
    Provider *createProvider() override
    {
        return new wincryptoQCAPlugin::WinCryptoProvider;
    }
};

#include "qca-wincrypto.moc"
