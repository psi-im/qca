// SPDX-License-Identifier: LGPL-2.1-or-later
#include "native_keys.h"
#include <QCoreApplication>
#include <QMetaObject>
#include <QUuid>
#include <algorithm>
#include <bcrypt.h>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>
#include <wincrypt.h>

using namespace QCA;
namespace wincryptoQCAPlugin {
namespace {
struct NativeKey
{
    NCRYPT_KEY_HANDLE value = 0;
    ~NativeKey()
    {
        if (value)
            NCryptFreeObject(value);
    }
};
std::shared_ptr<NativeKey> generateRSA(int bits, int exponent)
{
    if (bits < 2048 || bits > 8192 || bits % 64 || exponent != 65537)
        return {};
    NCRYPT_PROV_HANDLE provider = 0;
    if (NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
        return {};
    auto  key    = std::make_shared<NativeKey>();
    auto  status = NCryptCreatePersistedKey(provider, &key->value, NCRYPT_RSA_ALGORITHM, nullptr, 0, 0);
    DWORD length = DWORD(bits);
    // This unnamed key stays in memory. Export is allowed only for the
    // internal Schannel credential bridge, never through QCA serialization.
    DWORD policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
    if (!status)
        status =
            NCryptSetProperty(key->value, NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&length), sizeof(length), 0);
    if (!status)
        status = NCryptSetProperty(
            key->value, NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&policy), sizeof(policy), 0);
    if (!status)
        status = NCryptFinalizeKey(key->value, NCRYPT_SILENT_FLAG);
    NCryptFreeObject(provider);
    return status ? std::shared_ptr<NativeKey>() : key;
}

class WinRSA : public RSAContext
{
public:
    explicit WinRSA(Provider *provider)
        : RSAContext(provider)
    {
    }
    WinRSA(const WinRSA &other)
        : RSAContext(other)
        , _key(other._key)
        , _public(other._public)
        , _publicBits(other._publicBits)
        , _publicN(other._publicN)
        , _publicE(other._publicE)
    {
    }
    ~WinRSA() override
    {
        if (_worker.joinable())
            _worker.join();
    }
    Context *clone() const override
    {
        return new WinRSA(*this);
    }
    bool isNull() const override
    {
        return !_key && !_publicBits;
    }
    PKey::Type type() const override
    {
        return PKey::RSA;
    }
    bool isPrivate() const override
    {
        return _key && !_public;
    }
    bool canExport() const override
    {
        return false;
    }
    void convertToPublic() override
    {
        // Keep only already-public metadata in this view. In particular, a
        // public view must not prolong the lifetime of the native private key.
        _publicN    = n();
        _publicE    = e();
        _publicBits = bits();
        _key.reset();
        _public = true;
    }
    int bits() const override
    {
        if (_public)
            return _publicBits;
        DWORD value = 0, written = 0;
        return _key &&
                NCryptGetProperty(
                    _key->value, NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&value), sizeof(value), &written, 0) ==
                    ERROR_SUCCESS
            ? int(value)
            : 0;
    }
    void createPrivate(int bits, int exponent, bool block) override
    {
        clearKey();
        if (block)
            _key = generateRSA(bits, exponent);
        else
            _worker = std::thread([this, bits, exponent] {
                _key = generateRSA(bits, exponent);
                QMetaObject::invokeMethod(this, [this] { emit finished(); }, Qt::QueuedConnection);
            });
    }
    void createPrivate(const BigInteger &,
                       const BigInteger &,
                       const BigInteger &,
                       const BigInteger &,
                       const BigInteger &) override
    {
        clearKey();
    }
    void createPublic(const BigInteger &, const BigInteger &) override
    {
        clearKey();
    }
    BigInteger n() const override
    {
        return _public ? _publicN : component(false);
    }
    BigInteger e() const override
    {
        return _public ? _publicE : component(true);
    }
    BigInteger p() const override
    {
        return {};
    }
    BigInteger q() const override
    {
        return {};
    }
    BigInteger d() const override
    {
        return {};
    }
    NCRYPT_KEY_HANDLE handle() const
    {
        return isPrivate() ? _key->value : 0;
    }

private:
    void clearKey()
    {
        if (_worker.joinable())
            _worker.join();
        _key.reset();
        _public     = false;
        _publicBits = 0;
        _publicN    = BigInteger();
        _publicE    = BigInteger();
    }
    BigInteger component(bool exponent) const
    {
        if (!_key)
            return {};
        DWORD size = 0;
        if (NCryptExportKey(_key->value, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, nullptr, 0, &size, 0) != ERROR_SUCCESS ||
            size < sizeof(BCRYPT_RSAKEY_BLOB) || size > 16384)
            return {};
        SecureArray blob {int(size)};
        if (NCryptExportKey(
                _key->value, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, reinterpret_cast<PBYTE>(blob.data()), size, &size, 0) !=
            ERROR_SUCCESS)
            return {};
        BCRYPT_RSAKEY_BLOB header;
        std::memcpy(&header, blob.constData(), sizeof(header));
        if (header.cbPublicExp > size - sizeof(header) || header.cbModulus > size - sizeof(header) - header.cbPublicExp)
            return {};
        const auto  length = exponent ? header.cbPublicExp : header.cbModulus;
        const auto  offset = sizeof(header) + (exponent ? 0 : header.cbPublicExp);
        SecureArray positive(int(length) + 1);
        positive[0] = 0;
        std::memcpy(positive.data() + 1, blob.constData() + offset, length);
        return BigInteger(positive);
    }
    std::shared_ptr<NativeKey> _key;
    bool                       _public     = false;
    int                        _publicBits = 0;
    BigInteger                 _publicN, _publicE;
    std::thread                _worker;
};

class WinPKey : public PKeyContext
{
public:
    explicit WinPKey(Provider *provider)
        : PKeyContext(provider)
    {
    }
    WinPKey(const WinPKey &other)
        : PKeyContext(other)
        , _key(other._key ? static_cast<PKeyBase *>(other._key->clone()) : nullptr)
    {
    }
    Context *clone() const override
    {
        return new WinPKey(*this);
    }
    QList<PKey::Type> supportedTypes() const override
    {
        return {PKey::RSA};
    }
    QList<PKey::Type> supportedIOTypes() const override
    {
        return {};
    }
    QList<PBEAlgorithm> supportedPBEAlgorithms() const override
    {
        return {};
    }
    PKeyBase *key() override
    {
        return _key.get();
    }
    const PKeyBase *key() const override
    {
        return _key.get();
    }
    void setKey(PKeyBase *key) override
    {
        _key.reset(key);
    }
    bool importKey(const PKeyBase *key) override
    {
        const auto *native = dynamic_cast<const WinRSA *>(key);
        if (!native)
            return false;
        _key.reset(static_cast<PKeyBase *>(native->clone()));
        return !_key->isNull();
    }

private:
    std::unique_ptr<PKeyBase> _key;
};

QByteArray encode(LPCSTR type, const void *value)
{
    DWORD length = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, type, value, 0, nullptr, nullptr, &length) || length > 1024 * 1024)
        return {};
    QByteArray result(int(length), 0);
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, type, value, 0, nullptr, result.data(), &length))
        return {};
    result.resize(int(length));
    return result;
}
FILETIME fileTime(const QDateTime &date)
{
    ULARGE_INTEGER value;
    value.QuadPart = quint64(date.toMSecsSinceEpoch() + 11644473600000LL) * 10000;
    return {value.LowPart, value.HighPart};
}
} // namespace

Provider::Context *createRSAContext(Provider *provider)
{
    return new WinRSA(provider);
}
Provider::Context *createPKeyContext(Provider *provider)
{
    return new WinPKey(provider);
}
NCRYPT_KEY_HANDLE nativePrivateKey(const PKeyContext &key)
{
    const auto *rsa = dynamic_cast<const WinRSA *>(key.key());
    return rsa ? rsa->handle() : 0;
}

CredentialCertificate::~CredentialCertificate()
{
    if (certificate)
        CertFreeCertificateContext(certificate);
    if (store)
        CertCloseStore(store, 0);
    if (!removeTemporaryKey())
        NCryptFreeObject(temporaryKey);
}
bool CredentialCertificate::removeTemporaryKey()
{
    if (!temporaryKey)
        return true;
    if (NCryptDeleteKey(temporaryKey, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
        return false;
    temporaryKey = 0;
    return true;
}
std::unique_ptr<CredentialCertificate> createCredentialCertificate(const CertificateChain &chain, const PrivateKey &key)
{
    if (chain.isEmpty() || key.isNull())
        return {};
    const auto handle = nativePrivateKey(*static_cast<const PKeyContext *>(key.context()));
    if (!handle)
        return {};
    auto identity   = std::make_unique<CredentialCertificate>();
    identity->store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr);
    if (!identity->store)
        return {};
    for (int i = 0; i < chain.size(); ++i) {
        const auto der = chain[i].toDER();
        if (!CertAddEncodedCertificateToStore(identity->store,
                                              X509_ASN_ENCODING,
                                              reinterpret_cast<const BYTE *>(der.constData()),
                                              DWORD(der.size()),
                                              CERT_STORE_ADD_ALWAYS,
                                              i == 0 ? &identity->certificate : nullptr))
            return {};
    }
    DWORD size = 0;
    if (!CryptExportPublicKeyInfo(handle, CERT_NCRYPT_KEY_SPEC, X509_ASN_ENCODING, nullptr, &size) || size > 65536)
        return {};
    std::vector<BYTE> pub(size);
    if (!CryptExportPublicKeyInfo(handle,
                                  CERT_NCRYPT_KEY_SPEC,
                                  X509_ASN_ENCODING,
                                  reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(pub.data()),
                                  &size) ||
        !CertComparePublicKeyInfo(X509_ASN_ENCODING,
                                  reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(pub.data()),
                                  &identity->certificate->pCertInfo->SubjectPublicKeyInfo))
        return {};
    if (NCryptExportKey(handle, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, nullptr, nullptr, 0, &size, 0) != ERROR_SUCCESS ||
        size > 65536)
        return {};
    SecureArray exported {int(size)};
    if (NCryptExportKey(handle,
                        0,
                        NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                        nullptr,
                        reinterpret_cast<PBYTE>(exported.data()),
                        size,
                        &size,
                        0) != ERROR_SUCCESS)
        return {};
    NCRYPT_PROV_HANDLE provider = 0;
    if (NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
        return {};
    const auto   name = QStringLiteral("qca-wincrypto-%1-%2")
                            .arg(QCoreApplication::applicationPid())
                            .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
    NCryptBuffer buffer {
        DWORD((name.size() + 1) * sizeof(wchar_t)), NCRYPTBUFFER_PKCS_KEY_NAME, const_cast<ushort *>(name.utf16())};
    NCryptBufferDesc parameters {NCRYPTBUFFER_VERSION, 1, &buffer};
    auto             status = NCryptImportKey(provider,
                                              0,
                                              NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                                              &parameters,
                                              &identity->temporaryKey,
                                              reinterpret_cast<PBYTE>(exported.data()),
                                              size,
                                              NCRYPT_DO_NOT_FINALIZE_FLAG | NCRYPT_SILENT_FLAG);
    if (!status)
        status = NCryptFinalizeKey(identity->temporaryKey, NCRYPT_SILENT_FLAG);
    NCryptFreeObject(provider);
    exported.clear();
    if (status)
        return {};
    CRYPT_KEY_PROV_INFO info {};
    info.pwszContainerName = const_cast<LPWSTR>(reinterpret_cast<const wchar_t *>(name.utf16()));
    info.pwszProvName      = const_cast<LPWSTR>(MS_KEY_STORAGE_PROVIDER);
    info.dwFlags           = NCRYPT_SILENT_FLAG;
    if (!CertSetCertificateContextProperty(identity->certificate, CERT_KEY_PROV_INFO_PROP_ID, 0, &info))
        return {};
    return identity;
}

QByteArray createSelfSignedCertificate(const CertificateOptions &opts, const PKeyContext &key)
{
    const auto handle = nativePrivateKey(key);
    if (!handle || !opts.notValidBefore().isValid() || !opts.notValidAfter().isValid() ||
        opts.notValidAfter() <= opts.notValidBefore() ||
        opts.notValidBefore().toMSecsSinceEpoch() < -11644473600000LL || opts.serialNumber() <= BigInteger(0) ||
        !opts.policies().isEmpty() || !opts.crlLocations().isEmpty() || !opts.issuerLocations().isEmpty() ||
        !opts.ocspLocations().isEmpty())
        return {};
    const auto                 info = opts.infoOrdered().dnOnly();
    std::vector<QByteArray>    names, values;
    std::vector<CERT_RDN_ATTR> attrs;
    std::vector<CERT_RDN>      rdns;
    names.reserve(info.size());
    values.reserve(info.size());
    attrs.reserve(info.size());
    rdns.reserve(info.size());
    for (const auto &item : info) {
        if (item.value().contains(QChar(0)))
            return {};
        names.push_back(item.type().id().toLatin1());
        const auto text = item.value();
        values.emplace_back(reinterpret_cast<const char *>(text.utf16()), int(text.size() * sizeof(wchar_t)));
        attrs.push_back({names.back().data(),
                         CERT_RDN_UTF8_STRING,
                         {DWORD(values.back().size()), reinterpret_cast<PBYTE>(values.back().data())}});
        rdns.push_back({1, &attrs.back()});
    }
    CERT_NAME_INFO name {DWORD(rdns.size()), rdns.data()};
    auto           subject = encode(X509_UNICODE_NAME, &name);
    if (subject.isEmpty())
        return {};
    auto       serialSecure = opts.serialNumber().toArray();
    QByteArray serial(serialSecure.constData(), serialSecure.size());
    while (serial.size() > 1 && serial[0] == 0)
        serial.remove(0, 1);
    if (serial.size() > 20)
        return {};
    std::reverse(serial.begin(), serial.end());
    DWORD pubSize = 0;
    if (!CryptExportPublicKeyInfo(handle, CERT_NCRYPT_KEY_SPEC, X509_ASN_ENCODING, nullptr, &pubSize) ||
        pubSize > 65536)
        return {};
    std::vector<BYTE> publicInfo(pubSize);
    if (!CryptExportPublicKeyInfo(handle,
                                  CERT_NCRYPT_KEY_SPEC,
                                  X509_ASN_ENCODING,
                                  reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(publicInfo.data()),
                                  &pubSize))
        return {};
    std::vector<CERT_EXTENSION> extensions;
    std::vector<QByteArray>     extensionValues;
    extensionValues.reserve(4);
    extensions.reserve(4);
    const auto add = [&](const char *oid, LPCSTR type, const void *data, bool critical) {
        auto encoded = encode(type, data);
        if (encoded.isEmpty())
            return false;
        extensionValues.push_back(encoded);
        extensions.push_back({const_cast<char *>(oid),
                              critical,
                              {DWORD(encoded.size()), reinterpret_cast<PBYTE>(extensionValues.back().data())}});
        return true;
    };
    CERT_BASIC_CONSTRAINTS2_INFO basic {
        opts.isCA(), opts.isCA() && opts.pathLimit() >= 0, DWORD(std::max(0, opts.pathLimit()))};
    if (!add(szOID_BASIC_CONSTRAINTS2, X509_BASIC_CONSTRAINTS2, &basic, true))
        return {};
    BYTE                    usageBytes[2] {};
    std::vector<QByteArray> ekuNames;
    for (const auto &constraint : opts.constraints()) {
        if (constraint.section() == ConstraintType::ExtendedKeyUsage)
            ekuNames.push_back(constraint.id().toLatin1());
        else
            switch (constraint.known()) {
            case DigitalSignature:
                usageBytes[0] |= CERT_DIGITAL_SIGNATURE_KEY_USAGE;
                break;
            case NonRepudiation:
                usageBytes[0] |= CERT_NON_REPUDIATION_KEY_USAGE;
                break;
            case KeyEncipherment:
                usageBytes[0] |= CERT_KEY_ENCIPHERMENT_KEY_USAGE;
                break;
            case DataEncipherment:
                usageBytes[0] |= CERT_DATA_ENCIPHERMENT_KEY_USAGE;
                break;
            case KeyAgreement:
                usageBytes[0] |= CERT_KEY_AGREEMENT_KEY_USAGE;
                break;
            case KeyCertificateSign:
                usageBytes[0] |= CERT_KEY_CERT_SIGN_KEY_USAGE;
                break;
            case CRLSign:
                usageBytes[0] |= CERT_CRL_SIGN_KEY_USAGE;
                break;
            default:
                return {};
            }
    }
    if (usageBytes[0]) {
        CRYPT_BIT_BLOB usage {1, usageBytes, 0};
        if (!add(szOID_KEY_USAGE, X509_KEY_USAGE, &usage, true))
            return {};
    }
    if (!ekuNames.empty()) {
        std::vector<LPSTR> ids;
        for (auto &id : ekuNames)
            ids.push_back(id.data());
        CERT_ENHKEY_USAGE eku {DWORD(ids.size()), ids.data()};
        if (!add(szOID_ENHANCED_KEY_USAGE, X509_ENHANCED_KEY_USAGE, &eku, false))
            return {};
    }
    std::vector<CERT_ALT_NAME_ENTRY> alternatives;
    std::vector<QString>             dnsNames;
    std::vector<QByteArray>          xmppNames;
    std::vector<CERT_OTHER_NAME>     otherNames;
    const auto                       allInfo = opts.infoOrdered();
    alternatives.reserve(allInfo.size());
    dnsNames.reserve(allInfo.size());
    xmppNames.reserve(allInfo.size());
    otherNames.reserve(allInfo.size());
    for (const auto &item : allInfo) {
        if (item.type().section() == CertificateInfoType::DN)
            continue;
        CERT_ALT_NAME_ENTRY entry {};
        if (item.value().contains(QChar(0)))
            return {};
        if (item.type() == DNS) {
            dnsNames.push_back(item.value());
            entry.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
            entry.pwszDNSName     = reinterpret_cast<LPWSTR>(dnsNames.back().data());
        } else if (item.type() == XMPP) {
            const auto      text = item.value();
            CERT_NAME_VALUE value {
                CERT_RDN_UTF8_STRING,
                {DWORD(text.size() * sizeof(wchar_t)), reinterpret_cast<PBYTE>(const_cast<ushort *>(text.utf16()))}};
            xmppNames.push_back(encode(X509_UNICODE_ANY_STRING, &value));
            if (xmppNames.back().isEmpty())
                return {};
            otherNames.push_back({const_cast<char *>("1.3.6.1.5.5.7.8.5"),
                                  {DWORD(xmppNames.back().size()), reinterpret_cast<PBYTE>(xmppNames.back().data())}});
            entry.dwAltNameChoice = CERT_ALT_NAME_OTHER_NAME;
            entry.pOtherName      = &otherNames.back();
        } else
            return {};
        alternatives.push_back(entry);
    }
    if (!alternatives.empty()) {
        CERT_ALT_NAME_INFO alt {DWORD(alternatives.size()), alternatives.data()};
        if (!add(szOID_SUBJECT_ALT_NAME2, X509_ALTERNATE_NAME, &alt, false))
            return {};
    }
    CERT_INFO cert {};
    cert.dwVersion          = CERT_V3;
    cert.SerialNumber       = {DWORD(serial.size()), reinterpret_cast<PBYTE>(serial.data())};
    cert.SignatureAlgorithm = {const_cast<char *>(szOID_RSA_SHA256RSA), {0, nullptr}};
    cert.Subject = cert.Issuer = {DWORD(subject.size()), reinterpret_cast<PBYTE>(subject.data())};
    cert.NotBefore             = fileTime(opts.notValidBefore());
    cert.NotAfter              = fileTime(opts.notValidAfter());
    cert.SubjectPublicKeyInfo  = *reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(publicInfo.data());
    cert.cExtension            = DWORD(extensions.size());
    cert.rgExtension           = extensions.data();
    DWORD size                 = 0;
    if (!CryptSignAndEncodeCertificate(handle,
                                       CERT_NCRYPT_KEY_SPEC,
                                       X509_ASN_ENCODING,
                                       X509_CERT_TO_BE_SIGNED,
                                       &cert,
                                       &cert.SignatureAlgorithm,
                                       nullptr,
                                       nullptr,
                                       &size) ||
        size > 1024 * 1024)
        return {};
    QByteArray result(int(size), 0);
    if (!CryptSignAndEncodeCertificate(handle,
                                       CERT_NCRYPT_KEY_SPEC,
                                       X509_ASN_ENCODING,
                                       X509_CERT_TO_BE_SIGNED,
                                       &cert,
                                       &cert.SignatureAlgorithm,
                                       nullptr,
                                       reinterpret_cast<PBYTE>(result.data()),
                                       &size))
        return {};
    result.resize(int(size));
    return result;
}
} // namespace wincryptoQCAPlugin
