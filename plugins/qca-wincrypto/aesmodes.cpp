/*
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

#include "aesmodes.h"

#include <algorithm>
#include <cstring>

namespace wincryptoQCAPlugin {

namespace {

constexpr std::size_t BlockSize = BlockCipher::BlockSize;

// GCM limits the plaintext to 2^39 - 256 bits.
constexpr std::uint64_t MaxGcmBytes = (std::uint64_t(1) << 36) - 32;

std::uint64_t loadBigEndian(const std::uint8_t *p)
{
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v = (v << 8) | p[i];
    return v;
}

void storeBigEndian(std::uint8_t *p, std::uint64_t v)
{
    for (int i = 7; i >= 0; --i) {
        p[i] = std::uint8_t(v);
        v >>= 8;
    }
}

// X = X * Y in GF(2^128) as GCM defines it (NIST SP 800-38D, algorithm 1),
// without branches or table lookups that depend on the data.
void gfMultiply(std::uint8_t *x, const std::uint8_t *y)
{
    std::uint64_t zHigh = 0, zLow = 0;
    std::uint64_t vHigh = loadBigEndian(y), vLow = loadBigEndian(y + 8);
    for (int i = 0; i < 128; ++i) {
        const std::uint64_t bit  = (x[i / 8] >> (7 - i % 8)) & 1;
        const std::uint64_t mask = 0 - bit;
        zHigh ^= vHigh & mask;
        zLow ^= vLow & mask;
        const std::uint64_t carry = 0 - (vLow & 1);
        vLow                      = (vLow >> 1) | (vHigh << 63);
        vHigh                     = (vHigh >> 1) ^ (0xe100000000000000ULL & carry);
    }
    storeBigEndian(x, zHigh);
    storeBigEndian(x + 8, zLow);
}

// The whole block as a 128-bit big-endian counter, as OpenSSL's CTR mode.
void increment128(std::uint8_t *counter)
{
    for (int i = int(BlockSize) - 1; i >= 0; --i)
        if (++counter[i] != 0)
            break;
}

// The last 32 bits as a big-endian counter, as GCM.
void increment32(std::uint8_t *counter)
{
    for (int i = int(BlockSize) - 1; i >= int(BlockSize) - 4; --i)
        if (++counter[i] != 0)
            break;
}

void xorBlock(std::uint8_t *out, const std::uint8_t *a, const std::uint8_t *b)
{
    for (std::size_t i = 0; i < BlockSize; ++i)
        out[i] = a[i] ^ b[i];
}

}

void secureWipe(void *data, std::size_t size)
{
    volatile auto *p = static_cast<volatile std::uint8_t *>(data);
    while (size--)
        *p++ = 0;
}

void secureWipe(Bytes &bytes)
{
    secureWipe(bytes.data(), bytes.size());
    bytes.clear();
}

ModeEngine::ModeEngine(CipherMode                   mode,
                       bool                         pkcs7,
                       bool                         encrypt,
                       std::unique_ptr<BlockCipher> cipher,
                       const Bytes                 &iv,
                       const Bytes                 &tag)
    : _mode(mode)
    , _pkcs7(pkcs7)
    , _encrypt(encrypt)
    , _cipher(std::move(cipher))
{
    if (!_cipher)
        return;
    if (pkcs7 && mode != CipherMode::ECB && mode != CipherMode::CBC)
        return;

    switch (mode) {
    case CipherMode::ECB:
        break;
    case CipherMode::CBC:
    case CipherMode::OFB:
    case CipherMode::CTR:
        if (iv.size() != BlockSize)
            return;
        std::memcpy(_register, iv.data(), BlockSize);
        break;
    case CipherMode::CFB:
        if (iv.size() != BlockSize)
            return;
        // The feedback register is encrypted in place into the keystream.
        std::memcpy(_keystream, iv.data(), BlockSize);
        break;
    case CipherMode::GCM:
    {
        if (iv.empty() || tag.size() > BlockSize || (!encrypt && tag.empty()))
            return;
        const Block zero {};
        if (!_cipher->encrypt(zero, _h, 1))
            return;
        if (iv.size() == 12) {
            std::memcpy(_j0, iv.data(), 12);
            _j0[15] = 1;
        } else {
            // Other IV lengths are hashed into the first counter block.
            ghashBytes(iv.data(), iv.size());
            Block lengths {};
            storeBigEndian(lengths + 8, std::uint64_t(iv.size()) * 8);
            if (_ghashFill) {
                std::memset(_ghashPartial + _ghashFill, 0, BlockSize - _ghashFill);
                ghashBlock(_ghashPartial);
                _ghashFill = 0;
            }
            ghashBlock(lengths);
            std::memcpy(_j0, _ghash, BlockSize);
            secureWipe(_ghash, BlockSize);
        }
        std::memcpy(_register, _j0, BlockSize);
        increment32(_register);
        if (encrypt)
            _tagSize = tag.size();
        else
            _expectedTag = tag;
        break;
    }
    }
    _valid = true;
}

ModeEngine::ModeEngine(const ModeEngine &other)
    : _mode(other._mode)
    , _pkcs7(other._pkcs7)
    , _encrypt(other._encrypt)
    , _valid(other._valid)
    , _cipher(other._cipher ? other._cipher->clone() : nullptr)
    , _used(other._used)
    , _pending(other._pending)
    , _ghashFill(other._ghashFill)
    , _textBytes(other._textBytes)
    , _expectedTag(other._expectedTag)
    , _tagSize(other._tagSize)
    , _tag(other._tag)
{
    std::memcpy(_register, other._register, BlockSize);
    std::memcpy(_keystream, other._keystream, BlockSize);
    std::memcpy(_h, other._h, BlockSize);
    std::memcpy(_j0, other._j0, BlockSize);
    std::memcpy(_ghash, other._ghash, BlockSize);
    std::memcpy(_ghashPartial, other._ghashPartial, BlockSize);
    if (!_cipher)
        _valid = false;
}

ModeEngine::~ModeEngine()
{
    secureWipe(_register, BlockSize);
    secureWipe(_keystream, BlockSize);
    secureWipe(_h, BlockSize);
    secureWipe(_j0, BlockSize);
    secureWipe(_ghash, BlockSize);
    secureWipe(_ghashPartial, BlockSize);
    secureWipe(_pending);
    secureWipe(_expectedTag);
}

std::size_t ModeEngine::blockSize(CipherMode mode)
{
    return mode == CipherMode::ECB || mode == CipherMode::CBC ? BlockSize : 1;
}

bool ModeEngine::update(const std::uint8_t *in, std::size_t size, Bytes &out)
{
    if (!_valid)
        return false;
    if (!size)
        return true;

    switch (_mode) {
    case CipherMode::ECB:
    case CipherMode::CBC:
    {
        _pending.insert(_pending.end(), in, in + size);
        std::size_t blocks = _pending.size() / BlockSize;
        // The last block may hold the padding: keep it for final().
        if (!_encrypt && _pkcs7 && blocks && _pending.size() % BlockSize == 0)
            --blocks;
        if (!blocks)
            return true;
        const bool ok = processBlocks(_pending.data(), blocks, out);
        secureWipe(_pending.data(), blocks * BlockSize);
        _pending.erase(_pending.begin(), _pending.begin() + std::ptrdiff_t(blocks * BlockSize));
        return ok;
    }
    case CipherMode::CFB:
    case CipherMode::OFB:
    case CipherMode::CTR:
        return stream(in, size, out);
    case CipherMode::GCM:
        if (_textBytes + size > MaxGcmBytes)
            return false;
        _textBytes += size;
        if (!_encrypt) {
            // Nothing is released before the tag has been checked.
            _pending.insert(_pending.end(), in, in + size);
            return true;
        } else {
            const std::size_t start = out.size();
            if (!stream(in, size, out))
                return false;
            ghashBytes(out.data() + start, size);
            return true;
        }
    }
    return false;
}

bool ModeEngine::final(Bytes &out)
{
    if (!_valid)
        return false;
    _valid = false; // The engine is done either way.

    switch (_mode) {
    case CipherMode::ECB:
    case CipherMode::CBC:
        if (_encrypt) {
            if (_pkcs7) {
                const std::size_t pad = BlockSize - _pending.size() % BlockSize;
                _pending.insert(_pending.end(), pad, std::uint8_t(pad));
            }
            if (_pending.size() % BlockSize)
                return false; // A partial block without padding.
            const bool ok = _pending.empty() || processBlocks(_pending.data(), _pending.size() / BlockSize, out);
            secureWipe(_pending);
            return ok;
        }
        if (!_pkcs7)
            return _pending.empty();
        {
            if (_pending.size() != BlockSize)
                return false;
            Bytes      last;
            const bool ok = processBlocks(_pending.data(), 1, last);
            secureWipe(_pending);
            if (!ok || last.size() != BlockSize)
                return false;
            const std::uint8_t pad    = last[BlockSize - 1];
            bool               padded = pad >= 1 && pad <= BlockSize;
            for (std::size_t i = 0; padded && i < pad; ++i)
                padded = last[BlockSize - 1 - i] == pad;
            if (padded)
                out.insert(out.end(), last.begin(), last.end() - pad);
            secureWipe(last);
            return padded;
        }
    case CipherMode::CFB:
    case CipherMode::OFB:
    case CipherMode::CTR:
        return true;
    case CipherMode::GCM:
    {
        Block tag;
        if (_encrypt) {
            if (!gcmTag(tag))
                return false;
            _tag.assign(tag, tag + _tagSize);
            return true;
        }
        ghashBytes(_pending.data(), _pending.size());
        if (!gcmTag(tag))
            return false;
        std::uint8_t difference = 0;
        for (std::size_t i = 0; i < _expectedTag.size(); ++i)
            difference |= std::uint8_t(tag[i] ^ _expectedTag[i]);
        if (difference) {
            secureWipe(_pending);
            return false;
        }
        const bool ok = stream(_pending.data(), _pending.size(), out);
        secureWipe(_pending);
        return ok;
    }
    }
    return false;
}

bool ModeEngine::processBlocks(const std::uint8_t *in, std::size_t blocks, Bytes &out)
{
    const std::size_t start = out.size();
    out.resize(start + blocks * BlockSize);
    std::uint8_t *result = out.data() + start;

    if (_mode == CipherMode::ECB)
        return _encrypt ? _cipher->encrypt(in, result, blocks) : _cipher->decrypt(in, result, blocks);

    if (_encrypt) {
        // CBC encryption chains every block through the previous one.
        Block block;
        for (std::size_t i = 0; i < blocks; ++i) {
            xorBlock(block, in + i * BlockSize, _register);
            if (!_cipher->encrypt(block, result + i * BlockSize, 1))
                return false;
            std::memcpy(_register, result + i * BlockSize, BlockSize);
        }
        secureWipe(block, BlockSize);
        return true;
    }

    // CBC decryption decrypts all blocks at once, then unchains them.
    if (!_cipher->decrypt(in, result, blocks))
        return false;
    for (std::size_t i = 0; i < blocks; ++i) {
        const std::uint8_t *previous = i ? in + (i - 1) * BlockSize : _register;
        xorBlock(result + i * BlockSize, result + i * BlockSize, previous);
    }
    std::memcpy(_register, in + (blocks - 1) * BlockSize, BlockSize);
    return true;
}

bool ModeEngine::stream(const std::uint8_t *in, std::size_t size, Bytes &out)
{
    const std::size_t start = out.size();
    out.resize(start + size);
    std::uint8_t *result = out.data() + start;
    for (std::size_t i = 0; i < size; ++i) {
        if (_used == BlockSize) {
            if (!nextKeystream())
                return false;
            _used = 0;
        }
        const std::uint8_t byte = in[i];
        if (_mode == CipherMode::CFB) {
            // The register collects the ciphertext of the current block.
            result[i]         = _keystream[_used] ^ byte;
            _keystream[_used] = _encrypt ? result[i] : byte;
        } else {
            result[i] = _keystream[_used] ^ byte;
        }
        ++_used;
    }
    return true;
}

bool ModeEngine::nextKeystream()
{
    Block output;
    bool  ok = false;
    switch (_mode) {
    case CipherMode::CFB:
        ok = _cipher->encrypt(_keystream, output, 1);
        break;
    case CipherMode::OFB:
        ok = _cipher->encrypt(_register, output, 1);
        if (ok)
            std::memcpy(_register, output, BlockSize);
        break;
    case CipherMode::CTR:
        ok = _cipher->encrypt(_register, output, 1);
        increment128(_register);
        break;
    case CipherMode::GCM:
        ok = _cipher->encrypt(_register, output, 1);
        increment32(_register);
        break;
    default:
        break;
    }
    if (ok)
        std::memcpy(_keystream, output, BlockSize);
    secureWipe(output, BlockSize);
    return ok;
}

void ModeEngine::ghashBlock(const std::uint8_t *block)
{
    for (std::size_t i = 0; i < BlockSize; ++i)
        _ghash[i] ^= block[i];
    gfMultiply(_ghash, _h);
}

void ModeEngine::ghashBytes(const std::uint8_t *data, std::size_t size)
{
    while (size) {
        const std::size_t take = std::min(size, BlockSize - _ghashFill);
        std::memcpy(_ghashPartial + _ghashFill, data, take);
        _ghashFill += take;
        data += take;
        size -= take;
        if (_ghashFill == BlockSize) {
            ghashBlock(_ghashPartial);
            _ghashFill = 0;
        }
    }
}

bool ModeEngine::gcmTag(Block tag)
{
    if (_ghashFill) {
        std::memset(_ghashPartial + _ghashFill, 0, BlockSize - _ghashFill);
        ghashBlock(_ghashPartial);
        _ghashFill = 0;
    }
    // No additional authenticated data: its length is zero.
    Block lengths {};
    storeBigEndian(lengths + 8, _textBytes * 8);
    ghashBlock(lengths);
    Block mask;
    if (!_cipher->encrypt(_j0, mask, 1))
        return false;
    xorBlock(tag, _ghash, mask);
    secureWipe(mask, BlockSize);
    return true;
}

}
