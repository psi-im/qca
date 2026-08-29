/*
 * qca.h - Qt Cryptographic Architecture
 * Copyright (C) 2003-2005  Justin Karneges <justin@affinix.com>
 * Copyright (C) 2004-2006  Brad Hards <bradh@frogmouth.net>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 *
 */

/**
   \file qca.h

   Summary header file for %QCA.

   \note You should not use this header directly from an
   application. You should just use <tt> \#include \<QtCrypto>
   </tt> instead.
*/

#ifndef QCA_H
#define QCA_H

#include "qca_basic.h"
#include "qca_cert.h"
#include "qca_core.h"
#include "qca_keystore.h"
#include "qca_publickey.h"
#include "qca_safetimer.h"
#include "qca_securelayer.h"
#include "qca_securemessage.h"
#include "qca_textfilter.h"
#include "qcaprovider.h"
#include "qpipe.h"

namespace QCA {
namespace BigIntegerMath {

/**
   Return a non-negative representative of \a value modulo \a modulus.

   A non-positive modulus is invalid and returns zero.
*/
inline BigInteger positiveMod(const BigInteger &value, const BigInteger &modulus)
{
    const BigInteger zero(0);
    if (modulus <= zero)
        return zero;

    BigInteger result(value);
    result %= modulus;
    if (result < zero)
        result += modulus;
    return result;
}

/**
   Compute base^exponent modulo modulus using binary exponentiation.

   The exponent must be non-negative and the modulus must be positive.
   Invalid arguments return zero.
*/
inline BigInteger modPow(const BigInteger &base, const BigInteger &exponent, const BigInteger &modulus)
{
    const BigInteger zero(0);
    const BigInteger two(2);

    if (modulus <= zero || exponent < zero)
        return zero;

    BigInteger result(1);
    result %= modulus;

    BigInteger factor = positiveMod(base, modulus);
    BigInteger power(exponent);

    while (power > zero) {
        BigInteger bit(power);
        bit %= two;
        if (bit != zero) {
            result *= factor;
            result %= modulus;
        }

        power /= two;
        if (power != zero) {
            // The bundled Botan BigInt multiplication is not guaranteed to
            // support the same object as both input and output for large
            // values.  Keep the right-hand operand on the original shared
            // data while the left-hand copy detaches before multiplication.
            BigInteger squared(factor);
            squared *= factor;
            squared %= modulus;
            factor = squared;
        }
    }

    return result;
}

/**
   Compute the multiplicative inverse of \a value modulo \a modulus.

   Returns false when the modulus is invalid, \a inverse is null, or the
   inverse does not exist because value and modulus are not coprime.
*/
inline bool modInverse(const BigInteger &value, const BigInteger &modulus, BigInteger *inverse)
{
    const BigInteger zero(0);
    const BigInteger one(1);

    if (!inverse || modulus <= one)
        return false;

    BigInteger t(0);
    BigInteger newT(1);
    BigInteger r(modulus);
    BigInteger newR = positiveMod(value, modulus);

    while (newR != zero) {
        BigInteger quotient(r);
        quotient /= newR;

        BigInteger product(quotient);
        product *= newT;
        BigInteger nextT(t);
        nextT -= product;
        t = newT;
        newT = nextT;

        product = quotient;
        product *= newR;
        BigInteger nextR(r);
        nextR -= product;
        r = newR;
        newR = nextR;
    }

    if (r != one)
        return false;

    *inverse = positiveMod(t, modulus);
    return true;
}

} // namespace BigIntegerMath
} // namespace QCA

#endif
