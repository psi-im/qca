/*
Copyright (C) 1999-2007 The Botan Project. All rights reserved.

Redistribution and use in source and binary forms, for any use, with or without
modification, is permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions, and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions, and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE DISCLAIMED.

IN NO EVENT SHALL THE AUTHOR(S) OR CONTRIBUTOR(S) BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
// LICENSEHEADER_END
namespace QCA { // WRAPNS_LINE
/*************************************************
 * Parser Functions Source File                   *
 * (C) 1999-2007 The Botan Project                *
 *************************************************/

} // WRAPNS_LINE
#include <botan/parsing.h>
namespace QCA { // WRAPNS_LINE
} // WRAPNS_LINE
#include <botan/exceptn.h>
namespace QCA { // WRAPNS_LINE
} // WRAPNS_LINE
#include <botan/charset.h>
namespace QCA { // WRAPNS_LINE

namespace Botan {

/*************************************************
 * Convert a string into an integer               *
 *************************************************/
#ifndef BOTAN_TOOLS_ONLY
u32bit to_u32bit(const std::string &number)
{
    u32bit n = 0;

    for (std::string::const_iterator j = number.begin(); j != number.end(); ++j) {
        const u32bit OVERFLOW_MARK = 0xFFFFFFFF / 10;

        byte digit = Charset::char2digit(*j);

        if ((n > OVERFLOW_MARK) || (n == OVERFLOW_MARK && digit > 5))
            throw Decoding_Error("to_u32bit: Integer overflow");
        n *= 10;
        n += digit;
    }
    return n;
}
#endif

/*************************************************
 * Convert an integer into a string               *
 *************************************************/
std::string to_string(u64bit n, u32bit min_len)
{
    std::string lenstr;
    if (n) {
        while (n > 0) {
            lenstr = Charset::digit2char(n % 10) + lenstr; // NOLINT(performance-inefficient-string-concatenation)
            n /= 10;
        }
    } else
        lenstr = "0";

    while (lenstr.size() < min_len)
        lenstr = "0" + lenstr; // NOLINT(performance-inefficient-string-concatenation)

    return lenstr;
}

#ifndef BOTAN_TOOLS_ONLY
/*************************************************
 * Parse a SCAN-style algorithm name              *
 *************************************************/
std::vector<std::string> parse_algorithm_name(const std::string &namex)
{
    if (namex.find('(') == std::string::npos && namex.find(')') == std::string::npos)
        return std::vector<std::string>(1, namex);

    std::string              name = namex, substring;
    std::vector<std::string> elems;
    u32bit                   level = 0;

    elems.push_back(name.substr(0, name.find('(')));
    name = name.substr(name.find('('));

    for (std::string::const_iterator j = name.begin(); j != name.end(); ++j) {
        char c = *j;

        if (c == '(')
            ++level;
        if (c == ')') {
            if (level == 1 && j == name.end() - 1) {
                if (elems.size() == 1)
                    elems.push_back(substring.substr(1));
                else
                    elems.push_back(substring);
                return elems;
            }

            if (level == 0 || (level == 1 && j != name.end() - 1))
                throw Invalid_Algorithm_Name(namex);
            --level;
        }

        if (c == ',' && level == 1) {
            if (elems.size() == 1)
                elems.push_back(substring.substr(1));
            else
                elems.push_back(substring);
            substring.clear();
        } else
            substring += c;
    }

    if (substring != "")
        throw Invalid_Algorithm_Name(namex);

    return elems;
}

/*************************************************
 * Split the string on slashes                    *
 *************************************************/
std::vector<std::string> split_on(const std::string &str, char delim)
{
    std::vector<std::string> elems;
    if (str == "")
        return elems;

    std::string substr;
    for (std::string::const_iterator j = str.begin(); j != str.end(); ++j) {
        if (*j == delim) {
            if (substr != "")
                elems.push_back(substr);
            substr.clear();
        } else
            substr += *j;
    }

    if (substr == "")
        throw Format_Error("Unable to split string: " + str);
    elems.push_back(substr);

    return elems;
}

/*************************************************
 * Parse an ASN.1 OID string                      *
 *************************************************/
std::vector<u32bit> parse_asn1_oid(const std::string &oid)
{
    std::string         substring;
    std::vector<u32bit> oid_elems;

    for (std::string::const_iterator j = oid.begin(); j != oid.end(); ++j) {
        char c = *j;

        if (c == '.') {
            if (substring == "")
                throw Invalid_OID(oid);
            oid_elems.push_back(to_u32bit(substring));
            substring.clear();
        } else
            substring += c;
    }

    if (substring == "")
        throw Invalid_OID(oid);
    oid_elems.push_back(to_u32bit(substring));

    if (oid_elems.size() < 2)
        throw Invalid_OID(oid);

    return oid_elems;
}

/*************************************************
 * X.500 String Comparison                        *
 *************************************************/
bool x500_name_cmp(const std::string &name1, const std::string &name2)
{
    std::string::const_iterator p1 = name1.begin();
    std::string::const_iterator p2 = name2.begin();

    while ((p1 != name1.end()) && Charset::is_space(*p1))
        ++p1;
    while ((p2 != name2.end()) && Charset::is_space(*p2))
        ++p2;

    while (p1 != name1.end() && p2 != name2.end()) {
        if (Charset::is_space(*p1)) {
            if (!Charset::is_space(*p2))
                return false;

            while ((p1 != name1.end()) && Charset::is_space(*p1))
                ++p1;
            while ((p2 != name2.end()) && Charset::is_space(*p2))
                ++p2;

            if (p1 == name1.end() && p2 == name2.end())
                return true;
        }

        if (!Charset::caseless_cmp(*p1, *p2))
            return false;
        ++p1;
        ++p2;
    }

    while ((p1 != name1.end()) && Charset::is_space(*p1))
        ++p1;
    while ((p2 != name2.end()) && Charset::is_space(*p2))
        ++p2;

    if ((p1 != name1.end()) || (p2 != name2.end()))
        return false;
    return true;
}

/*************************************************
 * Parse and compute an arithmetic expression     *
 *************************************************/
u32bit parse_expr(const std::string &expr)
{
    const bool have_add = (expr.find('+') != std::string::npos);
    const bool have_mul = (expr.find('*') != std::string::npos);

    if (have_add) {
        std::vector<std::string> sub_expr = split_on(expr, '+');
        u32bit                   result   = 0;
        for (u32bit j = 0; j != sub_expr.size(); ++j)
            result += parse_expr(sub_expr[j]);
        return result;
    } else if (have_mul) {
        std::vector<std::string> sub_expr = split_on(expr, '*');
        u32bit                   result   = 1;
        for (u32bit j = 0; j != sub_expr.size(); ++j)
            result *= parse_expr(sub_expr[j]);
        return result;
    } else
        return to_u32bit(expr);
}
#endif

}
} // WRAPNS_LINE
