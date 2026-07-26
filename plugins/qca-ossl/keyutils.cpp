/*
 * Copyright (C) 2026  QCA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "keyutils.h"
#include "utils.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/param_build.h>
#endif

namespace opensslQCAPlugin {

EVP_PKEY_CTX *newPkeyContext(EVP_PKEY *pkey)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
#else
    return EVP_PKEY_CTX_new(pkey, nullptr);
#endif
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
EVP_PKEY *pkeyFromBnParameters(const char *algorithm, int selection, std::initializer_list<PkeyBnParameter> parameters)
{
    if (!algorithm || !*algorithm)
        return nullptr;

    ParamBldPtr builder(OSSL_PARAM_BLD_new());
    if (!builder)
        return nullptr;

    for (const PkeyBnParameter &parameter : parameters) {
        if (!parameter.name || !parameter.value ||
            OSSL_PARAM_BLD_push_BN(builder.get(), parameter.name, parameter.value) != 1)
            return nullptr;
    }

    ParamPtr params(OSSL_PARAM_BLD_to_param(builder.get()));
    if (!params)
        return nullptr;

    PkeyCtxPtr context(EVP_PKEY_CTX_new_from_name(nullptr, algorithm, nullptr));
    if (!context || EVP_PKEY_fromdata_init(context.get()) <= 0)
        return nullptr;

    EVP_PKEY *result = nullptr;
    if (EVP_PKEY_fromdata(context.get(), &result, selection, params.get()) <= 0) {
        EVP_PKEY_free(result);
        return nullptr;
    }

    return result;
}

QCA::BigInteger pkeyBnParameter(const EVP_PKEY *pkey, const char *name, bool sensitive)
{
    BIGNUM *value = nullptr;

    if (!pkey || !name || EVP_PKEY_get_bn_param(pkey, name, &value) != 1)
        return {};

    const QCA::BigInteger result = bn2bi(value);

    if (sensitive)
        BN_clear_free(value);
    else
        BN_free(value);

    return result;
}
#endif

} // namespace opensslQCAPlugin
