#include <sasl/sasl.h>
#ifndef SASL_CB_CRYPTO
#error The dependency bundle must provide cryptographic callbacks
#endif
#include <stdio.h>
#include <string.h>

static unsigned int getpath_calls;

static int getpath(void *context, const char **path)
{
    (void)context;
    ++getpath_calls;
    *path = "__qca_no_dynamic_sasl_plugins__";
    return SASL_OK;
}

static int verifyfile(void *context, const char *file, sasl_verify_type_t type)
{
    (void)context;
    (void)file;
    (void)type;
    return SASL_OK;
}

static sasl_callback_t callbacks[] = {{SASL_CB_GETPATH, (int (*)(void))getpath, NULL},
                                      {SASL_CB_VERIFYFILE, (int (*)(void))verifyfile, NULL},
                                      {SASL_CB_LIST_END, NULL, NULL}};

static int has_mechanism(const char **mechanisms, const char *expected)
{
    size_t i;

    for (i = 0; mechanisms[i] != NULL; ++i) {
        if (strcmp(mechanisms[i], expected) == 0) {
            return 1;
        }
    }

    return 0;
}

int main(void)
{
    static const char *const expected[] = {"PLAIN", "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-384", "SCRAM-SHA-512"};
    const char             **mechanisms;
    size_t                   i;
    int                      failed = 0;
    int                      rc     = sasl_client_init(callbacks);

    if (rc != SASL_OK) {
        fprintf(stderr, "sasl_client_init failed: %d\n", rc);
        return 10;
    }

    rc = sasl_server_init(callbacks, "qca");
    if (rc != SASL_OK) {
        fprintf(stderr, "sasl_server_init failed: %d\n", rc);
        sasl_done();
        return 12;
    }

#ifdef _WIN32
    /* Static Windows bundles must not consult host plugin paths or the registry. */
    if (getpath_calls != 0) {
        fprintf(stderr, "static SASL unexpectedly requested a dynamic plugin path\n");
        failed = 1;
    }
#endif

    mechanisms = sasl_global_listmech();
    if (mechanisms == NULL) {
        fprintf(stderr, "sasl_global_listmech failed\n");
        sasl_done();
        return 11;
    }

    for (i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i) {
        if (!has_mechanism(mechanisms, expected[i])) {
            fprintf(stderr, "missing static SASL mechanism: %s\n", expected[i]);
            failed = 1;
        }
    }

    if (failed) {
        fputs("registered SASL mechanisms:", stderr);
        for (i = 0; mechanisms[i] != NULL; ++i) {
            fprintf(stderr, " %s", mechanisms[i]);
        }
        fputc('\n', stderr);
    }

    sasl_done();

    if (failed) {
        return 1;
    }

    puts("Cyrus SASL static initialization and mechanisms verified");
    return 0;
}
