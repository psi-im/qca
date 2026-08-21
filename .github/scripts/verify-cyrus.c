#include <sasl/sasl.h>
#include <stdio.h>
#include <string.h>

static int getpath(void *context, const char **path)
{
    (void)context;
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

static int check_mech(const char *mech)
{
    sasl_conn_t     *conn     = NULL;
    const char      *out      = NULL;
    const char      *chosen   = NULL;
    unsigned         outlen   = 0;
    sasl_interact_t *interact = NULL;
    int              rc       = sasl_client_new("xmpp", "example.invalid", NULL, NULL, callbacks, 0, &conn);
    if (rc != SASL_OK) {
        fprintf(stderr, "sasl_client_new failed for %s: %d\n", mech, rc);
        return 1;
    }

    rc = sasl_client_start(conn, mech, &interact, &out, &outlen, &chosen);
    if (rc == SASL_NOMECH || chosen == NULL || strcmp(chosen, mech) != 0) {
        fprintf(stderr, "missing static SASL mechanism: %s (rc=%d, chosen=%s)\n", mech, rc, chosen ? chosen : "<none>");
        sasl_dispose(&conn);
        return 1;
    }

    sasl_dispose(&conn);
    return 0;
}

int main(void)
{
    int failed = 0;
    int rc     = sasl_client_init(callbacks);
    if (rc != SASL_OK) {
        fprintf(stderr, "sasl_client_init failed: %d\n", rc);
        return 10;
    }

    failed |= check_mech("PLAIN");
    failed |= check_mech("SCRAM-SHA-256");
    failed |= check_mech("DIGEST-MD5");
    sasl_done();
    return failed;
}
