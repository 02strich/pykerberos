/**
 
 **/

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>

#define krb5_get_err_text(context,code) error_message(code)

typedef struct {
    krb5_context     context;
    krb5_ccache      ccache;
    krb5_principal   client;
    char*            ccache_name;
} gss_store_state;

int authenticate_store_credential(gss_store_state* state, char *princ_name, gss_cred_id_t delegated_cred);
int authenticate_store_clear(gss_store_state* state);