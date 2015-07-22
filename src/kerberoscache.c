/**
 
 **/

#include <Python.h>
#include "kerberoscache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef PRINTFS

extern PyObject *GssException_class;
extern PyObject *BasicAuthException_class;

static void set_gss_error(OM_uint32 err_maj, OM_uint32 err_min);
static void set_basicauth_error(krb5_context context, krb5_error_code code);
static int
store_gss_creds(gss_store_state *state, char *princ_name, gss_cred_id_t delegated_cred);

static void set_basicauth_error(krb5_context context, krb5_error_code code)
{
    PyErr_SetObject(BasicAuthException_class, Py_BuildValue("(s:i)", krb5_get_err_text(context, code), code));
}

static void set_basicauth_error(krb5_context context, krb5_error_code code);

static void set_gss_error(OM_uint32 err_maj, OM_uint32 err_min)
{
    OM_uint32 maj_stat, min_stat;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_string;
    char buf_maj[512];
    char buf_min[512];
    
    do
    {
        maj_stat = gss_display_status (&min_stat,
                                       err_maj,
                                       GSS_C_GSS_CODE,
                                       GSS_C_NO_OID,
                                       &msg_ctx,
                                       &status_string);
        if (GSS_ERROR(maj_stat))
            break;
        strncpy(buf_maj, (char*) status_string.value, sizeof(buf_maj));
        gss_release_buffer(&min_stat, &status_string);
        
        maj_stat = gss_display_status (&min_stat,
                                       err_min,
                                       GSS_C_MECH_CODE,
                                       GSS_C_NULL_OID,
                                       &msg_ctx,
                                       &status_string);
        if (!GSS_ERROR(maj_stat))
        {
            strncpy(buf_min, (char*) status_string.value, sizeof(buf_min));
            gss_release_buffer(&min_stat, &status_string);
        }
    } while (!GSS_ERROR(maj_stat) && msg_ctx != 0);
    
    PyErr_SetObject(GssException_class, Py_BuildValue("((s:i)(s:i))", buf_maj, err_maj, buf_min, err_min));
}

static int
store_gss_creds(gss_store_state *state, char *princ_name, gss_cred_id_t delegated_cred)
{
   OM_uint32        maj_stat, min_stat;
   krb5_error_code  problem;
   const char *     temp_ccname = "FILE:/tmp/krb5cc_";
   int              ret = 1;

   problem = krb5_init_context(&state->context);
   if (problem) {      
       PyErr_SetObject(BasicAuthException_class, Py_BuildValue("((s:i))",
                                                                "Cannot initialize Kerberos5 context", problem));
       return 0;
   }
   
   int lenp = strlen(princ_name);
   int lent = strlen(temp_ccname);
   state->ccache_name = (char *) malloc(lenp+lent+1);
   state->ccache_name[lenp+lent] = 0;
   strcpy(state->ccache_name, temp_ccname);
   strcat(state->ccache_name, princ_name); 

   problem = krb5_cc_resolve(state->context, state->ccache_name, &state->ccache);
   if (problem) {
       set_basicauth_error(state->context, problem);
       ret = 0;
       goto end;
   }
   
   problem = krb5_parse_name(state->context, princ_name, &state->client);
   if (problem) {
       set_basicauth_error(state->context, problem);
       goto end;
   }

   problem = krb5_cc_initialize(state->context, state->ccache, state->client);
   if (problem) {
       set_basicauth_error(state->context, problem);
       ret = 0;
       goto end;
   }
   
   maj_stat = gss_krb5_copy_ccache(&min_stat, delegated_cred, state->ccache);
   if (GSS_ERROR(maj_stat))
   {
       set_gss_error(maj_stat, min_stat);
       ret = 0;
       goto end;
   }

   ret = 1;
   return ret;

end:
   if (state->client != NULL)
      krb5_free_principal(state->context, state->client);
   if (state->ccache != NULL)
      krb5_cc_destroy(state->context, state->ccache);
   krb5_free_context(state->context);
   return ret;
}

int authenticate_store_credential(gss_store_state* state, char *princ_name, gss_cred_id_t delegated_cred)
{
    state->context = NULL;
    state->ccache = NULL;
    state->client = NULL;
    state->ccache_name = NULL;
    
    return store_gss_creds(state, princ_name, delegated_cred);
}

int authenticate_store_clear(gss_store_state* state)
{
    if (state->client)
        krb5_free_principal(state->context, state->client);
    if (state->ccache)
        krb5_cc_destroy(state->context, state->ccache);
    krb5_free_context(state->context);
    if (state->ccache_name != NULL)
    {
        free(state->ccache_name);
        state->ccache_name = NULL;
    }
    return 1;
}
