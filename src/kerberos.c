/**
 * Copyright (c) 2006-2013 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

#include <Python.h>

#include "kerberosbasic.h"
#include "kerberospw.h"
#include "kerberosgss.h"
#include "kerberoscache.h"

/*
 * Support the Python 3 API while maintaining backward compatibility for the
 * Python 2 API.
 * Thanks to Lennart Regebro for http://python3porting.com/cextensions.html
 */
// Handle basic API changes
#if PY_MAJOR_VERSION >= 3
    // Basic renames (function parameters are the same)
    // No more int objects
    #define PyInt_FromLong PyLong_FromLong
    // CObjects to Capsules
    #define PyCObject_Check PyCapsule_CheckExact
    // #define PyCObject_SetVoidPtr PyCapsule_SetPointer
#else
    // More complex macros (function parameters are not the same)
    // Note for PyCObject_FromVoidPtr, destr is now the third parameter
    #define PyCapsule_New(cobj, NULL, destr) PyCObject_FromVoidPtr(cobj, destr)
    #define PyCapsule_GetPointer(pobj, NULL) PyCObject_AsVoidPtr(pobj)
#endif

PyObject *KrbException_class;
PyObject *BasicAuthException_class;
PyObject *PwdChangeException_class;
PyObject *GssException_class;

static PyObject *checkPassword(PyObject *self, PyObject *args)
{
    const char *user = NULL;
    const char *pswd = NULL;
    const char *service = NULL;
    const char *default_realm = NULL;
    const int verify = 1;
    int result = 0;

    if (!PyArg_ParseTuple(args, "ssssb", &user, &pswd, &service, &default_realm, &verify))
        return NULL;

    result = authenticate_user_krb5pwd(user, pswd, service, default_realm, verify);

    if (result)
        return Py_INCREF(Py_True), Py_True;
    else
        return NULL;
}

static PyObject *changePassword(PyObject *self, PyObject *args)
{
    const char *newpswd = NULL;
    const char *oldpswd = NULL;
    const char *user = NULL;
    int result = 0;

    if (!PyArg_ParseTuple(args, "sss", &user, &oldpswd, &newpswd))
        return NULL;

    result = change_user_krb5pwd(user, oldpswd, newpswd);

    if (result)
	return Py_INCREF(Py_True), Py_True;
    else
	return NULL;
}

static PyObject *getServerPrincipalDetails(PyObject *self, PyObject *args)
{
    const char *service = NULL;
    const char *hostname = NULL;
    char* result;

    if (!PyArg_ParseTuple(args, "ss", &service, &hostname))
        return NULL;

    result = server_principal_details(service, hostname);

    if (result != NULL)
    {
        PyObject* pyresult = Py_BuildValue("s", result);
        free(result);
        return pyresult;
    }
    else
        return NULL;
}

static PyObject* authGSSClientInit(PyObject* self, PyObject* args, PyObject* keywds)
{
    const char *service = NULL;
    const char *principal = NULL;
    gss_client_state *state;
    PyObject *pystate;
    static char *kwlist[] = {"service", "principal", "gssflags", NULL};
    long int gss_flags = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG;
    int result = 0;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "s|zl", kwlist, &service, &principal, &gss_flags))
        return NULL;

    state = (gss_client_state *) malloc(sizeof(gss_client_state));
    pystate = PyCapsule_New(state, NULL, NULL);

    result = authenticate_gss_client_init(service, principal, gss_flags, state);
    if (result == AUTH_GSS_ERROR)
        return NULL;

    return Py_BuildValue("(iO)", result, pystate);
}

static PyObject *authGSSClientClean(PyObject *self, PyObject *args)
{
    gss_client_state *state;
    PyObject *pystate;
    int result = 0;

    if (!PyArg_ParseTuple(args, "O", &pystate))
        return NULL;

    if (!PyCapsule_CheckExact(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = PyCapsule_GetPointer(pystate, NULL);
    if (state != NULL)
    {
        result = authenticate_gss_client_clean(state);

        free(state);
#if PY_MAJOR_VERSION < 3
        PyCObject_SetVoidPtr(pystate, NULL);
#endif
    }

    return Py_BuildValue("i", result);
}

static PyObject *authGSSClientStep(PyObject *self, PyObject *args)
{
    gss_client_state *state;
    PyObject *pystate;
    char *challenge = NULL;
    int result = 0;

    if (!PyArg_ParseTuple(args, "Os", &pystate, &challenge))
        return NULL;

    if (!PyCapsule_CheckExact(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = PyCapsule_GetPointer(pystate, NULL);
    if (state == NULL)
        return NULL;

    result = authenticate_gss_client_step(state, challenge);
    if (result == AUTH_GSS_ERROR)
        return NULL;

    return Py_BuildValue("i", result);
}

static PyObject *authGSSClientResponseConf(PyObject *self, PyObject *args)
{
    gss_client_state *state;
    PyObject *pystate;

    if (!PyArg_ParseTuple(args, "O", &pystate))
        return NULL;

    if (!PyCapsule_CheckExact(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = PyCapsule_GetPointer(pystate, NULL);
    if (state == NULL)
        return NULL;

    return Py_BuildValue("i", state->responseConf);
}

static PyObject *authGSSClientResponse(PyObject *self, PyObject *args)
{
    gss_client_state *state;
    PyObject *pystate;

    if (!PyArg_ParseTuple(args, "O", &pystate))
        return NULL;

    if (!PyCapsule_CheckExact(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = PyCapsule_GetPointer(pystate, NULL);
    if (state == NULL)
        return NULL;

    return Py_BuildValue("s", state->response);
}

static PyObject *authGSSClientUserName(PyObject *self, PyObject *args)
{
    gss_client_state *state;
    PyObject *pystate;

    if (!PyArg_ParseTuple(args, "O", &pystate))
        return NULL;

    if (!PyCapsule_CheckExact(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = PyCapsule_GetPointer(pystate, NULL);
    if (state == NULL)
        return NULL;

    return Py_BuildValue("s", state->username);
}

static PyObject *authGSSClientUnwrap(PyObject *self, PyObject *args)
{
	gss_client_state *state;
	PyObject *pystate;
	char *challenge = NULL;
	int result = 0;

	if (!PyArg_ParseTuple(args, "Os", &pystate, &challenge))
		return NULL;

    if (!PyCapsule_CheckExact(pystate)) {
		PyErr_SetString(PyExc_TypeError, "Expected a context object");
		return NULL;
	}

    state = PyCapsule_GetPointer(pystate, NULL);
	if (state == NULL)
		return NULL;

	result = authenticate_gss_client_unwrap(state, challenge);
	if (result == AUTH_GSS_ERROR)
		return NULL;

	return Py_BuildValue("i", result);
}

#ifdef GSSAPI_EXT
static PyObject *authGSSClientUnwrapIov(PyObject *self, PyObject *args)
{
	gss_client_state *state;
	PyObject *pystate;
	char *challenge = NULL;
	int result = 0;

	if (!PyArg_ParseTuple(args, "Os", &pystate, &challenge))
		return NULL;

    if (!PyCapsule_CheckExact(pystate)) {
		PyErr_SetString(PyExc_TypeError, "Expected a context object");
		return NULL;
	}

    state = PyCapsule_GetPointer(pystate, NULL);
	if (state == NULL)
		return NULL;

	result = authenticate_gss_client_unwrap_iov(state, challenge);
	if (result == AUTH_GSS_ERROR)
		return NULL;

	return Py_BuildValue("i", result);
}
#endif

static PyObject *authGSSClientWrap(PyObject *self, PyObject *args)
{
	gss_client_state *state;
	PyObject *pystate;
	char *challenge = NULL;
	char *user = NULL;
    int protect = 0;
	int result = 0;

	if (!PyArg_ParseTuple(args, "Os|zi", &pystate, &challenge, &user, &protect))
		return NULL;

    if (!PyCapsule_CheckExact(pystate)) {
		PyErr_SetString(PyExc_TypeError, "Expected a context object");
		return NULL;
	}

    state = PyCapsule_GetPointer(pystate, NULL);
	if (state == NULL)
		return NULL;

	result = authenticate_gss_client_wrap(state, challenge, user, protect);
	if (result == AUTH_GSS_ERROR)
		return NULL;

	return Py_BuildValue("i", result);
}

#ifdef GSSAPI_EXT
static PyObject *authGSSClientWrapIov(PyObject *self, PyObject *args)
{
        gss_client_state *state;
        PyObject *pystate;
        char *challenge = NULL;
        int protect = 1;
        int result = 0;
        int pad_len = 0;

        if (!PyArg_ParseTuple(args, "Os|i", &pystate, &challenge, &protect))
            return NULL;

    if (!PyCapsule_CheckExact(pystate)) {
            PyErr_SetString(PyExc_TypeError, "Expected a context object");
            return NULL;
        }

    state = PyCapsule_GetPointer(pystate, NULL);
        if (state == NULL)
            return NULL;

        result = authenticate_gss_client_wrap_iov(state, challenge, protect, &pad_len);
        if (result == AUTH_GSS_ERROR)
            return NULL;

        return Py_BuildValue("ii", result, pad_len);
}
#endif

static PyObject *authGSSServerInit(PyObject *self, PyObject *args)
{
    const char *service = NULL;
    gss_server_state *state;
    PyObject *pystate;
    int result = 0;

    if (!PyArg_ParseTuple(args, "s", &service))
        return NULL;

    state = (gss_server_state *) malloc(sizeof(gss_server_state));
    pystate = PyCapsule_New(state, NULL, NULL);

    result = authenticate_gss_server_init(service, state);
    if (result == AUTH_GSS_ERROR)
        return NULL;

    return Py_BuildValue("(iO)", result, pystate);
}

static PyObject *authGSSServerClean(PyObject *self, PyObject *args)
{
    gss_server_state *state;
    PyObject *pystate;
    int result = 0;

    if (!PyArg_ParseTuple(args, "O", &pystate))
        return NULL;

    if (!PyCapsule_CheckExact(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = PyCapsule_GetPointer(pystate, NULL);
    if (state != NULL)
    {
        result = authenticate_gss_server_clean(state);

        free(state);
#if PY_MAJOR_VERSION < 3
        PyCObject_SetVoidPtr(pystate, NULL);
#endif
    }

    return Py_BuildValue("i", result);
}

static PyObject *authGSSServerStep(PyObject *self, PyObject *args)
{
    gss_server_state *state;
    PyObject *pystate;
    char *challenge = NULL;
    int result = 0;

    if (!PyArg_ParseTuple(args, "Os", &pystate, &challenge))
        return NULL;

    if (!PyCapsule_CheckExact(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = PyCapsule_GetPointer(pystate, NULL);
    if (state == NULL)
        return NULL;

    result = authenticate_gss_server_step(state, challenge);
    if (result == AUTH_GSS_ERROR)
        return NULL;

    return Py_BuildValue("i", result);
}

static PyObject *authGSSServerResponse(PyObject *self, PyObject *args)
{
    gss_server_state *state;
    PyObject *pystate;

    if (!PyArg_ParseTuple(args, "O", &pystate))
        return NULL;

    if (!PyCapsule_CheckExact(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = PyCapsule_GetPointer(pystate, NULL);
    if (state == NULL)
        return NULL;

    return Py_BuildValue("s", state->response);
}

static PyObject *authGSSServerUserName(PyObject *self, PyObject *args)
{
    gss_server_state *state;
    PyObject *pystate;

    if (!PyArg_ParseTuple(args, "O", &pystate))
        return NULL;

    if (!PyCapsule_CheckExact(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = PyCapsule_GetPointer(pystate, NULL);
    if (state == NULL)
        return NULL;

    return Py_BuildValue("s", state->username);
}

static PyObject *authGSSServerTargetName(PyObject *self, PyObject *args)
{
    gss_server_state *state;
    PyObject *pystate;

    if (!PyArg_ParseTuple(args, "O", &pystate))
        return NULL;

    if (!PyCapsule_CheckExact(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = PyCapsule_GetPointer(pystate, NULL);
    if (state == NULL)
        return NULL;

    return Py_BuildValue("s", state->targetname);
}

static PyObject *authGSSStoreCredential(PyObject *self, PyObject *args)
{
    gss_server_state *state;
    PyObject *pystate;
    gss_store_state *storestate;
    PyObject *pystorestate;
    int result = 0;
    
    if (!PyArg_ParseTuple(args, "O", &pystate))
        return NULL;
    
    if (!PyCapsule_CheckExact(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }
    
    state = PyCapsule_GetPointer(pystate, NULL);
    if (state == NULL)
        return NULL;
    if (!(state->gss_flags & GSS_C_DELEG_FLAG))
    {
        PyErr_SetObject(BasicAuthException_class, Py_BuildValue("((s:i))",
                                                                "No credentials for delegation", 0));
        return NULL;
    }
    storestate = (gss_store_state *) malloc(sizeof(gss_store_state));
    pystorestate = PyCapsule_New(storestate, NULL, NULL);
    
    result = authenticate_store_credential(storestate, state->username, state->client_creds);
    if (result == 0)
        return NULL;
        
    return Py_BuildValue("(iO)", result, pystorestate);
}

static PyObject *authGSSStorageClean(PyObject *self, PyObject *args)
{
    gss_store_state *state;
    PyObject *pystate;
    int result = 0;

    if (!PyArg_ParseTuple(args, "O", &pystate))
        return NULL;

    if (!PyCapsule_CheckExact(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = PyCapsule_GetPointer(pystate, NULL);
    if (state != NULL)
    {
        result = authenticate_store_clear(state);

        free(state);
#if PY_MAJOR_VERSION < 3
        PyCObject_SetVoidPtr(pystate, NULL);
#endif
    }

    return Py_BuildValue("i", result);
}

static PyObject *authGSSStorageName(PyObject *self, PyObject *args)
{
    gss_store_state *state;
    PyObject *pystate;
    
    if (!PyArg_ParseTuple(args, "O", &pystate))
        return NULL;

    if (!PyCapsule_CheckExact(pystate)) {       
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }
    
    state = PyCapsule_GetPointer(pystate, NULL);  
    if (state == NULL)
        return NULL;
    
    return Py_BuildValue("s", state->ccache_name);
}
static PyMethodDef KerberosMethods[] = {
    {"checkPassword",  checkPassword, METH_VARARGS,
     "Check the supplied user/password against Kerberos KDC."},
    {"changePassword",  changePassword, METH_VARARGS,
     "Change the user password."},
    {"getServerPrincipalDetails",  getServerPrincipalDetails, METH_VARARGS,
     "Return the service principal for a given service and hostname."},
    {"authGSSClientInit",  (PyCFunction)authGSSClientInit, METH_VARARGS | METH_KEYWORDS,
     "Initialize client-side GSSAPI operations."},
    {"authGSSClientClean",  authGSSClientClean, METH_VARARGS,
     "Terminate client-side GSSAPI operations."},
    {"authGSSClientStep",  authGSSClientStep, METH_VARARGS,
     "Do a client-side GSSAPI step."},
    {"authGSSClientResponse",  authGSSClientResponse, METH_VARARGS,
     "Get the response from the last client-side GSSAPI step."},
    {"authGSSClientResponseConf",  authGSSClientResponseConf, METH_VARARGS,
     "return 1 if confidentiality was set in the last unwrapped buffer, 0 otherwise."},
    {"authGSSClientUserName",  authGSSClientUserName, METH_VARARGS,
     "Get the user name from the last client-side GSSAPI step."},
    {"authGSSServerInit",  authGSSServerInit, METH_VARARGS,
     "Initialize server-side GSSAPI operations."},
    {"authGSSClientWrap",  authGSSClientWrap, METH_VARARGS,
     "Do a GSSAPI wrap."},
    {"authGSSClientUnwrap",  authGSSClientUnwrap, METH_VARARGS,
     "Do a GSSAPI unwrap."},
#ifdef GSSAPI_EXT
    {"authGSSClientWrapIov",  authGSSClientWrapIov, METH_VARARGS,
     "Do a GSSAPI iov wrap."},
    {"authGSSClientUnwrapIov",  authGSSClientUnwrapIov, METH_VARARGS,
     "Do a GSSAPI iov unwrap."},
#endif
    {"authGSSServerClean",  authGSSServerClean, METH_VARARGS,
     "Terminate server-side GSSAPI operations."},
    {"authGSSServerStep",  authGSSServerStep, METH_VARARGS,
     "Do a server-side GSSAPI step."},
    {"authGSSServerResponse",  authGSSServerResponse, METH_VARARGS,
     "Get the response from the last server-side GSSAPI step."},
    {"authGSSServerUserName",  authGSSServerUserName, METH_VARARGS,
        "Get the user name from the last server-side GSSAPI step."},
    {"authGSSServerTargetName",  authGSSServerTargetName, METH_VARARGS,
        "Get the target name from the last server-side GSSAPI step."},
    {"authGSSStoreCredential",  authGSSStoreCredential, METH_VARARGS,
        "Get the target name from the last server-side GSSAPI step."},
    {"authGSSStorageClean",  authGSSStorageClean, METH_VARARGS,
        "Get the target name from the last server-side GSSAPI step."},
    {"authGSSStorageName",  authGSSStorageName, METH_VARARGS,
        "Get the target name from the last server-side GSSAPI step."},        
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

#if PY_MAJOR_VERSION >= 3
    static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        "kerberos",          /* m_name */
        "High-level interface to kerberos",  /* m_doc */
        -1,                  /* m_size */
        KerberosMethods,     /* m_methods */
        NULL,                /* m_reload */
        NULL,                /* m_traverse */
        NULL,                /* m_clear */
        NULL,                /* m_free */
    };

#endif



#if PY_MAJOR_VERSION >= 3
PyObject* PyInit_kerberos(void)
#else
void initkerberos(void)
#endif
{
    PyObject *m,*d;

#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&moduledef);
#else
    m = Py_InitModule("kerberos", KerberosMethods);
#endif

    d = PyModule_GetDict(m);

    /* create the base exception class */
    if (!(KrbException_class = PyErr_NewException("kerberos.KrbError", NULL, NULL)))
        goto error;
    PyDict_SetItemString(d, "KrbError", KrbException_class);
    Py_INCREF(KrbException_class);

    /* ...and the derived exceptions */
    if (!(BasicAuthException_class = PyErr_NewException("kerberos.BasicAuthError", KrbException_class, NULL)))
        goto error;
    Py_INCREF(BasicAuthException_class);
    PyDict_SetItemString(d, "BasicAuthError", BasicAuthException_class);

    if (!(PwdChangeException_class = PyErr_NewException("kerberos.PwdChangeError", KrbException_class, NULL)))
        goto error;
    Py_INCREF(PwdChangeException_class);
    PyDict_SetItemString(d, "PwdChangeError", PwdChangeException_class);

    if (!(GssException_class = PyErr_NewException("kerberos.GSSError", KrbException_class, NULL)))
        goto error;
    Py_INCREF(GssException_class);
    PyDict_SetItemString(d, "GSSError", GssException_class);

    PyDict_SetItemString(d, "AUTH_GSS_COMPLETE", PyInt_FromLong(AUTH_GSS_COMPLETE));
    PyDict_SetItemString(d, "AUTH_GSS_CONTINUE", PyInt_FromLong(AUTH_GSS_CONTINUE));

    PyDict_SetItemString(d, "GSS_C_DELEG_FLAG", PyInt_FromLong(GSS_C_DELEG_FLAG));
    PyDict_SetItemString(d, "GSS_C_MUTUAL_FLAG", PyInt_FromLong(GSS_C_MUTUAL_FLAG));
    PyDict_SetItemString(d, "GSS_C_REPLAY_FLAG", PyInt_FromLong(GSS_C_REPLAY_FLAG));
    PyDict_SetItemString(d, "GSS_C_SEQUENCE_FLAG", PyInt_FromLong(GSS_C_SEQUENCE_FLAG));
    PyDict_SetItemString(d, "GSS_C_CONF_FLAG", PyInt_FromLong(GSS_C_CONF_FLAG));
    PyDict_SetItemString(d, "GSS_C_INTEG_FLAG", PyInt_FromLong(GSS_C_INTEG_FLAG));
    PyDict_SetItemString(d, "GSS_C_ANON_FLAG", PyInt_FromLong(GSS_C_ANON_FLAG));
    PyDict_SetItemString(d, "GSS_C_PROT_READY_FLAG", PyInt_FromLong(GSS_C_PROT_READY_FLAG));
    PyDict_SetItemString(d, "GSS_C_TRANS_FLAG", PyInt_FromLong(GSS_C_TRANS_FLAG));

error:
    if (PyErr_Occurred())
        PyErr_SetString(PyExc_ImportError, "kerberos: init failed");
#if PY_MAJOR_VERSION >= 3
    return m;
#endif
}
