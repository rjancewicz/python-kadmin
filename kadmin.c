

#include <Python.h>
#include <kadm5/admin.h>
#include <krb5/krb5.h>
#include <kdb.h>
#include <stdio.h>
#include <string.h>
#include <structmember.h>

#include "PyKAdminObject.h"
#include "PyKAdminErrors.h"
#include "PyKAdminIterator.h"
#include "PyKAdminPrincipalObject.h"
#include "PyKAdminPolicyObject.h"

#ifdef KADMIN_LOCAL
static PyKAdminObject *_kadmin_local(PyObject *self, PyObject *args); 
#endif

static PyKAdminObject *_kadmin_init_with_ccache(PyObject *self, PyObject *args); 
static PyKAdminObject *_kadmin_init_with_keytab(PyObject *self, PyObject *args); 
static PyKAdminObject *_kadmin_init_with_password(PyObject *self, PyObject *args); 

static char module_docstring[] = "";

char *service_name          = KADM5_ADMIN_SERVICE;
krb5_ui_4 struct_version    = KADM5_STRUCT_VERSION;
krb5_ui_4 api_version       = KADM5_API_VERSION_2;

static struct PyMethodDef module_methods[] = {
    
    #ifdef KADMIN_LOCAL
    {"local",               (PyCFunction)_kadmin_local,                 METH_VARARGS, "local()"},
    #endif

    {"init_with_ccache",   (PyCFunction)_kadmin_init_with_ccache,   METH_VARARGS, "init_with_ccache(principal, ccache)"},
    {"init_with_keytab",   (PyCFunction)_kadmin_init_with_keytab,   METH_VARARGS, "init_with_keytab(principal, keytab)"},
    {"init_with_password", (PyCFunction)_kadmin_init_with_password, METH_VARARGS, "init_with_password(principal, password)"},

    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC 
#ifdef KADMIN_LOCAL
    initkadmin_local(void) 
#else
    initkadmin(void)
#endif
{

    if (PyType_Ready(&PyKAdminObject_Type) < 0) 
        return;

    if (PyType_Ready(&PyKAdminPrincipalObject_Type) < 0)
        return;

    Py_XINCREF(&PyKAdminObject_Type);
    Py_XINCREF(&PyKAdminPrincipalObject_Type);

    #ifdef KADMIN_LOCAL
    PyObject *module = Py_InitModule3("kadmin_local", module_methods, module_docstring);
    #else
    PyObject *module = Py_InitModule3("kadmin", module_methods, module_docstring);
    #endif

    if (!module) 
        return;

    #ifdef KADMIN_LOCAL
    KAdminError = PyErr_NewException("kadmin_local.KAdminError", NULL, NULL);
    #else
    KAdminError = PyErr_NewException("kadmin.KAdminError", NULL, NULL);
    #endif

    Py_XINCREF(KAdminError);

    PyModule_AddObject(module, "KAdminError", KAdminError);

    PyKAdminError_init(module); 

}

#ifdef KADMIN_LOCAL
static PyKAdminObject *_kadmin_local(PyObject *self, PyObject *args) {

    static const char *kROOT_ADMIN = "root/admin";

    PyKAdminObject *kadmin = PyKAdminObject_create();
    kadm5_ret_t retval     = 0; 
    int result             = 0;
    char **db_args         = NULL;
    char *client_name      = NULL;

    kadm5_config_params *params = calloc(0x1, sizeof(kadm5_config_params));

    result = asprintf(&client_name, "%s@%s", kROOT_ADMIN, kadmin->realm);

    if (result == -1) {
        client_name = (char *)kROOT_ADMIN;
    }

    retval = kadm5_init_with_password(
                kadmin->context, 
                client_name, 
                NULL, 
                service_name, 
                params, 
                struct_version, 
                api_version, 
                db_args, 
                &kadmin->server_handle);

    if (retval) { PyKAdmin_RaiseKAdminError(retval, "kadm5_init_with_password"); return NULL; }

    return kadmin;

}
#endif


static PyKAdminObject *_kadmin_init_with_ccache(PyObject *self, PyObject *args) {
    
    PyKAdminObject *kadmin = PyKAdminObject_create();
    kadm5_ret_t retval;

    krb5_principal princ = NULL;
    char *ccache_name    = NULL;
    char *client_name    = NULL;
    char **db_args       = NULL;

    krb5_ccache cc;             

    kadm5_config_params *params = calloc(0x1, sizeof(kadm5_config_params));

    memset(&cc, 0, sizeof(krb5_ccache));

    // TODO : unpack database args as an optional third parameter (will be a dict or array)
    if (!PyArg_ParseTuple(args, "|zz", &client_name, &ccache_name))
        return NULL; 

    if (ccache_name == NULL) {
        retval = krb5_cc_default(kadmin->context, &cc);
        if (retval) { PyKAdmin_RaiseKAdminError(retval, "krb5_cc_default"); return NULL; }
    } else {
        retval = krb5_cc_resolve(kadmin->context, ccache_name, &cc);
        if (retval) { PyKAdmin_RaiseKAdminError(retval, "krb5_cc_resolve"); return NULL; }
    } 

    if (client_name == NULL) {
        retval = krb5_cc_get_principal(kadmin->context, cc, &princ);
        if (retval) { PyKAdmin_RaiseKAdminError(retval, "krb5_cc_get_principal"); return NULL; }

        retval = krb5_unparse_name(kadmin->context, princ, &client_name);
        if (retval) { PyKAdmin_RaiseKAdminError(retval, "krb5_unparse_name"); return NULL; }

        krb5_free_principal(kadmin->context, princ);
    }
    
    retval = kadm5_init_with_creds(
                kadmin->context, 
                client_name, 
                cc, 
                service_name, 
                params,
                struct_version, 
                api_version, 
                db_args, 
                &kadmin->server_handle);

    if (retval) { PyKAdmin_RaiseKAdminError(retval, "kadm5_init_with_creds"); return NULL; }

    Py_XINCREF(kadmin);
    return kadmin;
}



static PyKAdminObject *_kadmin_init_with_keytab(PyObject *self, PyObject *args) {

    PyKAdminObject *kadmin = PyKAdminObject_create();
    kadm5_ret_t retval = 0x0;

    krb5_principal princ = NULL;
    char *client_name    = NULL;
    char *keytab_name    = NULL;
    char **db_args       = NULL;

    kadm5_config_params *params = calloc(0x1, sizeof(kadm5_config_params));

    if (!PyArg_ParseTuple(args, "|zz", &client_name, &keytab_name))
        return NULL; 

    if (keytab_name == NULL) {
        
        keytab_name = "/etc/krb5.keytab";
    }
  
    if (client_name == NULL) {
        
        retval = krb5_sname_to_principal(kadmin->context, NULL, "host", KRB5_NT_SRV_HST, &princ);
        if (retval) { PyKAdmin_RaiseKAdminError(retval, "krb5_sname_to_principal"); return NULL; }
        
        retval = krb5_unparse_name(kadmin->context, princ, &client_name);
        if (retval) { PyKAdmin_RaiseKAdminError(retval, "krb5_unparse_name"); return NULL; }

        krb5_free_principal(kadmin->context, princ);
    }



    retval = kadm5_init_with_skey(
                kadmin->context, 
                client_name, 
                keytab_name, 
                service_name, 
                params,
                struct_version, 
                api_version, 
                db_args, 
                &kadmin->server_handle);

    if (retval) { PyKAdmin_RaiseKAdminError(retval, "kadm5_init_with_skey"); return NULL; }


   // kadmin->context = kadmin->server_handle->context;

    //retval = krb5_db_setup_lib_handle(kadmin->context);

 //   if (retval) {
   //     printf("retval [%d] %s\n", retval, krb5_get_error_message(kadmin->context, retval));
   // 
    //}
    //if (retval) { PyKAdmin_RaiseKAdminError(retval, "kadm5_init_with_skey"); return NULL; }


    Py_XINCREF(kadmin);
    return kadmin;
}


static PyKAdminObject *_kadmin_init_with_password(PyObject *self, PyObject *args) {

    PyKAdminObject *kadmin = PyKAdminObject_create();
    kadm5_ret_t retval;
    
    char *client_name = NULL;
    char *password    = NULL;
    char **db_args    = NULL;
     
    kadm5_config_params *params = calloc(0x1, sizeof(kadm5_config_params));

    if (!PyArg_ParseTuple(args, "zz", &client_name, &password))
        return NULL;

    retval = kadm5_init_with_password(
                kadmin->context, 
                client_name, 
                password, 
                service_name, 
                params, 
                struct_version, 
                api_version, 
                db_args, 
                &kadmin->server_handle);
    
    if (retval) { PyKAdmin_RaiseKAdminError(retval, "kadm5_init_with_password"); return NULL; }

    Py_XINCREF(kadmin);
    return kadmin;

}

