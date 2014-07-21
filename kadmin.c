
#include "pykadmin.h"

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
    {"local",               (PyCFunction)_kadmin_local,             METH_NOARGS, "local()"},
    #endif

    {"init_with_ccache",   (PyCFunction)_kadmin_init_with_ccache,   METH_VARARGS, "init_with_ccache(principal, ccache)"},
    {"init_with_keytab",   (PyCFunction)_kadmin_init_with_keytab,   METH_VARARGS, "init_with_keytab(principal, keytab)"},
    {"init_with_password", (PyCFunction)_kadmin_init_with_password, METH_VARARGS, "init_with_password(principal, password)"},

    /* todo: these should permit the user to set/get the 
        service, struct, api version, default realm, ... 

    {"get_option",         (PyCFunction)_get_option, METH_VARARGS,  "_get_option(option)"},
    {"set_option",         (PyCFunction)_set_option, METH_VARARGS,  "_set_option(option, value)"},
    */

    {NULL, NULL, 0, NULL}
};

void PyKAdminConstant_init(PyObject *module) {

    PyModule_AddIntConstant(module, "DISALLOW_POSTDATED",     KRB5_KDB_DISALLOW_POSTDATED);
    PyModule_AddIntConstant(module, "DISALLOW_FORWARDABLE",   KRB5_KDB_DISALLOW_FORWARDABLE);
    PyModule_AddIntConstant(module, "DISALLOW_TGT_BASED",     KRB5_KDB_DISALLOW_TGT_BASED);
    PyModule_AddIntConstant(module, "DISALLOW_RENEWABLE",     KRB5_KDB_DISALLOW_RENEWABLE);
    PyModule_AddIntConstant(module, "DISALLOW_PROXIABLE",     KRB5_KDB_DISALLOW_PROXIABLE);
    PyModule_AddIntConstant(module, "DISALLOW_DUP_SKEY",      KRB5_KDB_DISALLOW_DUP_SKEY);
    PyModule_AddIntConstant(module, "DISALLOW_ALL_TIX",       KRB5_KDB_DISALLOW_ALL_TIX);
    PyModule_AddIntConstant(module, "REQUIRES_PRE_AUTH",      KRB5_KDB_REQUIRES_PRE_AUTH);
    PyModule_AddIntConstant(module, "REQUIRES_HW_AUTH",       KRB5_KDB_REQUIRES_HW_AUTH);
    PyModule_AddIntConstant(module, "REQUIRES_PWCHANGE",      KRB5_KDB_REQUIRES_PWCHANGE);
    PyModule_AddIntConstant(module, "DISALLOW_SVR",           KRB5_KDB_DISALLOW_SVR);
    PyModule_AddIntConstant(module, "PWCHANGE_SERVICE",       KRB5_KDB_PWCHANGE_SERVICE);
    PyModule_AddIntConstant(module, "SUPPORT_DESMD5",         KRB5_KDB_SUPPORT_DESMD5);
    PyModule_AddIntConstant(module, "NEW_PRINC",              KRB5_KDB_NEW_PRINC);
    PyModule_AddIntConstant(module, "OK_AS_DELEGATE",         KRB5_KDB_OK_AS_DELEGATE);
    PyModule_AddIntConstant(module, "OK_TO_AUTH_AS_DELEGATE", KRB5_KDB_OK_TO_AUTH_AS_DELEGATE);
    PyModule_AddIntConstant(module, "NO_AUTH_DATA_REQUIRED",  KRB5_KDB_NO_AUTH_DATA_REQUIRED);
    
}

#ifdef PYTHON3

#   ifdef KADMIN_LOCAL
#   define PyKADMIN_INIT_FUNC PyObject *PyInit_kadmin_local(void)
#   else
#   define PyKADMIN_INIT_FUNC PyObject *PyInit_kadmin(void)
#   endif

#define PyModule_INIT_RETURN return NULL

static int pykadmin_traverse(PyObject *module, visitproc visit, void *arg) {
    Py_VISIT(GETSTATE(module)->error);
    return 0;
}

static int pykadmin_clear(PyObject *module) {
    Py_CLEAR(GETSTATE(module)->error);
    return 0;
}

static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        module_docstring,
        NULL,
        sizeof(struct module_state),
        module_methods,
        NULL,
        pykadmin_traverse,
        pykadmin_clear,
        NULL
};

#else 
    
#   ifdef KADMIN_LOCAL
#   define PyKADMIN_INIT_FUNC void initkadmin_local(void) 
#   else
#   define PyKADMIN_INIT_FUNC void initkadmin(void)
#   endif

#define PyModule_INIT_RETURN return

#endif



/*
PyMODINIT_FUNC 
#ifdef KADMIN_LOCAL
    initkadmin_local(void) 
#else
    initkadmin(void)
#endif
*/

PyKADMIN_INIT_FUNC {

    if (PyType_Ready(&PyKAdminObject_Type) < 0) 
        PyModule_INIT_RETURN;

    if (PyType_Ready(&PyKAdminPrincipalObject_Type) < 0)
        PyModule_INIT_RETURN;

    if (PyType_Ready(&PyKAdminPolicyObject_Type) < 0)
        PyModule_INIT_RETURN;

    #ifdef PYTHON3
    PyObject *module = PyModule_Create(&moduledef);
    #else
    PyObject *module = Py_InitModule3(kMODULE_NAME, module_methods, module_docstring);
    #endif


    if (!module) {
        PyModule_INIT_RETURN;
    }

    Py_INCREF(&PyKAdminObject_Type);
    Py_INCREF(&PyKAdminPrincipalObject_Type);
    Py_INCREF(&PyKAdminPolicyObject_Type);
                
    PyKAdminError_init(module);
    PyKAdminConstant_init(module);

#ifdef PYTHON3
    return module;
#endif

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

    if (retval) { PyKAdminError_raise_kadm_error(retval, "kadm5_init_with_password"); return NULL; }

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
        if (retval) { PyKAdminError_raise_kadm_error(retval, "krb5_cc_default"); return NULL; }
    } else {
        retval = krb5_cc_resolve(kadmin->context, ccache_name, &cc);
        if (retval) { PyKAdminError_raise_kadm_error(retval, "krb5_cc_resolve"); return NULL; }
    } 

    if (client_name == NULL) {
        retval = krb5_cc_get_principal(kadmin->context, cc, &princ);
        if (retval) { PyKAdminError_raise_kadm_error(retval, "krb5_cc_get_principal"); return NULL; }

        retval = krb5_unparse_name(kadmin->context, princ, &client_name);
        if (retval) { PyKAdminError_raise_kadm_error(retval, "krb5_unparse_name"); return NULL; }

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

    if (retval) { PyKAdminError_raise_kadm_error(retval, "kadm5_init_with_creds"); return NULL; }

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
        if (retval) { PyKAdminError_raise_kadm_error(retval, "krb5_sname_to_principal"); return NULL; }
        
        retval = krb5_unparse_name(kadmin->context, princ, &client_name);
        if (retval) { PyKAdminError_raise_kadm_error(retval, "krb5_unparse_name"); return NULL; }

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

    if (retval) { PyKAdminError_raise_kadm_error(retval, "kadm5_init_with_skey"); return NULL; }


   // kadmin->context = kadmin->server_handle->context;

    //retval = krb5_db_setup_lib_handle(kadmin->context);

 //   if (retval) {
   //     printf("retval [%d] %s\n", retval, krb5_get_error_message(kadmin->context, retval));
   // 
    //}
    //if (retval) { PyKAdminError_raise_kadm_error(retval, "kadm5_init_with_skey"); return NULL; }


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
    
    if (retval) { PyKAdminError_raise_kadm_error(retval, "kadm5_init_with_password"); return NULL; }

    Py_XINCREF(kadmin);
    return kadmin;

}

