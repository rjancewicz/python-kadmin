
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

static PyObject *_kadmin_get_option(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *_kadmin_set_option(PyObject *self, PyObject *args, PyObject *kwds);

static char module_docstring[] = "";

char *service_name          = KADM5_ADMIN_SERVICE;
krb5_ui_4 struct_version    = KADM5_STRUCT_VERSION;
krb5_ui_4 api_version       = KADM5_API_VERSION_2;

static struct PyMethodDef module_methods[] = {

    #ifdef KADMIN_LOCAL
    {"local",               (PyCFunction)_kadmin_local,             METH_VARARGS, "local()"},
    #endif

    {"init_with_ccache",   (PyCFunction)_kadmin_init_with_ccache,   METH_VARARGS, "init_with_ccache(principal, ccache)"},
    {"init_with_keytab",   (PyCFunction)_kadmin_init_with_keytab,   METH_VARARGS, "init_with_keytab(principal, keytab)"},
    {"init_with_password", (PyCFunction)_kadmin_init_with_password, METH_VARARGS, "init_with_password(principal, password)"},

    /* todo: these should permit the user to set/get the 
        service, struct, api version, default realm, ... 
    */
    {"get_option",         (PyCFunction)_kadmin_get_option, METH_VARARGS,  "get_option(option)"},
    {"set_option",         (PyCFunction)_kadmin_set_option, METH_VARARGS,  "set_option(option, value)"},

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

#define PyModule_RETURN_ERROR return NULL

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

#define PyModule_RETURN_ERROR return

static struct module_state _state;

#endif


PyKADMIN_INIT_FUNC {

    // initialize the module's class object types

    if (PyType_Ready(&PyKAdminObject_Type) < 0) 
        PyModule_RETURN_ERROR;

    if (PyType_Ready(&PyKAdminPrincipalObject_Type) < 0)
        PyModule_RETURN_ERROR;

    if (PyType_Ready(&PyKAdminPolicyObject_Type) < 0)
        PyModule_RETURN_ERROR;

    if (PyType_Ready(&PyKAdminIterator_Type) < 0)
        PyModule_RETURN_ERROR;

    // initialize the module

#   ifdef PYTHON3
    PyObject *module = PyModule_Create(&moduledef);
#   else
    PyObject *module = Py_InitModule3(kMODULE_NAME, module_methods, module_docstring);
#   endif

    if (!module) PyModule_RETURN_ERROR;

    // increment the ref for each type object

    Py_INCREF(&PyKAdminObject_Type);
    Py_INCREF(&PyKAdminPrincipalObject_Type);
    Py_INCREF(&PyKAdminPolicyObject_Type);
            
    // initialize the errors 

    struct module_state *st = GETSTATE(module);

    st->error = PyKAdminError_init(module);
    if (st->error == NULL) {
        Py_DECREF(module);
        PyModule_RETURN_ERROR;
    }

    // initialize constant
    PyKAdminConstant_init(module);

#ifdef PYTHON3
    return module;
#endif

}


static PyObject *_kadmin_get_option(PyObject *self, PyObject *args, PyObject *kwds) {

    // todo
    return NULL;
}

static PyObject *_kadmin_set_option(PyObject *self, PyObject *args, PyObject *kwds) {

    // todo
    return NULL;
}

char **_kadmin_dict_to_db_args(PyObject *dict) {

    PyObject *key   = NULL;
    PyObject *value = NULL;

    char *str_key   = NULL;
    char *str_value = NULL;
    char *argument  = NULL;
    char **db_args  = NULL;

    Py_ssize_t index  = 0;
    Py_ssize_t position  = 0;

    if (dict) {    

        Py_ssize_t length = PyDict_Size(dict) + 1;

        db_args = calloc(length, sizeof(intptr_t));

        if (db_args && PyDict_CheckExact(dict)) {

            while (PyDict_Next(dict, &position, &key, &value)) {

                if (PyUnicodeBytes_Check(key) && PyUnicodeBytes_Check(value)) {

                    str_key   = PyUnicode_or_PyBytes_asCString(key);
                    str_value = PyUnicode_or_PyBytes_asCString(value);

                    if (str_key && str_value) {

                        length = strlen(str_key) + strlen(str_value) + 2;
                        argument = calloc(length, sizeof(char));

                        if (argument) {
                            snprintf(argument, length, "%s=%s", str_key, str_value);
                            db_args[index++] = argument;
                        }
                    }
                }
            }

            db_args[index] = NULL;
        }
    }


    return db_args;

}

void _kadmin_free_db_args(char **db_args) {

    Py_ssize_t index = 0;

    if (db_args) {

        while(db_args[index] != NULL) {
            free(db_args[index++]);
        }

        free(db_args);
    }

}

#ifdef KADMIN_LOCAL
static PyKAdminObject *_kadmin_local(PyObject *self, PyObject *args) {

    static const char *kROOT_ADMIN = "root/admin";

    PyKAdminObject *kadmin = PyKAdminObject_create();
    PyObject *db_args_dict = NULL;
    kadm5_ret_t retval     = KADM5_OK; 
    int result             = 0;
    char **db_args         = NULL;
    char *client_name      = NULL;
    int has_error          = 0;

    if (!PyArg_ParseTuple(args, "|O!", &PyDict_Type, &db_args_dict))
        return NULL; 

    if (db_args_dict)
        db_args = _kadmin_dict_to_db_args(db_args_dict);

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

    if (db_args) {
        _kadmin_free_db_args(db_args);
	db_args = NULL;
    }

    if (retval != KADM5_OK) { PyKAdmin_RETURN_ERROR(retval, "kadm5_init_with_password.local"); }

 epilog:
    if (db_args) _kadmin_free_db_args(db_args);
    if (has_error) return NULL;
    return kadmin;
}
#endif


static PyKAdminObject *_kadmin_init_with_ccache(PyObject *self, PyObject *args) {
    
    PyKAdminObject *kadmin = PyKAdminObject_create();
    PyObject *db_args_dict = NULL;
    kadm5_ret_t retval = KADM5_OK;
    krb5_error_code code = 0;

    krb5_principal princ = NULL;
    char *ccache_name    = NULL;
    char *client_name    = NULL;
    char **db_args       = NULL;

    krb5_ccache cc;
    int has_error        = 0;

    kadm5_config_params *params = calloc(0x1, sizeof(kadm5_config_params));

    memset(&cc, 0, sizeof(krb5_ccache));

    // TODO : unpack database args as an optional third parameter (will be a dict or array)
    if (!PyArg_ParseTuple(args, "|zzO!", &client_name, &ccache_name, &PyDict_Type, &db_args_dict))
        return NULL; 

    db_args = _kadmin_dict_to_db_args(db_args_dict);

    if (!ccache_name) {
        code = krb5_cc_default(kadmin->context, &cc);
        if (code) { PyKAdmin_RETURN_ERROR(code, "krb5_cc_default"); }
    } else {
        code = krb5_cc_resolve(kadmin->context, ccache_name, &cc);
        if (code) { PyKAdmin_RETURN_ERROR(code, "krb5_cc_resolve"); }
    } 

    if (!client_name) {
        code = krb5_cc_get_principal(kadmin->context, cc, &princ);
        if (code) { PyKAdmin_RETURN_ERROR(code, "krb5_cc_get_principal"); }

        code = krb5_unparse_name(kadmin->context, princ, &client_name);
        if (code) { PyKAdmin_RETURN_ERROR(code, "krb5_unparse_name"); }

        krb5_free_principal(kadmin->context, princ);
	princ = NULL;
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

    if (db_args) {
        _kadmin_free_db_args(db_args);
	db_args = NULL;
    }

    if (retval != KADM5_OK) { PyKAdmin_RETURN_ERROR(retval, "kadm5_init_with_creds"); }

 epilog:
    if (princ) krb5_free_principal(kadmin->context, princ);
    if (db_args) _kadmin_free_db_args(db_args);
    if (has_error) return NULL;
    Py_XINCREF(kadmin);
    return kadmin;
}



static PyKAdminObject *_kadmin_init_with_keytab(PyObject *self, PyObject *args) {

    PyKAdminObject *kadmin = PyKAdminObject_create();
    PyObject *db_args_dict = NULL;
    kadm5_ret_t retval = KADM5_OK;
    krb5_error_code code = 0;

    krb5_principal princ = NULL;
    char *client_name    = NULL;
    char *keytab_name    = NULL;
    char **db_args       = NULL;
    int has_error        = 0;

    kadm5_config_params *params = calloc(0x1, sizeof(kadm5_config_params));

    if (!PyArg_ParseTuple(args, "|zzO!", &client_name, &keytab_name, &PyDict_Type, &db_args_dict))
        return NULL; 

    db_args = _kadmin_dict_to_db_args(db_args_dict);

    if (keytab_name == NULL) {
        keytab_name = "/etc/krb5.keytab";
    }
  
    if (client_name == NULL) {
        
        code = krb5_sname_to_principal(kadmin->context, NULL, "host", KRB5_NT_SRV_HST, &princ);
        if (code) { PyKAdmin_RETURN_ERROR(code, "krb5_sname_to_principal"); }
        
        code = krb5_unparse_name(kadmin->context, princ, &client_name);
        if (code) { PyKAdmin_RETURN_ERROR(code, "krb5_unparse_name"); }

        krb5_free_principal(kadmin->context, princ);
	princ = NULL;
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

    if (db_args) {
        _kadmin_free_db_args(db_args);
	db_args = NULL;
    }

    if (retval != KADM5_OK) { PyKAdmin_RETURN_ERROR(retval, "kadm5_init_with_skey"); }

 epilog:
    if (princ) krb5_free_principal(kadmin->context, princ);
    if (db_args) _kadmin_free_db_args(db_args);
    if (has_error) return NULL;
    Py_XINCREF(kadmin);
    return kadmin;
}


static PyKAdminObject *_kadmin_init_with_password(PyObject *self, PyObject *args) {

    PyKAdminObject *kadmin = PyKAdminObject_create();
    PyObject *db_args_dict = NULL;
    kadm5_ret_t retval = KADM5_OK;
    
    char *client_name = NULL;
    char *password    = NULL;
    char **db_args    = NULL;
    int has_error     = 0;
     
    kadm5_config_params params;
    memset(&params, 0, sizeof(params));

    if (!PyArg_ParseTuple(args, "zz|O!", &client_name, &password, &PyDict_Type, &db_args_dict))
        return NULL;

    db_args = _kadmin_dict_to_db_args(db_args_dict);

    retval = kadm5_init_with_password(
                kadmin->context, 
                client_name, 
                password, 
                service_name, 
                &params, 
                struct_version, 
                api_version, 
                db_args, 
                &kadmin->server_handle);

    if (db_args) {
        _kadmin_free_db_args(db_args);
	db_args = NULL;
    }

    if (retval != KADM5_OK) { PyKAdmin_RETURN_ERROR(retval, "kadm5_init_with_password"); }

 epilog:
    if (db_args) _kadmin_free_db_args(db_args);
    if (has_error) return NULL;
    Py_XINCREF(kadmin);
    return kadmin;

}

