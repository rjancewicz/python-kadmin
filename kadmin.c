

#include <Python.h>
#include <kadm5/admin.h>
#include <krb5/krb5.h>
#include <stdio.h>
#include <string.h>
#include <structmember.h>

#include "PyKAdminObject.h"
#include "PyKAdminErrors.h"
#include "PyKAdminIterator.h"
#include "PyKAdminPrincipalObject.h"
#include "PyKAdminPolicyObject.h"

#define IS_NULL(ptr) (ptr == NULL)

static PyKAdminObject *_kadmin_init_with_creds(PyObject *self, PyObject *args); 
static PyKAdminObject *_kadmin_init_with_keytab(PyObject *self, PyObject *args); 
static PyKAdminObject *_kadmin_init_with_password(PyObject *self, PyObject *args); 
static PyKAdminObject *_kadmin_local(PyObject *self, PyObject *args); 

static char module_docstring[] = "";

krb5_context context;

void *server_handle         = NULL;
char *default_realm         = NULL;
char *service_name          = KADM5_ADMIN_SERVICE;
krb5_ui_4 struct_version    = KADM5_STRUCT_VERSION;
krb5_ui_4 api_version       = KADM5_API_VERSION_2;

static struct PyMethodDef module_methods[] = {
    
    {"init_with_creds",     (PyCFunction)_kadmin_init_with_creds,       METH_VARARGS, ""},
    {"init_with_keytab",    (PyCFunction)_kadmin_init_with_keytab,      METH_VARARGS, "init_with_keytab([principal[, keytab_path]] )"},
    {"init_with_password",  (PyCFunction)_kadmin_init_with_password,    METH_VARARGS, ""},
    {"local",     (PyCFunction)_kadmin_local,       METH_VARARGS, ""},
    {NULL, NULL, 0, NULL}
};


PyMODINIT_FUNC initkadmin(void) {

    if (PyType_Ready(&PyKAdminObject_Type) < 0) 
        return;

    if (PyType_Ready(&PyKAdminPrincipalObject_Type) < 0)
        return;

    Py_XINCREF(&PyKAdminObject_Type);
    Py_XINCREF(&PyKAdminPrincipalObject_Type);

    PyObject *module = Py_InitModule3("kadmin", module_methods, module_docstring);
    if (IS_NULL(module)) 
        return;

    KAdminError = PyErr_NewException("kadmin.KAdminError", NULL, NULL);
    Py_XINCREF(KAdminError);

    PyModule_AddObject(module, "KAdminError", KAdminError);

    PyKAdminError_init(module); 

}

/*
void _kadmin_init_errors(void) {
    
    PyObject *base_exception = PyErr_NewException("kadmin.Error", NULL, NULL);
    
    PyObject *error = PyErr_NewException("kadmin.newException", base_exception, NULL);

}
*/

static PyKAdminObject *_kadmin_init_with_creds(PyObject *self, PyObject *args) {
    
    return NULL;
}


static PyKAdminObject *_kadmin_local(PyObject *self, PyObject *args) {

    PyKAdminObject *kadmin = PyKAdminObject_create();
    kadm5_ret_t retval = 0x0;

    kadm5_config_params *params = calloc(0x1, sizeof(kadm5_config_params));

    retval = kadm5_init_with_password(kadmin->context, "test/admin@EXAMPLE.COM", NULL, service_name, params, struct_version, api_version, NULL, &kadmin->server_handle);
    //if (retval != 0x0) { PyKAdmin_RaiseKAdminError(retval, "kadm5_init_with_password"); return NULL; }

    return kadmin;

}

static PyKAdminObject *_kadmin_init_with_keytab(PyObject *self, PyObject *args) {

    PyKAdminObject *kadmin = PyKAdminObject_create();
    kadm5_ret_t retval = 0x0;

    krb5_principal principal    = NULL;
    char *client_name           = NULL;
    char *keytab_name           = NULL;

    kadm5_config_params *params = calloc(0x1, sizeof(kadm5_config_params));

 //   kadm5_config_params params;
 //   memset(&params, 0, sizeof(params));

    if (!PyArg_ParseTuple(args, "|zz", &client_name, &keytab_name))
        return NULL; 
       
    if (keytab_name == NULL)
        keytab_name = "/etc/krb5.keytab";
    
    // krb5_sname_to_principal(krb5_context context, const char *hostname, const char *sname,
    //                        krb5_int32 type, krb5_principal *ret_princ);
  
    if (client_name == NULL) {
        
        retval = krb5_sname_to_principal(kadmin->context, NULL, "host", KRB5_NT_SRV_HST, &principal);
        if (retval) { PyKAdmin_RaiseKAdminError(retval, "krb5_sname_to_principal"); return NULL; }
        /*
        if (retval) {
            RETURN_KAdminError(retval, "krb5_sname_to_principal");
        }*/
        
        retval = krb5_unparse_name(kadmin->context, principal, &client_name);
        if (retval) { PyKAdmin_RaiseKAdminError(retval, "krb5_unparse_name"); return NULL; }
        //PyKAdmin_HandleKAdminError(retval, "krb5_unparse_name");
        
        /*if (retval) {
            printf("krb5_unparse_name failure %ld\n", retval);
        }*/

        krb5_free_principal(kadmin->context, principal);
    }




    retval = kadm5_init_with_skey(kadmin->context, client_name, keytab_name, service_name, params, struct_version, api_version, NULL, &kadmin->server_handle);
    if (retval) { PyKAdmin_RaiseKAdminError(retval, "kadm5_init_with_skey"); return NULL; }
    //PyKAdmin_HandleKAdminError(retval, "kadm5_init_with_skey");


    /*
    if (retval) {
        PyKAdminObject_destroy(kadmin);
        return (PyKAdminObject *)PyKAdminError_raise_kadmin_error(retval, "kadm5_init_with_skey");
    }
    */

    return kadmin;
}


static PyKAdminObject *_kadmin_init_with_password(PyObject *self, PyObject *args) {

    PyKAdminObject *kadmin = PyKAdminObject_create();
    kadm5_ret_t retval;
    
    char *client_name   = NULL;
    char *password   = NULL;
     
    kadm5_config_params *params = calloc(0x1, sizeof(kadm5_config_params));
    //memset((char *) &params, 0, sizeof(params));

    if (!PyArg_ParseTuple(args, "zz", &client_name, &password))
        return NULL;

    retval = kadm5_init_with_password(kadmin->context, client_name, password, service_name, params, struct_version, api_version, NULL, &kadmin->server_handle);
    if (retval) {
        printf("kadm5_init_with_password failure: %ld\n", retval);
        PyKAdminObject_destroy(kadmin);
        return NULL;
    }

    Py_XINCREF(kadmin);
    return kadmin;

}

