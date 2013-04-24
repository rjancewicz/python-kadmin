/*
 *
 *
 */


#include <python2.6/Python.h>
#include <kadm5/admin.h>
#include <krb5/krb5.h>

#include <stdio.h>
#include <string.h>

#include "PyKAdminObject.h"
#include "PyKAdminPrincipalObject.h"


//static PyObject *_kadmin_get_principal(PyObject *self, PyObject *args);

static PyKAdminObject *_kadmin_init_with_creds(PyObject *self, PyObject *args); 
static PyKAdminObject *_kadmin_init_with_keytab(PyObject *self, PyObject *args); 
static PyKAdminObject *_kadmin_init_with_password(PyObject *self, PyObject *args); 

//static PyObject *_kadmin_destroy(PyObject *self, PyObject *args); 


static char module_docstring[] = "hello, world!";


krb5_context context;

void *server_handle = NULL;
char *default_realm = NULL;
//


static struct PyMethodDef module_methods[] = {
    
    {"init_with_creds", (PyCFunction)_kadmin_init_with_creds, METH_VARARGS, ""},
    {"init_with_keytab", (PyCFunction)_kadmin_init_with_keytab, METH_VARARGS, ""},
    {"init_with_password", (PyCFunction)_kadmin_init_with_password, METH_VARARGS, ""},

    //{"destroy", _kadmin_destroy, METH_VARARGS, ""},
    {NULL, NULL, 0, NULL}
};




PyMODINIT_FUNC initkadmin(void) {

    if (PyType_Ready(&PyKAdminObject_Type) < 0) 
        return;

    if (PyType_Ready(&PyKAdminPrincipalObject_Type) < 0)
        return;

    Py_XINCREF(&PyKAdminObject_Type);
    Py_XINCREF(&PyKAdminPrincipalObject_Type);

    // PyObject *module = Py_InitModule3("_kadmin", module_methods, module_docstring);
    PyObject *module = Py_InitModule3("kadmin", module_methods, module_docstring);
    if (module == NULL)
        return;

   

}

/*
void _kadmin_init_errors(void) {
    
    PyObject *base_exception = PyErr_NewException("kadmin.Error", NULL, NULL);
    
    PyObject *error = PyErr_NewException("kadmin.newException", base_exception, NULL);

}
*/



static PyKAdminObject *_kadmin_init_with_creds(PyObject *self, PyObject *args) {
    // (char *client_name, krb5_ccache cc, char *service_name, kadm5_config_params *params, krb5_ui_4 struct_version, krb5_ui_4 api_version, char **db_args, void **server_handle)
    
    PyObject *ret = NULL;

    char *retstr                = NULL;
    kadm5_ret_t retval;

    char *client_name           = NULL;     // principal
    char *ccache_name           = NULL;
    krb5_ccache cc              = NULL;
    char *service_name          = KADM5_ADMIN_SERVICE;
    krb5_ui_4 struct_version    = KADM5_STRUCT_VERSION;
    krb5_ui_4 api_version       = KADM5_API_VERSION_2;

    kadm5_config_params params;
    memset((char *) &params, 0, sizeof(params));

    
    if (!PyArg_ParseTuple(args, "sz", &client_name, &ccache_name))
        return NULL;
    
    if (default_realm == NULL && krb5_get_default_realm(context, &default_realm)) {
        fprintf(stderr, "%s: unable to get default realm\n", client_name);
    }

    params.mask |= KADM5_CONFIG_REALM;
    params.realm = default_realm;


    if (ccache_name == NULL) {
        if ( (retval = krb5_cc_default(context, &cc)) ) {
            return NULL;
        }
    } else {
        if ( (retval = krb5_cc_resolve(context, ccache_name, &cc)) ) {
            return NULL;
        }
    }

    retval = kadm5_init_with_creds(context, client_name, cc, service_name, &params, struct_version, api_version, NULL, &server_handle);
   
    if (retval) {
        retstr = "Error";
    } else {
        retstr = "Success";
    }
    

    //char *hello = malloc(sizeof(char) * 200);
    
    //sprintf(hello, "%s", client_name);

    //kr

    ret = Py_BuildValue("s", retstr);

    return ret;
}

/*
kadm5_ret_t    kadm5_init_with_skey(krb5_context context,
                                    char *client_name,
                                    char *keytab,
                                    char *service_name,
                                    kadm5_config_params *params,
                                    krb5_ui_4 struct_version,
                                    krb5_ui_4 api_version,
                                    char **db_args,
                                    void **server_handle);
*/

//static PyObject *_kadmin_init_with_keytab(PyObject *self, PyObject *args) {
static PyKAdminObject *_kadmin_init_with_keytab(PyObject *self, PyObject *args) {

    PyKAdminObject *kadmin = PyKAdminObject_create();

    //PyObject *ret = NULL;
    kadm5_ret_t retval;
    char *retstr;

    krb5_principal principal    = NULL;
    char *client_name           = NULL;
    char *keytab_name           = NULL;
    char *service_name          = KADM5_ADMIN_SERVICE;
    krb5_ui_4 struct_version    = KADM5_STRUCT_VERSION;
    krb5_ui_4 api_version       = KADM5_API_VERSION_2;

    kadm5_config_params params;
    memset((char *) &params, 0, sizeof(params));

    if (!PyArg_ParseTuple(args, "|zz", &client_name, &keytab_name))
        return NULL; 
       
    if (keytab_name == NULL)
        keytab_name = "/etc/krb5.keytab";
    
    // krb5_sname_to_principal(krb5_context context, const char *hostname, const char *sname,
    //                        krb5_int32 type, krb5_principal *ret_princ);
  
    if (client_name == NULL) {

        if ( (retval = krb5_sname_to_principal(kadmin->context, NULL, "host", KRB5_NT_SRV_HST, &principal)) ) {
            printf("krb5_sname_to_principal %ld\n", retval);
        }
        
        if ( (retval = krb5_unparse_name(kadmin->context, principal, &client_name)) ) {
            printf("krb5_unparse_name %ld\n", retval);
        }

        krb5_free_principal(kadmin->context, principal);
    }

    // debug
    printf("Connecting to kadmin;\n\tclient_name: %s\n\tkeytab_name: %s\n", client_name, keytab_name);

    if ( (retval = kadm5_init_with_skey(kadmin->context, client_name, keytab_name, service_name, &params, struct_version, api_version, NULL, &kadmin->handle)) ) {
        printf("kadm5_init_with_skey %ld\n", retval);
    }


    //ret = Py_True;
    
    return kadmin;
}


static PyKAdminObject *_kadmin_init_with_password(PyObject *self, PyObject *args) {

    PyObject *ret = NULL;
    return ret;

}

/*
    kadm5_ret_t    kadm5_get_principal(void *server_handle,
                                   krb5_principal principal,
                                   kadm5_principal_ent_t ent,
                                   long mask);
*/

/*    

typedef krb5_error_code krb5_magic; 

typedef struct krb5_principal_data {
    krb5_magic magic;
    krb5_data realm;
    krb5_data *data;            // < An array of strings 
    krb5_int32 length;
    krb5_int32 type;
} krb5_principal_data;

typedef struct _krb5_data {
    krb5_magic magic;
    unsigned int length;
    char *data;
} krb5_data;

*/



// static PyObject *__kadmin_principal_entry_object(kadm5_principal_ent_t entry) {


/*

typedef struct _kadm5_principal_ent_t {
    krb5_principal  principal;          // PRINCIPAL
    krb5_timestamp  princ_expire_time;  // krb5_int32
    krb5_timestamp  last_pwd_change;    // krb5_int32
    krb5_timestamp  pw_expiration;      // krb5_int32
    krb5_deltat     max_life;           // krb5_int32
    krb5_principal  mod_name;           // PRINCIPAL
    krb5_timestamp  mod_date;           // krb5_int32
    krb5_flags      attributes;         // krb5_int32
    krb5_kvno       kvno;               // unsigned int
    krb5_kvno       mkvno;              // unsigned int
    char            *policy;            
    long            aux_attributes;

    // version 2 fields //
    krb5_deltat max_renewable_life;     // krb5_int32
    krb5_timestamp last_success;        // krb5_int32
    krb5_timestamp last_failed;         // krb5_int32
    krb5_kvno fail_auth_count;          // unsigned int
    krb5_int16 n_key_data;              
    krb5_int16 n_tl_data;
    krb5_tl_data *tl_data;              
    krb5_key_data *key_data;
} kadm5_principal_ent_rec, *kadm5_principal_ent_t;

*/

   // PyObject *ret = NULL;
    

    

  //  return ret;
//}
/*
static PyObject *_kadmin_get_principal(PyObject *self, PyObject *args) { 

    PyObject *ret           = NULL;
    kadm5_ret_t retval      = NULL;
   
    char *client_name           = NULL;
    krb5_principal principal;
    kadm5_principal_ent_t entry;

    if (!PyArg_ParseTuple(args, "s", &client_name))
        return NULL; 
   
    // TODO validate client_name is complete with name@DOMAIN structure

    krb5_parse_name(context, client_name, &principal);
    
    kadm5_get_principal(server_handle, principal, entry, KADM5_PRINCIPAL_NORMAL_MASK);


    return ret;

}

static PyObject *_kadmin_destroy(PyObject *self, PyObject *args) {
    return NULL;
}

*/

