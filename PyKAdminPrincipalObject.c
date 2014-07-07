
#include "PyKAdminObject.h"
#include "PyKAdminErrors.h"
#include "PyKAdminIterator.h"
#include "PyKAdminPrincipalObject.h"
#include "PyKAdminPolicyObject.h"

#include "PyKAdminCommon.h"

#define IS_NULL(ptr) (ptr == NULL)

static void KAdminPrincipal_dealloc(PyKAdminPrincipalObject *self) {
    
    kadm5_free_principal_ent(self->kadmin->server_handle, &self->entry);

    Py_XDECREF(self->kadmin);
   
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject *KAdminPrincipal_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {

    PyKAdminPrincipalObject *self;

    self = (PyKAdminPrincipalObject *)type->tp_alloc(type, 0);

    if (!self)
        return NULL;
    
    memset(&self->entry, 0, sizeof(kadm5_principal_ent_rec));
    return (PyObject *)self;    
}

static int KAdminPrincipal_init(PyKAdminPrincipalObject *self, PyObject *args, PyObject *kwds) {
    return 0;
}

static int KAdminPrincipal_print(PyKAdminPrincipalObject *self, FILE *file, int flags){

    krb5_error_code retval = 0; 
    char *client_name = NULL;

    if (self->kadmin) {
        
        retval = krb5_unparse_name(self->kadmin->context, self->entry.principal, &client_name);
        /*if (retval) {
            printf("%d\n", retval);
        }*/

        printf("<kadmin:principal> %s", client_name);
    }

    if (client_name)
        free(client_name);
    
    return 0;
}



static PyMemberDef KAdminPrincipal_members[] = {


    {"last_password_change",        T_INT, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, last_pwd_change),       READONLY, ""},
    {"expire_time",                 T_INT, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, princ_expire_time),     READONLY, ""},
    {"password_expiration",         T_INT, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, pw_expiration),         READONLY, ""},
    {"modified_time",               T_INT, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, mod_date),              READONLY, ""},
    {"max_life",                    T_INT, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, max_life),              READONLY, ""},
    
    {"max_renewable_life",          T_INT, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, max_renewable_life),    READONLY, ""},
    {"last_success",                T_INT, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, last_success),          READONLY, ""},
    {"last_failed",                 T_INT, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, last_failed),           READONLY, ""},
    {"failed_auth_count",           T_INT, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, fail_auth_count),       READONLY, ""},
    
    {"key_version_number",          T_INT, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, kvno),                  READONLY, ""},
    {"master_key_version_number",   T_INT, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, mkvno),                 READONLY, ""},

    {"policy",                      T_STRING, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, policy),                READONLY, ""},
    
    {NULL}
};


static PyObject *PyKAdminPrincipal_get_principal(PyKAdminPrincipalObject *self, void *closure) {
  
    char *client_name = NULL;
    
    krb5_unparse_name(self->kadmin->context, self->entry.principal, &client_name);

    PyObject *principal = Py_BuildValue("s", client_name);

    free(client_name);

    return principal;
}

static PyObject *KAdminPrincipal_set_expire(PyKAdminPrincipalObject *self, PyObject *args, PyObject *kwds) {
    
    kadm5_ret_t retval; 
    time_t date     = 0; 
    char *expire    = NULL;

    if (!PyArg_ParseTuple(args, "s", &expire))
        return NULL;
    
    date = get_date(expire);

    self->entry.princ_expire_time = date;

    retval = kadm5_modify_principal(self->kadmin->server_handle, &self->entry, KADM5_PRINC_EXPIRE_TIME);
    if (retval != 0x0) { PyKAdmin_RaiseKAdminError(retval, "kadm5_modify_principal"); return NULL; }

    Py_RETURN_TRUE;
}

static PyObject *KAdminPrincipal_set_policy(PyKAdminPrincipalObject *self, PyObject *args, PyObject *kwds) {
    
    kadm5_ret_t retval; 
    char *policy = NULL;

    if (!PyArg_ParseTuple(args, "s", &policy))
        return NULL;
    
    strcpy(self->entry.policy, policy);

    retval = kadm5_modify_principal(self->kadmin->server_handle, &self->entry, KADM5_POLICY);
    if (retval != 0x0) { PyKAdmin_RaiseKAdminError(retval, "kadm5_modify_principal"); return NULL; }

    Py_RETURN_TRUE;
}

static PyObject *KAdminPrincipal_clear_policy(PyKAdminPrincipalObject *self, PyObject *args, PyObject *kwds) {
    
    kadm5_ret_t retval; 

    retval = kadm5_modify_principal(self->kadmin->server_handle, &self->entry, KADM5_POLICY_CLR);
    if (retval != 0x0) { PyKAdmin_RaiseKAdminError(retval, "kadm5_modify_principal"); return NULL; }

    Py_RETURN_TRUE;
}


static PyGetSetDef KAdminPrincipal_getters_setters[] = {

    // {"policy", (getter)PyKAdminPrincipal_get_policy, (setter)PyKAdminPrincipal_set_policy, "Kerberos Policy"},
    // {"principal", (getter)PyKAdminPrincipal_get_principal, (setter)PyKAdminPrincipal_set_principal, "Kerberos Principal"},
    // {"policy", (getter)PyKAdminPrincipal_get_policy, NULL, "Kerberos Policy"},
    
    {"principal", (getter)PyKAdminPrincipal_get_principal, NULL, "Kerberos Principal"},
    {NULL}
};

static PyObject *_KAdminPrincipal_load_principal(PyKAdminPrincipalObject *self, char *client_name) {

    kadm5_ret_t retval;
    krb5_error_code errno;
    krb5_principal parsed_name;

    if (client_name) {

        errno = krb5_parse_name(self->kadmin->context, client_name, &parsed_name);

        if (errno) {
           printf("Failed to parse princ name %d\n", errno);
        }
    
        retval = kadm5_get_principal(self->kadmin->server_handle, parsed_name, &self->entry, KADM5_PRINCIPAL_NORMAL_MASK);
        if (retval != 0x0) { PyKAdmin_RaiseKAdminError(retval, "kadm5_get_principal"); return NULL; }

        krb5_free_principal(self->kadmin->context, parsed_name);
    
        Py_RETURN_TRUE;
    }

    // TODO: raise exception 
    return NULL;
    //Py_RETURN_FALSE;
}

static PyObject *_KAdminPrincipal_refresh_principal(PyKAdminPrincipalObject *self) {

    kadm5_ret_t retval;

    retval = kadm5_get_principal(self->kadmin->server_handle, self->entry.principal, &self->entry, KADM5_PRINCIPAL_NORMAL_MASK);
    if (retval != 0x0) { PyKAdmin_RaiseKAdminError(retval, "kadm5_get_principal"); return NULL; }

    Py_RETURN_NONE;

}

static PyObject *KAdminPrincipal_change_password(PyKAdminPrincipalObject *self, PyObject *args, PyObject *kwds) {

    kadm5_ret_t retval; 
    char *password  = NULL;
    char *canon     = NULL;

    if (!PyArg_ParseTuple(args, "s", &password))
        return NULL; 

    if (password) {

        retval = krb5_unparse_name(self->kadmin->context, self->entry.principal, &canon);

        if (retval) {
            printf("krb5_unparse_name failure: %ld\n", retval); 
        }
        
        retval = kadm5_chpass_principal(self->kadmin->server_handle, self->entry.principal, password);
        if (retval != 0x0) { PyKAdmin_RaiseKAdminError(retval, "kadm5_chpass_principal"); return NULL; }
            
        _KAdminPrincipal_refresh_principal(self);
        
        Py_RETURN_TRUE;

    } else {
        Py_RETURN_FALSE;
    }
}

static PyObject *KAdminPrincipal_randomize_key(PyKAdminPrincipalObject *self, PyObject *args, PyObject *kwds) {

    kadm5_ret_t retval; 
    char *canon = NULL;

    retval = krb5_unparse_name(self->kadmin->context, self->entry.principal, &canon);
    if (retval != 0x0) { PyKAdmin_RaiseKAdminError(retval, "krb5_unparse_name"); return NULL; }

    retval = kadm5_randkey_principal(self->kadmin->server_handle, self->entry.principal, NULL, NULL);
    if (retval != 0x0) { PyKAdmin_RaiseKAdminError(retval, "kadm5_randkey_principal"); return NULL; }

    _KAdminPrincipal_refresh_principal(self);

    Py_XINCREF(Py_True);
    return Py_True;
}

static PyObject *KAdminPrincipal_get_name(PyKAdminPrincipalObject *self, PyObject *args, PyObject *kwds) {

    krb5_error_code retval = 0; 
    char *client_name = NULL;
    PyObject *name = NULL;

    if (self->kadmin) {
        
        retval = krb5_unparse_name(self->kadmin->context, self->entry.principal, &client_name);
        if (retval) {}

        name = Py_BuildValue("z", client_name);

    }
    
    return name;
}

static PyMethodDef KAdminPrincipal_methods[] = {
    {"cpw",             (PyCFunction)KAdminPrincipal_change_password,   METH_VARARGS, ""},
    {"change_password", (PyCFunction)KAdminPrincipal_change_password,   METH_VARARGS, ""},
    {"randkey",         (PyCFunction)KAdminPrincipal_randomize_key,     METH_VARARGS, ""},
    {"randomize_key",   (PyCFunction)KAdminPrincipal_randomize_key,     METH_VARARGS, ""},
    
    {"expire",          (PyCFunction)KAdminPrincipal_set_expire,     METH_VARARGS, ""},
    {"set_policy",      (PyCFunction)KAdminPrincipal_set_policy,     METH_VARARGS, ""},
    {"clear_policy",    (PyCFunction)KAdminPrincipal_clear_policy,   METH_VARARGS, ""},

    {"name",            (PyCFunction)KAdminPrincipal_get_name,        METH_VARARGS, ""},

    {NULL, NULL, 0, NULL}
};


PyTypeObject PyKAdminPrincipalObject_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "kadmin.Principal",             /*tp_name*/
    sizeof(PyKAdminPrincipalObject),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)KAdminPrincipal_dealloc, /*tp_dealloc*/
    (printfunc)KAdminPrincipal_print,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0, //PyKAdminPrincipal_str,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,   /*tp_flags*/
    "KAdminPrincipal objects",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    KAdminPrincipal_methods,             /* tp_methods */
    KAdminPrincipal_members,             /* tp_members */
    KAdminPrincipal_getters_setters,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)KAdminPrincipal_init,      /* tp_init */
    0,                         /* tp_alloc */
    KAdminPrincipal_new,                 /* tp_new */
};


PyKAdminPrincipalObject *PyKAdminPrincipalObject_principal_with_name(PyKAdminObject *kadmin, char *client_name) {

    PyKAdminPrincipalObject *principal = (PyKAdminPrincipalObject *)KAdminPrincipal_new(&PyKAdminPrincipalObject_Type, NULL, NULL);

    if (principal) {

        Py_XINCREF(kadmin);
        principal->kadmin = kadmin;

        /* todo : fetch kadmin entry */
        PyObject *result = _KAdminPrincipal_load_principal(principal, client_name);

        if (!result) {
            Py_XDECREF(kadmin);
            Py_XINCREF(Py_None);
            KAdminPrincipal_dealloc(principal);
            principal = (PyKAdminPrincipalObject *)Py_None;
        }

    }

    return principal;
}

PyKAdminPrincipalObject *PyKadminPrincipalObject_principal_with_db_entry(PyKAdminObject *kadmin, krb5_db_entry *kdb) {

    krb5_error_code retval;

    PyKAdminPrincipalObject *principal = (PyKAdminPrincipalObject *)KAdminPrincipal_new(&PyKAdminPrincipalObject_Type, NULL, NULL);

    if (kdb) {

        Py_XINCREF(kadmin);
        principal->kadmin = kadmin;

        retval = pykadmin_kadm_from_kdb(kadmin, kdb, &principal->entry, KADM5_PRINCIPAL_NORMAL_MASK);

        if (retval) {

        } 
    }

    return principal;
}

/*
PyKAdminPrincipalObject *PyKadminPrincipalObject_principal_with_kadm_entry(PyKAdminObject *kadmin, kadm5_principal_ent_rec *entry) {

    krb5_error_code retval;

    PyKAdminPrincipalObject *principal = (PyKAdminPrincipalObject *)KAdminPrincipal_new(&PyKAdminPrincipalObject_Type, NULL, NULL);

    if (entry) {

        Py_XINCREF(kadmin);
        principal->kadmin = kadmin;

        //retval = pykadmin_copy_kadm_ent_rec(kadmin, entry, &principal->entry);

        if (retval) {

        }


    }

    return principal;
}
*/

PyKAdminPrincipalObject *PyKAdminPrincipalObject_create(PyKAdminObject *kadmin, char *client_name) {

    PyKAdminPrincipalObject *principal = NULL; 

    principal = (PyKAdminPrincipalObject *)KAdminPrincipal_new(&PyKAdminPrincipalObject_Type, NULL, NULL);

    if (principal) {
        principal->kadmin = kadmin;
        Py_XINCREF(kadmin);

        PyObject *result = _KAdminPrincipal_load_principal(principal, client_name);

        if (!result) {
            KAdminPrincipal_dealloc(principal);
            principal = (PyKAdminPrincipalObject *)Py_None;
            Py_XDECREF(kadmin);
            Py_XINCREF(Py_None);
        }
    }

    return principal;
}

void KAdminPrincipal_destroy(PyKAdminPrincipalObject *self) {
    KAdminPrincipal_dealloc(self);
}



