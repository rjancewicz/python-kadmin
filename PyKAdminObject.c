
#include "PyKAdminObject.h"
#include "PyKAdminErrors.h"
#include "PyKAdminIterator.h"
#include "PyKAdminPrincipalObject.h"
#include "PyKAdminPolicyObject.h"

#include "PyKAdminCommon.h"


static void PyKAdminObject_dealloc(PyKAdminObject *self) {
    
    kadm5_ret_t retval;

    if (self) {
        krb5_db_unlock(self->context);

        if (self->server_handle) {
            retval = kadm5_destroy(self->server_handle);
            if (retval) {}
            self->server_handle = NULL;
        }
        
        if (self->context) {
            krb5_free_context(self->context);
            self->context = NULL;
        }

        if (self->realm) {
            free(self->realm);
        }

        self->ob_type->tp_free((PyObject*)self);
    }
}
    
static PyObject *PyKAdminObject_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {

    PyKAdminObject *self; 
    kadm5_ret_t retval = 0;

    self = (PyKAdminObject *)type->tp_alloc(type, 0);

    if (self) {
        retval = kadm5_init_krb5_context(&self->context);
        // retval = krb5_init_context(&self->context);

        if (retval) {
            Py_DECREF(self);
            PyKAdmin_RaiseKAdminError(retval, "kadm5_init_with_password");
            return NULL;
        }

        self->server_handle = NULL;

        // attempt to load the default realm for this connection
        //krb5_get_default_realm(self->context, &self->realm);
        //if (!self->realm) {
        //    // todo : fail 
        //}
    }

    return (PyObject *)self;    

}

static int PyKAdminObject_init(PyKAdminObject *self, PyObject *args, PyObject *kwds) {
    return 0;
}

static PyObject *PyKAdminObject_delete_principal(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    
    kadm5_ret_t retval;
    krb5_error_code errno;
    krb5_principal princ = NULL;

    char *client_name = NULL;

    if (!PyArg_ParseTuple(args, "s", &client_name))
        return NULL;

    if (self->server_handle) {

        retval = krb5_parse_name(self->context, client_name, &princ);
        if (retval != 0x0) { PyKAdmin_RaiseKAdminError(retval, "krb5_parse_name"); return NULL; }

        retval = kadm5_delete_principal(self->server_handle, princ);
        if (retval != 0x0) { PyKAdmin_RaiseKAdminError(retval, "kadm5_delete_principal"); return NULL; }

    }
    
    krb5_free_principal(self->context, princ);

    Py_RETURN_TRUE;

}


static PyObject *PyKAdminObject_create_principal(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    //PyObject *result = NULL;

    kadm5_ret_t retval;
    krb5_error_code errno;

    char *princ_name = NULL;
    char *princ_pass = NULL;

    kadm5_principal_ent_rec entry;
    
    memset(&entry, 0, sizeof(entry));
    entry.attributes = 0;
    
    if (!PyArg_ParseTuple(args, "s|z", &princ_name, &princ_pass))
        return NULL;

    if (self->server_handle) {

        if ( (errno = krb5_parse_name(self->context, princ_name, &entry.principal) ) ) {

            printf("Error: krb5_unparse_name [%d]\n", errno);
            return NULL; 
        
        } else {

            retval = kadm5_create_principal(self->server_handle, &entry, KADM5_PRINCIPAL, princ_pass); 
            
            if (retval != 0x0) { PyKAdmin_RaiseKAdminError(retval, "kadm5_create_principal"); return NULL; }
        }
    }

    kadm5_free_principal_ent(self->server_handle, &entry);

    Py_RETURN_TRUE;
}


static PyKAdminPrincipalObject *PyKAdminObject_get_principal(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    PyKAdminPrincipalObject *principal = NULL;
    char *client_name = NULL;

    if (!PyArg_ParseTuple(args, "s", &client_name)) {
        return NULL;
    }

    if (self->server_handle) {
        principal = PyKAdminPrincipalObject_principal_with_name(self, client_name);

    } 

    return principal;
}

static PyKAdminPolicyObject *PyKAdminObject_get_policy(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    PyKAdminPolicyObject *policy = NULL;
    char *policy_name = NULL;

    if (!PyArg_ParseTuple(args, "s", &policy_name))
        return NULL;

    if (self->server_handle) {
        policy = PyKAdminPolicyObject_policy_with_name(self, policy_name);
    } 

    return policy;
}


static PyKAdminIterator *PyKAdminObject_principal_iter(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    char *match = NULL;
    PyObject *unpack = Py_False; 
    PyKadminIteratorModes mode = iterate_principals;

    static char *kwlist[] = {"match", "unpack", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|zO", kwlist, &match, &unpack))
        return NULL;

    return PyKAdminIterator_create(self, mode, match);
}


static PyKAdminIterator *PyKAdminObject_policy_iter(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    char *match = NULL;
    PyObject *unpack = Py_False; 
    PyKadminIteratorModes mode = iterate_policies;

    static char *kwlist[] = {"match", "unpack", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|zO", kwlist, &match, &unpack))
        return NULL;

    return PyKAdminIterator_create(self, mode, match);
}

static int kdb_iter_princs(void *data, krb5_db_entry *kdb) {

    PyKAdminObject *self = (PyKAdminObject *)data;

    PyObject *result = NULL;
    //PyObject *args   = NULL;

    PyKAdminPrincipalObject *principal = PyKAdminPrincipalObject_principal_with_db_entry(self, kdb);

    if (principal) {

        if (self->each_principal.callback) {

            //args = PyTuple_Pack(2, principal, self->each_principal.data);
            
            //result = PyObject_Call(self->each_principal.callback, args, NULL);
            result = PyObject_CallFunctionObjArgs(self->each_principal.callback, principal, self->each_principal.data, NULL);
            
            //Py_DECREF(args);

            if (!result) {
                // use self to hold exception 
            }

        }
        KAdminPrincipal_destroy(principal);
    }

    return 0;

}



static PyObject *PyKAdminObject_each_principal(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    char *match = NULL;
    krb5_error_code retval = 0; 
    kadm5_ret_t lock = 0; 


    static char *kwlist[] = {"", "data", "match", NULL};
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|Oz", kwlist, /*&PyFunction_Type,*/ &self->each_principal.callback, &self->each_principal.data, &match))
        return NULL;

    if (!self->each_principal.data)
        self->each_principal.data = Py_None;



    Py_XINCREF(self->each_principal.callback);
    Py_XINCREF(self->each_principal.data);
    


    lock = kadm5_lock(self->server_handle);

    if (!lock || (lock == KRB5_PLUGIN_OP_NOTSUPP)) {

        krb5_clear_error_message(self->context);

        retval = krb5_db_iterate(self->context, match, kdb_iter_princs, (void *)self);
    
        if (lock != KRB5_PLUGIN_OP_NOTSUPP) {     
            lock = kadm5_unlock(self->server_handle);
        }
    }

    Py_XDECREF(self->each_principal.callback);
    Py_XDECREF(self->each_principal.data);

    if (retval) {
        // TODO raise proper exception
        return NULL;
    }

    Py_RETURN_TRUE;

}



static void kdb_iter_pols(void *data, osa_policy_ent_rec *entry) {

    PyKAdminObject *self = (PyKAdminObject *)data;

    PyObject *result = NULL;

    PyKAdminPolicyObject *policy = PyKAdminPolicyObject_policy_with_osa_entry(self, entry);

    if (policy) {

        if (self->each_policy.callback) {
            
            result = PyObject_CallFunctionObjArgs(self->each_policy.callback, policy, self->each_policy.data, NULL);
            
            if (!result) {
                // use self to hold exception 
            }

        }
        PyKAdminPolicyObject_destroy(policy);
    }
}


static PyObject *PyKAdminObject_each_policy(PyKAdminObject *self, PyObject *args, PyObject *kwds) {
    
    char *match = NULL;
    krb5_error_code retval = 0; 
    kadm5_ret_t lock = 0; 

    static char *kwlist[] = {"", "data", "match", NULL};
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|Oz", kwlist, &PyFunction_Type, &self->each_policy.callback, &self->each_policy.data, &match))
        return NULL;

    if (!self->each_policy.data)
        self->each_policy.data = Py_None;

    Py_XINCREF(self->each_policy.callback);
    Py_XINCREF(self->each_policy.data);
    
    lock = kadm5_lock(self->server_handle);

    if (!lock || (lock == KRB5_PLUGIN_OP_NOTSUPP)) {

        krb5_clear_error_message(self->context);

        retval = krb5_db_iter_policy(self->context, match, kdb_iter_pols, (void *)self);
    
        if (lock != KRB5_PLUGIN_OP_NOTSUPP) {     
            lock = kadm5_unlock(self->server_handle);
        }
    }

    Py_XDECREF(self->each_policy.callback);
    Py_XDECREF(self->each_policy.data);

    if (retval) {
        // TODO raise proper exception
        return NULL;
    }

    Py_RETURN_TRUE;

}


static PyMethodDef PyKAdminObject_methods[] = {

    {"ank",                 (PyCFunction)PyKAdminObject_create_principal, METH_VARARGS, ""},
    {"addprinc",            (PyCFunction)PyKAdminObject_create_principal, METH_VARARGS, ""},
    {"add_principal",       (PyCFunction)PyKAdminObject_create_principal, METH_VARARGS, ""},

    {"delprinc",            (PyCFunction)PyKAdminObject_delete_principal, METH_VARARGS, ""},
    {"delete_principal",    (PyCFunction)PyKAdminObject_delete_principal, METH_VARARGS, ""},

    // kadmin modify princ, rename princ 

    {"getprinc",            (PyCFunction)PyKAdminObject_get_principal,    METH_VARARGS, ""},
    {"get_principal",       (PyCFunction)PyKAdminObject_get_principal,    METH_VARARGS, ""},


    
    {"getpol",              (PyCFunction)PyKAdminObject_get_policy,       METH_VARARGS, ""},
    {"get_policy",          (PyCFunction)PyKAdminObject_get_policy,       METH_VARARGS, ""},

    {"principals",          (PyCFunction)PyKAdminObject_principal_iter,   (METH_VARARGS | METH_KEYWORDS), ""},
    {"policies",            (PyCFunction)PyKAdminObject_policy_iter,      (METH_VARARGS | METH_KEYWORDS), ""},

    // todo implement
    {"lock",                (PyCFunction)NULL,                            METH_NOARGS, ""},
    {"unlock",              (PyCFunction)NULL,                            METH_NOARGS, ""},

    #ifdef KADMIN_LOCAL
    /*
        due to the nature of how the kadm5clnt library interfaces with the kerberos database over the rpc layer 
            we are unable to (and should not) expose unpacked iteration "each" to the gssapi version of python-kadmin
     */
    {"each_principal",      (PyCFunction)PyKAdminObject_each_principal,   (METH_VARARGS | METH_KEYWORDS), ""},
    {"each_policy",         (PyCFunction)PyKAdminObject_each_policy,      (METH_VARARGS | METH_KEYWORDS), ""},
    #endif

    {NULL, NULL, 0, NULL}
};


PyTypeObject PyKAdminObject_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "kadmin.KAdmin",             /*tp_name*/
    sizeof(PyKAdminObject),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)PyKAdminObject_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "KAdmin objects",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    PyKAdminObject_methods,             /* tp_methods */
    0,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)PyKAdminObject_init,      /* tp_init */
    0,                         /* tp_alloc */
    PyKAdminObject_new,                 /* tp_new */
};



PyKAdminObject *PyKAdminObject_create(void) {
    return (PyKAdminObject *)PyKAdminObject_new(&PyKAdminObject_Type, NULL, NULL);
}

void PyKAdminObject_destroy(PyKAdminObject *self) {
    PyKAdminObject_dealloc(self); 
}

