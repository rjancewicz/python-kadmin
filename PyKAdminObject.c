
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

        Py_TYPE(self)->tp_free((PyObject *)self);
    }
}
    
static PyObject *PyKAdminObject_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {

    PyKAdminObject *self = NULL;
    kadm5_ret_t retval   = KADM5_OK;
    krb5_error_code code = 0;

    self = (PyKAdminObject *)type->tp_alloc(type, 0);

    if (self) {

        retval = kadm5_init_krb5_context(&self->context);
        if (retval != KADM5_OK) { PyKAdmin_RETURN_ERROR(retval, "kadm5_init_krb5_context"); }

        self->server_handle = NULL;

        // attempt to load the default realm 
        code = krb5_get_default_realm(self->context, &self->realm);
        if (code) { PyKAdmin_RETURN_ERROR(code, "krb5_get_default_realm"); }

        self->_storage = PyDict_New();
    }

    return (PyObject *)self;    

}

static int PyKAdminObject_init(PyKAdminObject *self, PyObject *args, PyObject *kwds) {
    return 0;
}


static PyObject *PyKAdminObject_principal_exists(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    kadm5_ret_t retval = KADM5_OK;
    krb5_error_code code = 0;
    krb5_principal princ = NULL;

    char *client_name = NULL;
    PyObject *result = NULL;

    kadm5_principal_ent_rec entry;

    if (!PyArg_ParseTuple(args, "s", &client_name))
        return NULL;

    if (self->server_handle) {

        code = krb5_parse_name(self->context, client_name, &princ);
        if (code) { PyKAdmin_RETURN_ERROR(retval, "krb5_parse_name"); }

        retval = kadm5_get_principal(self->server_handle, princ, &entry, KADM5_PRINCIPAL);
        if (retval == KADM5_OK) { result = Py_True; }
        else if (retval == KADM5_UNK_PRINC) { result = Py_False; }
        else { PyKAdmin_RETURN_ERROR(retval, "kadm5_delete_principal"); }
    }
    
    krb5_free_principal(self->context, princ);
    kadm5_free_principal_ent(self->server_handle, &entry);

    Py_XINCREF(result);
    return result;

}

static PyObject *PyKAdminObject_delete_principal(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    kadm5_ret_t retval = KADM5_OK;
    krb5_error_code code = 0;
    krb5_principal princ = NULL;

    char *client_name = NULL;

    if (!PyArg_ParseTuple(args, "s", &client_name))
        return NULL;

    if (self->server_handle) {

        code = krb5_parse_name(self->context, client_name, &princ);
        if (code) { PyKAdmin_RETURN_ERROR(retval, "krb5_parse_name"); }

        retval = kadm5_delete_principal(self->server_handle, princ);
        if (retval != KADM5_OK) { PyKAdmin_RETURN_ERROR(retval, "kadm5_delete_principal"); }

    }
    
    krb5_free_principal(self->context, princ);

    Py_RETURN_TRUE;

}


static PyObject *PyKAdminObject_create_principal(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    kadm5_ret_t retval   = KADM5_OK;
    krb5_error_code code = 0;
    char *princ_name = NULL;
    char *princ_pass = NULL;
    PyDictObject *db_args = NULL;

    kadm5_principal_ent_rec entry;
    
    memset(&entry, 0, sizeof(entry));
    entry.attributes = 0;

    // todo set default attributes.
    static char *kwlist[] = {"db_args", NULL};

    if (!PyArg_ParseTuple(args, "s|z", &princ_name, &princ_pass))
        return NULL;
    
    if (!PyArg_ParseTupleAndKeywords(PyTuple_New(0), kwds, "|O", kwlist, &db_args))
        return NULL;

    pykadmin_principal_append_db_args(&entry, db_args);

    if (self->server_handle) {

        code = krb5_parse_name(self->context, princ_name, &entry.principal);
        if (code) { PyKAdmin_RETURN_ERROR(retval, "krb5_parse_name"); }

        retval = kadm5_create_principal(self->server_handle, &entry, KADM5_PRINCIPAL | KADM5_TL_DATA, princ_pass); 
        if (retval != KADM5_OK) { PyKAdmin_RETURN_ERROR(retval, "kadm5_create_principal"); }

    }

    kadm5_free_principal_ent(self->server_handle, &entry);

    Py_RETURN_TRUE;
}


static PyKAdminPrincipalObject *PyKAdminObject_get_principal(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    PyKAdminPrincipalObject *principal = NULL;
    char *client_name = NULL;

    if (!PyArg_ParseTuple(args, "s", &client_name))
        return NULL;

    principal = PyKAdminPrincipalObject_principal_with_name(self, client_name);

    

    return principal;
}

static PyKAdminPolicyObject *PyKAdminObject_get_policy(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    PyKAdminPolicyObject *policy = NULL;
    char *policy_name = NULL;

    if (!PyArg_ParseTuple(args, "s", &policy_name))
        return NULL;

    policy = PyKAdminPolicyObject_policy_with_name(self, policy_name);
    
    return policy;
}


static PyKAdminIterator *PyKAdminObject_principal_iter(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    char *match = NULL;

    static char *kwlist[] = {"match", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|z", kwlist, &match))
        return NULL;

    return PyKAdminIterator_principal_iterator(self, match);
}


static PyKAdminIterator *PyKAdminObject_policy_iter(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    char *match = NULL;

    static char *kwlist[] = {"match", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|z", kwlist, &match))
        return NULL;

    return PyKAdminIterator_policy_iterator(self, match);
}


#ifdef KADMIN_LOCAL

static void _pykadmin_each_encapsulate_error(PyObject **store) {

    PyObject *ptype      = NULL;
    PyObject *pvalue     = NULL;
    PyObject *ptraceback = NULL;

    if (PyErr_Occurred()) {
        PyErr_Fetch(&ptype, &pvalue, &ptraceback);
        *store = PyTuple_Pack(3, ptype, pvalue, ptraceback);
    } else {
        *store = PyExc_RuntimeError;
    }
}

static void _pykadmin_each_restore_error(PyObject *store) {
    
    if (PyTuple_CheckExact(store)) {

        PyObject *ptype      = PyTuple_GetItem(store, 0);
        PyObject *pvalue     = PyTuple_GetItem(store, 1);
        PyObject *ptraceback = PyTuple_GetItem(store, 2);

        PyErr_Restore(ptype, pvalue, ptraceback);
        Py_DECREF(store);

    } else {

        PyErr_SetString(PyExc_RuntimeError, "Internal Fatal Iteration Exception");
    }
}


static int kdb_iter_princs(void *data, krb5_db_entry *kdb) {

    PyKAdminObject *self = (PyKAdminObject *)data;

    PyKAdminPrincipalObject *principal = NULL;
    PyObject *result = NULL;

    if (!self->each_principal.error) {

        principal = PyKAdminPrincipalObject_principal_with_db_entry(self, kdb);

        if (principal) {

            if (self->each_principal.callback) {

                result = PyObject_CallFunctionObjArgs(self->each_principal.callback, principal, self->each_principal.data, NULL);            
                if (!result) { _pykadmin_each_encapsulate_error(&self->each_principal.error); }
            }
            
            Py_DECREF(principal);
        }
    }

    return 0;

}



static PyObject *PyKAdminObject_each_principal(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    char *match = NULL;
    krb5_error_code code = 0; 
    kadm5_ret_t lock = KADM5_OK; 

    static char *kwlist[] = {"callback", "data", "match", NULL};
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|Oz", kwlist, &PyFunction_Type, &self->each_principal.callback, &self->each_principal.data, &match))
        return NULL;

    if (!self->each_principal.data)
        self->each_principal.data = Py_None;

    self->each_principal.error = NULL;

    Py_INCREF(self->each_principal.callback);
    Py_INCREF(self->each_principal.data);
    
    lock = kadm5_lock(self->server_handle);

    if ((lock == KADM5_OK) || (lock == KRB5_PLUGIN_OP_NOTSUPP)) {

        krb5_clear_error_message(self->context);

        code = krb5_db_iterate(self->context, match, kdb_iter_princs, (void *)self);
    
        if (lock != KRB5_PLUGIN_OP_NOTSUPP)   
            lock = kadm5_unlock(self->server_handle);
    }

    Py_DECREF(self->each_principal.callback);
    Py_DECREF(self->each_principal.data);

    if (code) { PyKAdmin_RETURN_ERROR(code, "krb5_db_iterate"); }

    if (self->each_principal.error) {
        _pykadmin_each_restore_error(self->each_principal.error);
        return NULL;
    }


    Py_RETURN_TRUE;

}



static void kdb_iter_pols(void *data, osa_policy_ent_rec *entry) {

    PyKAdminObject *self = (PyKAdminObject *)data;
    PyKAdminPolicyObject *policy = NULL;
    PyObject *result = NULL;

    if (!self->each_policy.error) {

        policy = PyKAdminPolicyObject_policy_with_osa_entry(self, entry);

        if (policy) {

            if (self->each_policy.callback) {
                
                result = PyObject_CallFunctionObjArgs(self->each_policy.callback, policy, self->each_policy.data, NULL);
                if (!result) { _pykadmin_each_encapsulate_error(&self->each_policy.error); }

            }
            
            Py_DECREF(policy);
        }
    }   
}


static PyObject *PyKAdminObject_each_policy(PyKAdminObject *self, PyObject *args, PyObject *kwds) {
    
    char *match = NULL;
    krb5_error_code code = 0; 
    kadm5_ret_t lock = KADM5_OK; 

    static char *kwlist[] = {"", "data", "match", NULL};
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|Oz", kwlist, &PyFunction_Type, &self->each_policy.callback, &self->each_policy.data, &match))
        return NULL;

    if (!self->each_policy.data)
        self->each_policy.data = Py_None;

    Py_INCREF(self->each_policy.callback);
    Py_INCREF(self->each_policy.data);
    
    lock = kadm5_lock(self->server_handle);

    if ((lock == KADM5_OK) || (lock == KRB5_PLUGIN_OP_NOTSUPP)) {

        krb5_clear_error_message(self->context);

        code = krb5_db_iter_policy(self->context, match, kdb_iter_pols, (void *)self);
    
        if (lock != KRB5_PLUGIN_OP_NOTSUPP)
            lock = kadm5_unlock(self->server_handle);
    }

    Py_DECREF(self->each_policy.callback);
    Py_DECREF(self->each_policy.data);

    if (code) { PyKAdmin_RETURN_ERROR(code, "krb5_db_iter_policy"); }

    if (self->each_policy.error) {
        _pykadmin_each_restore_error(self->each_policy.error);
        return NULL;
    }

    Py_RETURN_TRUE;

}
#endif

static PyMethodDef PyKAdminObject_methods[] = {

    {"ank",                 (PyCFunction)PyKAdminObject_create_principal, (METH_VARARGS | METH_KEYWORDS), ""},
    {"addprinc",            (PyCFunction)PyKAdminObject_create_principal, (METH_VARARGS | METH_KEYWORDS), ""},
    {"add_principal",       (PyCFunction)PyKAdminObject_create_principal, (METH_VARARGS | METH_KEYWORDS), ""},

    {"delprinc",            (PyCFunction)PyKAdminObject_delete_principal, METH_VARARGS, ""},
    {"delete_principal",    (PyCFunction)PyKAdminObject_delete_principal, METH_VARARGS, ""},

    {"principal_exists",    (PyCFunction)PyKAdminObject_principal_exists, METH_VARARGS, ""},

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

#   ifdef KADMIN_LOCAL
    /*
        due to the nature of how the kadm5clnt library interfaces with the kerberos database over the rpc layer 
            we are unable to (and should not) expose unpacked iteration "each" to the gssapi version of python-kadmin
     */
    {"each_principal",      (PyCFunction)PyKAdminObject_each_principal,   (METH_VARARGS | METH_KEYWORDS), ""},
    {"each_policy",         (PyCFunction)PyKAdminObject_each_policy,      (METH_VARARGS | METH_KEYWORDS), ""},
#   endif

    {NULL, NULL, 0, NULL}
};


PyTypeObject PyKAdminObject_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    //PyObject_HEAD_INIT(NULL)
    //0,                         /*ob_size*/
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

