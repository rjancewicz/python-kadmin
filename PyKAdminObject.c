
#include "PyKAdminObject.h"
#include "PyKAdminErrors.h"
#include "PyKAdminIterator.h"
#include "PyKAdminPrincipalObject.h"
#include "PyKAdminPolicyObject.h"

#include "PyKAdminCommon.h"

#define IS_NULL(ptr) (ptr == NULL)

static void PyKAdminObject_dealloc(PyKAdminObject *self) {
    
    kadm5_ret_t retval;

    if (!IS_NULL(self->server_handle)) {
        retval = kadm5_destroy(self->server_handle);
        if (retval) {}
    }
    
    if (!IS_NULL(self->context)) {
        krb5_free_context(self->context);
    }

    if (!IS_NULL(self->realm)) {
        free(self->realm);
    }

    self->ob_type->tp_free((PyObject*)self);
}

static PyObject *PyKAdminObject_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {

    PyKAdminObject *self;
    kadm5_ret_t retval = 0;

    self = (PyKAdminObject *)type->tp_alloc(type, 0);

    if (self) {
        retval = krb5_init_context(&self->context);

        if (retval) {
            Py_DECREF(self);
            PyKAdmin_RaiseKAdminError(retval, "kadm5_init_with_password");
            return NULL;
        }

        // attempt to load the default realm for this connection
        krb5_get_default_realm(self->context, &self->realm);
        if (!self->realm) {
            // todo : fail 
        }
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

    if (!IS_NULL(self->server_handle)) {

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
    char *client_name; 

    if (!PyArg_ParseTuple(args, "s", &client_name)) {
        return NULL;
    }

    if (!IS_NULL(self->server_handle)) {
        principal = PyKAdminPrincipalObject_create(self, client_name);

    } 

    return principal;
}


static PyKAdminIterator *PyKAdminObject_principal_iter(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    char *match = NULL;
    PyObject *unpack = Py_False; 
    PyKadminIteratorModes mode = iterate_principals;

    static char *kwlist[] = {"match", "unpack", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|zO", kwlist, &match, &unpack))
        return NULL;

    if (PyObject_IsTrue(unpack))
        mode |= iterate_unpack;

    return PyKAdminIterator_create(self, mode, match);
}

static PyKAdminIterator *PyKAdminObject_policy_iter(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    char *match = NULL;
    PyObject *unpack = Py_False; 
    PyKadminIteratorModes mode = iterate_policies;

    static char *kwlist[] = {"match", "unpack", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|zO", kwlist, &match, &unpack))
        return NULL;

    if (PyObject_IsTrue(unpack))
        mode |= iterate_unpack;

    return PyKAdminIterator_create(self, mode, match);
}

/*
static krb5_error_code
kdb_iter_func(krb5_pointer data, krb5_db_entry *kdb)
{
    iter_data *id = (iter_data *) data;

    (*(id->func))(id->data, kdb->princ);

    return(0);
}

krb5_error_code
kdb_iter_entry(kadm5_server_handle_t handle, char *match_entry,
               void (*iter_fct)(void *, krb5_principal), void *data)
{
    iter_data id;
    krb5_error_code ret;

    id.func = iter_fct;
    id.data = data;

    ret = krb5_db_iterate(handle->context, match_entry, kdb_iter_func, &id);
    if (ret)
        return(ret);

    return(0);
}
*/

static krb5_error_code kdb_iter_func(void *data, krb5_db_entry *kdb) {

    PyKAdminObject *self = (PyKAdminObject *)data;

    //char *name = NULL;
    PyObject *result = NULL;

    if (krb5_unparse_name(self->context, kdb->princ, &name) != 0)
        return 1;

    //PyKAdminPrincipalObject *principal = PyKAdminPrincipalObject_create(self, NULL);

    //kadm5_principal_ent_rec *entry = malloc(sizeof(kadm5_principal_ent_rec));


        //PyKadmin_kadm_entry_from_kdb_entry(self, kdb, entry, KADM5_PRINCIPAL_NORMAL_MASK);

        //memcpy(&principal->entry, entry, sizeof(kadm5_principal_ent_rec));

        //PyObject *args = Py_BuildValue("(O)", principal);

        //principal->entry.principal = kdb->princ;

        PyObject *args = Py_BuildValue("(s)", name);

        if (self->each_callback) {
            //result = PyObject_CallFunctionObjArgs(self->each_callback, principal, NULL);
            result = PyObject_CallObject(self->each_callback, args);
            Py_XDECREF(args);
            if (!result) {
                printf("callback failed\n");
            }
        }
    
    //KAdminPrincipal_destroy(principal);
//
    //printf("%s\n", name);

    return 0;

}


static PyObject *PyKAdminObject_each_principal(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    krb5_error_code ret = 0; 

    if (!PyArg_ParseTuple(args, "O!", &PyFunction_Type, &self->each_callback))
        return NULL;

    // we need to hold the refernce to the object while we plan on using it
    Py_XINCREF(self->each_callback);
    // TODO kdb5_lock(excusive)
    ret = krb5_db_iterate(self->context, NULL, kdb_iter_func, self);
    // TODO kdb5_unlock
    Py_XDECREF(self->each_callback);

    if (ret)
        return NULL;

    Py_RETURN_TRUE;

}

static PyObject *PyKAdminObject_each_policy(PyKAdminObject *self, PyObject *args, PyObject *kwds) {
    // todo
    return NULL;
}


static PyKAdminPrincipalObject *PyKAdminObject_list_principals(PyKAdminObject *self, PyObject *args, PyObject *kwds) {
    return NULL;
}


static PyMethodDef PyKAdminObject_methods[] = {
    {"getprinc",            (PyCFunction)PyKAdminObject_get_principal,    METH_VARARGS, ""},
    {"get_principal",       (PyCFunction)PyKAdminObject_get_principal,    METH_VARARGS, ""},

    {"delprinc",            (PyCFunction)PyKAdminObject_delete_principal, METH_VARARGS, ""},
    {"delete_principal",    (PyCFunction)PyKAdminObject_delete_principal, METH_VARARGS, ""},

    {"ank",                 (PyCFunction)PyKAdminObject_create_principal, METH_VARARGS, ""},
    {"create_princ",        (PyCFunction)PyKAdminObject_create_principal, METH_VARARGS, ""},
    {"create_principal",    (PyCFunction)PyKAdminObject_create_principal, METH_VARARGS, ""},
    {"list_principals",     (PyCFunction)PyKAdminObject_list_principals,  METH_VARARGS, ""},
    {"principals",          (PyCFunction)PyKAdminObject_principal_iter,   (METH_VARARGS | METH_KEYWORDS), ""},
    {"policies",            (PyCFunction)PyKAdminObject_policy_iter,      (METH_VARARGS | METH_KEYWORDS), ""},
    
    {"each_principal",      (PyCFunction)PyKAdminObject_each_principal,   METH_VARARGS, ""},
    {"each_policy",         (PyCFunction)PyKAdminObject_each_policy,      METH_VARARGS, ""},

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

