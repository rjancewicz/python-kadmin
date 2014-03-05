
#include "PyKAdminObject.h"
#include "PyKAdminPrincipalObject.h"
#include "PyKAdminErrors.h"

#define IS_NULL(ptr) (ptr == NULL)

/*
typedef struct {
    PyObject_HEAD
    
    krb5_context context; 
    void *handle;
    char *realm;
} PyKAdminObject;
*/

static void PyKAdminObject_dealloc(PyKAdminObject *self) {
    
    kadm5_ret_t retval;

    if (!IS_NULL(self->handle)) {
        retval = kadm5_destroy(self->handle);
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
    kadm5_ret_t retval;

    self = (PyKAdminObject *)type->tp_alloc(type, 0);

    if (!IS_NULL(self)) {
        if ( (retval = krb5_init_context(&(self->context))) ) {
            Py_DECREF(self);
            return NULL;
        }
    }

    return (PyObject *)self;    

}

static int PyKAdminObject_init(PyKAdminObject *self, PyObject *args, PyObject *kwds) {
    return 0;
}

/*static krb5_error_code create_princ(void *handle, kadm5_principal_ent_rec *princ, long mask, int n_ks, krb5_key_salt_tuple *ks, char *pass) {

    if (ks)
        return kadm5_create_principal_3(handle, princ, mask, n_ks, ks, pass);
    else
        return kadm5_create_principal(handle, princ, mask, pass);

}*/


static PyObject *PyKAdminObject_create_principal(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    //PyObject *result = NULL;

    kadm5_ret_t retval;
    krb5_error_code errno;

    char *princ_name = NULL;
    char *princ_pass = NULL;

    kadm5_principal_ent_rec entry;
    
    memset(&entry, 0, sizeof(entry));
    entry.attributes = 0;
    
    if (!PyArg_ParseTuple(args, "sz", &princ_name, &princ_pass))
        return NULL;

    if (self->handle) {

        if ( (errno = krb5_parse_name(self->context, princ_name, &entry.principal) ) ) {

            printf("Error: krb5_unparse_name [%d]\n", errno);
            return NULL; 
        
        } else {

            retval = kadm5_create_principal(self->handle, &entry, KADM5_PRINCIPAL, NULL); 
            
            if (retval)
                return PyKAdminError_raise_kadmin_error(retval, "kadm5_create_principal");
        }
    }

    kadm5_free_principal_ent(self->handle, &entry);

    Py_RETURN_TRUE;
}


static PyKAdminPrincipalObject *PyKAdminObject_get_principal(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    PyKAdminPrincipalObject *princ = NULL;
    kadm5_ret_t retval;
    krb5_error_code errno; 
    char *client_name; 
    krb5_principal principal;

    if (!PyArg_ParseTuple(args, "s", &client_name))
        return NULL;

    if (self->handle) {

        princ = PyKAdminPrincipalObject_create();
        princ->kadmin = self;
        Py_XINCREF(self);
        
        errno = krb5_parse_name(self->context, client_name, &principal);
        if (errno) {
            printf("Failed to parse princ name %d\n", errno);
        }
    
        if ( (retval = kadm5_get_principal(self->handle, principal, &princ->entry, KADM5_PRINCIPAL_NORMAL_MASK)) ) {
            KAdminPrincipal_destroy(princ);
            krb5_free_principal(self->context, principal);

            return (PyKAdminPrincipalObject *)PyKAdminError_raise_kadmin_error(retval, "kadm5_get_principal");
        }

        krb5_free_principal(self->context, principal);

        // Py_XINCREF(princ);
    } 

    return princ;
}


static PyMethodDef PyKAdminObject_methods[] = {
    {"get_princ",           (PyCFunction)PyKAdminObject_get_principal,    METH_VARARGS, ""},
    {"get_principal",       (PyCFunction)PyKAdminObject_get_principal,    METH_VARARGS, ""},
    {"ank",                 (PyCFunction)PyKAdminObject_create_principal, METH_VARARGS, ""},
    {"create_princ",        (PyCFunction)PyKAdminObject_create_principal, METH_VARARGS, ""},
    {"create_principal",    (PyCFunction)PyKAdminObject_create_principal, METH_VARARGS, ""},
    {"list_principals",     (PyCFunction)PyKAdminObject_create_principal, METH_VARARGS, ""},
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

