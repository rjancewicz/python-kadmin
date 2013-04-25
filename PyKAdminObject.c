
#include "PyKAdminObject.h"
#include "PyKAdminPrincipalObject.h"

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

    printf("PyKAdminObject_dealloc...\n");

    if (self->handle != NULL) {
        if ( (retval = kadm5_destroy(self->handle)) ) {
            // TODO handle error
        }
    }
    
    if (self->context != NULL) {
        krb5_free_context(self->context);
    }

    if (self->realm != NULL) {
        free(self->realm);
    }

    self->ob_type->tp_free((PyObject*)self);
}

static PyObject *PyKAdminObject_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {

    PyKAdminObject *self;
    kadm5_ret_t retval;

    self = (PyKAdminObject *)type->tp_alloc(type, 0);

    if (self != NULL) {
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

static PyObject *PyKAdminObject_moo(PyKAdminObject *self) {
    
    return Py_BuildValue("s", "Moooooooooooo");

}

static PyKAdminPrincipalObject *PyKAdminObject_get_principal(PyKAdminObject *self, PyObject *args, PyObject *kwds) {

    PyKAdminPrincipalObject *princ = NULL;
    kadm5_ret_t retval;
    krb5_error_code errno; 
    char *client_name; 
    krb5_principal principal;

    if (!PyArg_ParseTuple(args, "s", &client_name))
        return NULL;

    /*
        kadm5_ret_t    kadm5_get_principal(void *server_handle,
                                   krb5_principal principal,
                                   kadm5_principal_ent_t ent,
                                   long mask);
    */

    if (self->handle) {

        princ = PyKAdminPrincipalObject_create();
        princ->kadmin = self;
        Py_XINCREF(self);

        
        if ( (errno = krb5_parse_name(self->context, client_name, &principal)) ) {
            printf("Failed to parse princ name %d\n", errno);
        }
    

        if ( (retval = kadm5_get_principal(self->handle, principal, &princ->entry, KADM5_PRINCIPAL_NORMAL_MASK)) ) {
            // TODO Handle Error More Cleanly (ie throw an exception in addition to the dealloc)
            printf("Failed to fetch princ name %d\n", retval);
            KAdminPrincipal_destroy(princ);
            princ = NULL;
        }

        Py_XINCREF(princ);
    } 

    return princ;
}


static PyMethodDef PyKAdminObject_methods[] = {
    {"moo", (PyCFunction)PyKAdminObject_moo, METH_VARARGS, "moo"},
    {"get_princ", (PyCFunction)PyKAdminObject_get_principal, METH_VARARGS, ""},
    {"get_principal", (PyCFunction)PyKAdminObject_get_principal, METH_VARARGS, ""},
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

