
#include "PyKAdminObject.h"
#include "PyKAdminErrors.h"
#include "PyKAdminIterator.h"
#include "PyKAdminPrincipalObject.h"
#include "PyKAdminPolicyObject.h"

static void PyKAdminPolicyObject_dealloc(PyKAdminPolicyObject *self) {
    
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject *PyKAdminPolicyObject_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {

    PyKAdminPolicyObject *self;

    self = (PyKAdminPolicyObject *)type->tp_alloc(type, 0);

    if (self) {
        
    }

    return (PyObject *)self;    

}

static int PyKAdminPolicyObject_init(PyKAdminPolicyObject *self, PyObject *args, PyObject *kwds) {
    return 0;
}


static PyMethodDef PyKAdminPolicyObject_methods[] = {
    {NULL, NULL, 0, NULL}
};

PyTypeObject PyKAdminPolicyObject_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "kadmin.KAdminPolicy",             /*tp_name*/
    sizeof(PyKAdminPolicyObject),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)PyKAdminPolicyObject_dealloc, /*tp_dealloc*/
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
    PyKAdminPolicyObject_methods,             /* tp_methods */
    0,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)PyKAdminPolicyObject_init,      /* tp_init */
    0,                         /* tp_alloc */
    PyKAdminPolicyObject_new,                 /* tp_new */
};



PyKAdminPolicyObject *PyKAdminPolicyObject_create(PyKAdminObject *kadmin, char *name) {


    PyKAdminPolicyObject *policy = NULL; 

    policy = (PyKAdminPolicyObject *)PyKAdminPolicyObject_new(&PyKAdminPolicyObject_Type, NULL, NULL);
    
    if (policy) {
        Py_XINCREF(kadmin);
        policy->kadmin = kadmin;
    }

    //_KAdminPolicy_load_principal(policy, client_name);

    return policy;
}

void PyKAdminPolicyObject_destroy(PyKAdminPolicyObject *self) {
    PyKAdminPolicyObject_dealloc(self); 
}

