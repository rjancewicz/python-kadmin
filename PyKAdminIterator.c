
#include "PyKAdminObject.h"
#include "PyKAdminIterator.h"
#include "PyKAdminPrincipalObject.h"
#include "PyKAdminPolicyObject.h"
#include "PyKAdminErrors.h"

static void PyKAdminIterator_dealloc(PyKAdminIterator *self) {
      
    kadm5_free_name_list(self->kadmin->server_handle, self->names, self->count);
    Py_DECREF(self->kadmin);

    Py_TYPE(self)->tp_free((PyObject *)self);
}


static int PyKAdminIterator_init(PyKAdminIterator *self, PyObject *args, PyObject *kwds) {
    return 0;
}

static PyObject *PyKAdminIterator_next(PyKAdminIterator *self) {
    
    char *name = NULL;
    PyObject *next = NULL;

    if (self->index < self->count) {

        name = self->names[self->index];
        next = PyUnicode_FromString(name);

        self->index++;
    }

    return next;
}

PyTypeObject PyKAdminIterator_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    //PyObject_HEAD_INIT(NULL)
    //0,                         /*ob_size*/
    "kadmin.PrincipalIterator",             /*tp_name*/
    sizeof(PyKAdminIterator),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)PyKAdminIterator_dealloc, /*tp_dealloc*/
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
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER, /*tp_flags*/
    "KAdmin Principal Iterator",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    PyObject_SelfIter,     /* tp_iter */
    (iternextfunc)PyKAdminIterator_next,                     /* tp_iternext */
    0,             /* tp_methods */
    0,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0, //(initproc)PyKAdminIterator_init,      /* tp_init */
    0,                         /* tp_alloc */
    0, //PyKAdminIterator_new,                 /* tp_new */
};


PyKAdminIterator *PyKAdminIterator_principal_iterator(PyKAdminObject *kadmin, char *match) {

    kadm5_ret_t retval = KADM5_OK;
    PyKAdminIterator *iter = PyObject_New(PyKAdminIterator, &PyKAdminIterator_Type);

    if (iter) {

        iter->count = 0x0; 
        iter->index = 0x0;

        iter->kadmin = kadmin;
        Py_INCREF(kadmin);

        retval = kadm5_get_principals(kadmin->server_handle, match, &iter->names, &iter->count);
        if (retval != KADM5_OK) { 
            PyKAdminError_raise_error(retval, "kadm5_get_principals");
        }
    }

    return iter;
}


PyKAdminIterator *PyKAdminIterator_policy_iterator(PyKAdminObject *kadmin, char *match) {

    kadm5_ret_t retval = KADM5_OK;
    PyKAdminIterator *iter = PyObject_New(PyKAdminIterator, &PyKAdminIterator_Type);

    if (iter) {

        iter->count = 0x0; 
        iter->index = 0x0;

        iter->kadmin = kadmin;
        Py_INCREF(kadmin);

        retval = kadm5_get_policies(kadmin->server_handle, match, &iter->names, &iter->count);
        if (retval != KADM5_OK) { 
            PyKAdminError_raise_error(retval, "kadm5_get_policies"); 
        }
    }

    return iter;
}

