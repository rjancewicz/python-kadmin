
#include "PyKAdminObject.h"
#include "PyKAdminIterator.h"
#include "PyKAdminPrincipalObject.h"
#include "PyKAdminPolicyObject.h"
#include "PyKAdminErrors.h"

static void PyKAdminIterator_dealloc(PyKAdminIterator *self) {
      
    kadm5_free_name_list(self->kadmin->server_handle, self->names, self->count);
    Py_XDECREF(self->kadmin);

    self->ob_type->tp_free((PyObject*)self);
}


static int PyKAdminIterator_init(PyKAdminIterator *self, PyObject *args, PyObject *kwds) {
        
    self->count = 0x0; 
    self->index = 0x0;

    if (self->kadmin->server_handle) {

        if (self->mode & iterate_principals) {  
            kadm5_get_principals(self->kadmin->server_handle, self->match, &self->names, &self->count);
        } else if (self->mode & iterate_policies) {
            kadm5_get_policies(self->kadmin->server_handle, self->match, &self->names, &self->count);
        }
    }


    return 0;
}

static PyObject *PyKAdminIterator_next(PyKAdminIterator *self) {
    
    PyObject *next = NULL;

    if (self->index < self->count) {

        char *name = self->names[self->index];

        if (self->mode & iterate_unpack) {
            if (self->mode & iterate_principals) {
                next = (PyObject *)PyKAdminPrincipalObject_create(self->kadmin, name);
            } else if (self->mode & iterate_policies) {
                next = (PyObject *)PyKAdminPolicyObject_create(self->kadmin, name);
                // todo need policy constructor
                //next = PyKAdminPrincipalObject_create(self->kadmin, name);
                // for the time we will use a name string as a placeholder so NULL isn't returned
                next = Py_BuildValue("s", name);
            } else {
                next = Py_BuildValue("s", name);
            }
        } else {
            next = Py_BuildValue("s", name);
        }

        self->index++;
    }

    return next;
}

PyTypeObject PyKAdminIterator_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
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



PyKAdminIterator *PyKAdminIterator_create(PyKAdminObject *kadmin, PyKadminIteratorModes mode, char *match) {

    PyKAdminIterator *iter = PyObject_New(PyKAdminIterator, &PyKAdminIterator_Type);

    if (iter) {
        Py_XINCREF(kadmin);
        iter->kadmin = kadmin;
        iter->mode   = mode;
        iter->match  = match;
    }

    PyKAdminIterator_init(iter, NULL, NULL);
    Py_XINCREF(iter);

    return iter;
}

void PyKAdminIterator_destroy(PyKAdminIterator *self) {
    PyKAdminIterator_dealloc(self);
}

