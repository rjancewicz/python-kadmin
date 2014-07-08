
#include "PyKAdminObject.h"
#include "PyKAdminErrors.h"
#include "PyKAdminIterator.h"
#include "PyKAdminPrincipalObject.h"

#include "PyKAdminPolicyObject.h"

static void PyKAdminPolicyObject_dealloc(PyKAdminPolicyObject *self) {
    
    if (self) {
        kadm5_free_policy_ent(self->kadmin->server_handle, &self->entry);  

        Py_XDECREF(self->kadmin);

        PyObject_Del((PyObject*)self);

        //self->ob_type->tp_free((PyObject*)self);
    }
}

static PyObject *PyKAdminPolicyObject_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {

    PyKAdminPolicyObject *self;

    self = (PyKAdminPolicyObject *)type->tp_alloc(type, 0);

    if (!self)
        return NULL;

    memset(&self->entry, 0, sizeof(kadm5_policy_ent_rec));

    return (PyObject *)self;    

}

static kadm5_ret_t _PyKAdminPolicyObject_load(PyKAdminPolicyObject *self, char *policy_name) {

    kadm5_ret_t retval = 0;

    retval = kadm5_get_policy(self->kadmin->server_handle, policy_name, &self->entry);

    return retval;
}



static int PyKAdminPolicyObject_init(PyKAdminPolicyObject *self, PyObject *args, PyObject *kwds) {
    return 0;
}


static PyMethodDef PyKAdminPolicyObject_methods[] = {
    {NULL, NULL, 0, NULL}
};

/*
Policy: test_policy
Maximum password life: 0
Minimum password life: 864000
Minimum password length: 1
Minimum number of password character classes: 1
Number of old keys kept: 1
Reference count: 0
Maximum password failures before lockout: 10
Password failure count reset interval: 0 days 00:00:00
Password lockout duration: 0 days 00:00:00
*/

static int KAdminPolicyObject_print(PyKAdminPolicyObject *self, FILE *file, int flags){
    // TODO
    
    return 0;
}


PyObject *PyKAdminPolicy_RichCompare(PyObject *o1, PyObject *o2, int opid) {

    PyKAdminPolicyObject *a = (PyKAdminPolicyObject *)o1;
    PyKAdminPolicyObject *b = (PyKAdminPolicyObject *)o2;

    PyObject *result = NULL; 
        
    int equal = pykadmin_policy_ent_rec_compare(a->kadmin->context, &a->entry, &b->entry);

    switch (opid) {

        case Py_EQ:
            result = ((a == b) || equal) ? Py_True : Py_False;
            break;
        case Py_NE:
            result = ((a != b) && !equal) ? Py_True : Py_False;
            break;
        case Py_LT:
        case Py_LE:
        case Py_GT:
        case Py_GE:
        default: 
            result = Py_NotImplemented;
    }

    Py_XINCREF(result);
    return result;
}

PyTypeObject PyKAdminPolicyObject_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
//    0,                         /*ob_size*/
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
    "Python KAdmin Policy Object",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    PyKAdminPolicy_RichCompare,                     /* tp_richcompare */
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
    PyType_GenericAlloc,                         /* tp_alloc */
    PyKAdminPolicyObject_new,                 /* tp_new */
};

PyKAdminPolicyObject *PyKAdminPolicyObject_policy_with_name(PyKAdminObject *kadmin, char *name) {

    kadm5_ret_t retval = 0;
    PyKAdminPolicyObject *policy = NULL; 

    policy = (PyKAdminPolicyObject *)PyKAdminPolicyObject_new(&PyKAdminPolicyObject_Type, NULL, NULL);
    
    if (policy) {
        Py_XINCREF(kadmin);
        policy->kadmin = kadmin;

        retval = _PyKAdminPolicyObject_load(policy, name);

        if (retval) {
            PyKAdminPolicyObject_dealloc(policy);
        }

    }

    return policy;
}


PyKAdminPolicyObject *PyKAdminPolicyObject_policy_with_osa_entry(PyKAdminObject *kadmin, osa_policy_ent_rec *entry) {
    
    PyKAdminPolicyObject *policy = NULL; 

    krb5_error_code retval = 0;

    policy = (PyKAdminPolicyObject *)PyKAdminPolicyObject_new(&PyKAdminPolicyObject_Type, NULL, NULL);
    
    if (policy) {
        Py_XINCREF(kadmin);
        policy->kadmin = kadmin;

        retval = pykadmin_policy_kadm_from_osa(kadmin->context, entry, &policy->entry, 0);

        if (retval) {
            // this will never happen for while the above is called.
        }
    }

    return policy;
}



void PyKAdminPolicyObject_destroy(PyKAdminPolicyObject *self) {
    PyKAdminPolicyObject_dealloc(self); 
}

