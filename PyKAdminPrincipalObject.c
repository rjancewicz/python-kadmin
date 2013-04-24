
#include <Python.h>
#include <structmember.h>

#include "PyKAdminObject.h"
#include "PyKAdminPrincipalObject.h"

/*
typedef struct {
    PyObject_HEAD

    PyKAdminObject *kadmin;
    kadm5_principal_ent_t princ;  
} PyKAdminPrincipalObject;
*/

static void KAdminPrincipal_dealloc(PyKAdminPrincipalObject *self) {
    
    printf("KAdminPrincipal_dealloc...\n");
    
    if (self->princ != NULL) {
        kadm5_free_principal_ent(self->kadmin->handle, self->princ);
    }

    Py_XDECREF(self->kadmin);
   
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject *KAdminPrincipal_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {

    PyKAdminPrincipalObject *self;

    self = (PyKAdminPrincipalObject *)type->tp_alloc(type, 0);

    if (self != NULL) {
    } 
    
    return (PyObject *)self;    

}

static int KAdminPrincipal_init(PyKAdminPrincipalObject *self, PyObject *args, PyObject *kwds) {
    return 0;
}



/*
typedef struct _kadm5_principal_ent_t {
    krb5_principal  principal;
    krb5_timestamp  princ_expire_time;
    krb5_timestamp  last_pwd_change;
    krb5_timestamp  pw_expiration;
    krb5_deltat     max_life;
    krb5_principal  mod_name;
    krb5_timestamp  mod_date;
    krb5_flags      attributes;
    krb5_kvno       kvno;
    krb5_kvno       mkvno;
    char            *policy;
    long            aux_attributes;

    // version 2 fields //
    krb5_deltat max_renewable_life;
    krb5_timestamp last_success;
    krb5_timestamp last_failed;
    krb5_kvno fail_auth_count;
    krb5_int16 n_key_data;
    krb5_int16 n_tl_data;
    krb5_tl_data *tl_data;
    krb5_key_data *key_data;
} kadm5_principal_ent_rec, *kadm5_principal_ent_t;
*/

//const int offsetof(PyKAdminPrincipalObject, princ) = offsetof(PyKAdminPrincipalObject, princ);

static PyMemberDef KAdminPrincipal_members[] = {
    {"last_password_change",    T_INT, offsetof(PyKAdminPrincipalObject, princ) + offsetof(kadm5_principal_ent_rec, last_pwd_change),       READONLY, ""},
    {"expire_time",             T_INT, offsetof(PyKAdminPrincipalObject, princ) + offsetof(kadm5_principal_ent_rec, princ_expire_time),     READONLY, ""},
    {"password_expiration",     T_INT, offsetof(PyKAdminPrincipalObject, princ) + offsetof(kadm5_principal_ent_rec, pw_expiration),         READONLY, ""},
    {"modified_time",           T_INT, offsetof(PyKAdminPrincipalObject, princ) + offsetof(kadm5_principal_ent_rec, mod_date),              READONLY, ""},
    {"max_life",                T_INT, offsetof(PyKAdminPrincipalObject, princ) + offsetof(kadm5_principal_ent_rec, max_life),              READONLY, ""},
    
    {"max_renewable_life",      T_INT, offsetof(PyKAdminPrincipalObject, princ) + offsetof(kadm5_principal_ent_rec, max_renewable_life),    READONLY, ""},
    {"last_success",            T_INT, offsetof(PyKAdminPrincipalObject, princ) + offsetof(kadm5_principal_ent_rec, last_success),          READONLY, ""},
    {"last_failed",             T_INT, offsetof(PyKAdminPrincipalObject, princ) + offsetof(kadm5_principal_ent_rec, last_failed),           READONLY, ""},

    {NULL}
};

//PyMemberDef KAdminPrincipal_members = NULL;

static PyMethodDef KAdminPrincipal_methods[] = {
  //  {"get_princ", (PyCFunction)KAdminPrincipal_get_principal, METH_NOARGS, ""},
    {NULL, NULL, 0, NULL}
};


PyTypeObject PyKAdminPrincipalObject_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "kadmin.KAdminPrincipal",             /*tp_name*/
    sizeof(PyKAdminPrincipalObject),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)KAdminPrincipal_dealloc, /*tp_dealloc*/
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
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)KAdminPrincipal_init,      /* tp_init */
    0,                         /* tp_alloc */
    KAdminPrincipal_new,                 /* tp_new */
};



PyKAdminPrincipalObject *PyKAdminPrincipalObject_create(void) {
    return (PyKAdminPrincipalObject *)KAdminPrincipal_new(&PyKAdminPrincipalObject_Type, NULL, NULL);
}

void KAdminPrincipal_destroy(PyKAdminPrincipalObject *self) {
    KAdminPrincipal_dealloc(self);
}

