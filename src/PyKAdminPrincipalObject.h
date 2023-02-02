
#ifndef PYKADMINPRINCIPALOBJECT_H
#define PYKADMINPRINCIPALOBJECT_H

#include <Python.h>

#include <kadm5/admin.h>
#include <krb5/krb5.h>
#include <stdio.h>
#include <string.h>
#include <structmember.h>

extern time_t get_date(char *);

typedef struct {
    PyObject_HEAD
    PyKAdminObject *kadmin;
    kadm5_principal_ent_rec entry;

    unsigned int mask; 

} PyKAdminPrincipalObject;

extern PyTypeObject PyKAdminPrincipalObject_Type;

//#define PyKAdminPrincipalObject_Check(principal) PyObject_TypeCheck(principal, &PyKAdminPrincipalObject_Type)
#define PyKAdminPrincipalObject_CheckExact(obj) (Py_TYPE(obj) == &PyKAdminPrincipalObject_Type)

PyKAdminPrincipalObject *PyKAdminPrincipalObject_principal_with_name(PyKAdminObject *kadmin, char *client_name);
PyKAdminPrincipalObject *PyKAdminPrincipalObject_principal_with_db_entry(PyKAdminObject *kadmin, krb5_db_entry *kdb);
PyKAdminPrincipalObject *PyKAdminPrincipalObject_principal_with_kadm_entry(PyKAdminObject *kadmin, kadm5_principal_ent_rec *entry);


void PyKAdminPrincipalObject_destroy(PyKAdminPrincipalObject *self); 


#endif