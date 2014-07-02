
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
} PyKAdminPrincipalObject;

PyTypeObject PyKAdminPrincipalObject_Type;

PyKAdminPrincipalObject *PyKAdminPrincipalObject_create(PyKAdminObject *kadmin, char *client_name);
void KAdminPrincipal_destroy(PyKAdminPrincipalObject *self); 

#endif