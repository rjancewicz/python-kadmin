
#ifndef PYKADMINITERATOROBJECT_H
#define PYKADMINITERATOROBJECT_H

#include <Python.h>
#include <kadm5/admin.h>
#include <krb5/krb5.h>
#include <stdio.h>
#include <string.h>
#include <structmember.h>

typedef struct {
    PyObject_HEAD
	
	Py_ssize_t index;

	int count; 
	char **names;
	
	PyKAdminObject *kadmin;

} PyKAdminIterator;

extern PyTypeObject PyKAdminIterator_Type;

PyKAdminIterator *PyKAdminIterator_principal_iterator(PyKAdminObject *kadmin, char *match);
PyKAdminIterator *PyKAdminIterator_policy_iterator(PyKAdminObject *kadmin, char *match);

//PyKAdminIterator *PyKAdminIterator_create(PyKAdminObject *kadmin, PyKadminIteratorModes mode, char *filter);

#endif