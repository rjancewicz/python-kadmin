
#include <Python.h>
#include <kadm5/admin.h>
#include <krb5/krb5.h>
#include <stdio.h>
#include <string.h>
#include <structmember.h>

typedef enum {
	iterate_principals 	= 0x1,
	iterate_policies	= 0x2,
	iterate_unpack		= 0x4
} PyKadminIteratorModes;

typedef struct {
    PyObject_HEAD
	
	//Py_ssize_t count;
	Py_ssize_t index;
	PyKadminIteratorModes mode;

	int count; 
	char *match;
	char **names;
	
	PyKAdminObject *kadmin;

} PyKAdminIterator;

PyTypeObject PyKAdminIterator_Type;

PyKAdminIterator *PyKAdminIterator_create(PyKAdminObject *kadmin, PyKadminIteratorModes mode, char *filter);
void PyKAdminIterator_destroy(PyKAdminIterator *self);
