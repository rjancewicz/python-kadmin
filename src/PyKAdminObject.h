
#ifndef PYKADMINOBJECT_H
#define PYKADMINOBJECT_H

#include <Python.h>
#include <kadm5/admin.h>
#include <krb5/krb5.h>
#include <stdio.h>
#include <string.h>
#include <structmember.h>

typedef struct {
	PyObject *callback;
	PyObject *data;
    PyObject *error;
} each_iteration_t; 

typedef struct {
    PyObject_HEAD
    
    uint8_t locked; 

    krb5_context context; 
    void *server_handle;
    char *realm;
    
    each_iteration_t each_principal;
    each_iteration_t each_policy;

    PyObject *_storage; 
    
} PyKAdminObject;

extern PyTypeObject PyKAdminObject_Type;

PyKAdminObject *PyKAdminObject_create(void);
void PyKAdminObject_destroy(PyKAdminObject *self);

#endif
