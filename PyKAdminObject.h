
#include <Python.h>
#include <kadm5/admin.h>
#include <krb5/krb5.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    PyObject_HEAD
    
    krb5_context context; 
    void *handle;
    char *realm;
} PyKAdminObject;

PyTypeObject PyKAdminObject_Type;
PyKAdminObject *PyKAdminObject_create(void);
void PyKAdminObject_destroy(PyKAdminObject *self);
