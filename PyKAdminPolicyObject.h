
#include <Python.h>
#include <kadm5/admin.h>
#include <krb5/krb5.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    PyObject_HEAD
    
    PyKAdminObject *kadmin;
    kadm5_policy_ent_rec policy; 
} PyKAdminPolicyObject;


PyTypeObject PyKAdminPolicyObject_Type;
PyKAdminPolicyObject *PyKAdminPolicyObject_create(void);
void PyKAdminPolicyObject_destroy(PyKAdminPolicyObject *self);
