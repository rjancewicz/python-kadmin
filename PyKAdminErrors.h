

#include <python2.6/Python.h>
#include <kadm5/admin.h>
#include <krb5/krb5.h>
#include <stdio.h>
#include <string.h>

PyObject *KAdminError;
PyObject *KAdminErrorsDict; 

void PyKAdminError_init(PyObject *module);
//inline void PyKAdminError_insert(kadm5_ret_t retval, char *error_name, char *error_string);

PyObject *PyKAdminError_raise_kadmin_error(kadm5_ret_t retval, char *caller);
//PyObject *PyKAdminError_raise_kadmin_error(kadm5_ret_t retval); 
