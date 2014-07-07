
#ifndef PYKADMINERRORS_H
#define PYKADMINERRORS_H

#include <Python.h>
#include <kadm5/admin.h>
#include <kadm5/kadm_err.h>
#include <krb5/krb5.h>
#include <stdio.h>
#include <string.h>
#include <structmember.h>

#define PyKAdmin_HandleKAdminError(retval, caller) if (retval != 0x0) { (PyKAdmin_RaiseKAdminError(retval, caller)); return NULL; }

PyObject *KAdminError;
PyObject *KAdminErrorsDict;

void PyKAdminError_init(PyObject *module);

PyObject *PyKAdmin_RaiseKAdminError(kadm5_ret_t retval, char *caller);

#endif
