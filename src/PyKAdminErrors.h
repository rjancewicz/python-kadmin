
#ifndef PyKAdminError_H
#define PyKAdminError_H

#include <Python.h>
#include <kadm5/admin.h>
#include <kadm5/kadm_err.h>
#include <krb5/krb5.h>
#include <stdio.h>
#include <string.h>
#include <structmember.h>

#include "pykadmin.h"

PyObject *PyKAdminError_init(PyObject *module);

void PyKAdminError_raise_error(long code, char *caller);

/*
void PyKAdminError_raise_kadm_error(kadm5_ret_t retval, char *caller);
void PyKAdminError_raise_krb5_error(krb5_error_code code, char *caller);
void PyKAdminError_raise_kdb_error(krb5_error_code retval, char *caller);
*/

#endif
