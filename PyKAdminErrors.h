
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


	#ifdef KADMIN_LOCAL
		#define kBASE_ERROR_NAME "kadmin_local.KAdminError"
		#define kKADM_ERROR_NAME "kadmin_local.AdminError"
		#define kKRB5_ERROR_NAME "kadmin_local.KerberosError"
	#else
		#define kBASE_ERROR_NAME "kadmin.KAdminError"
		#define kKADM_ERROR_NAME "kadmin.AdminError"
		#define kKRB5_ERROR_NAME "kadmin.KerberosError"
	#endif

#define PyKAdmin_RETURN_KADM5_ERROR(retval, caller) { PyKAdminError_raise_kadm_error(retval, caller); return NULL; }
#define PyKAdmin_RETURN_KRB5_ERROR(code, caller) { PyKAdminError_raise_krb5_error(code, caller); return NULL; }

// Base Exception Objects

PyObject *PyKAdminError_base;
PyObject *PyKAdminError_kadm;
PyObject *PyKAdminError_krb5;

int PyKAdminError_init_kadm(PyObject *modle);
int PyKAdminError_init_krb5(PyObject *modle);

void PyKAdminError_raise_kadm_error(kadm5_ret_t retval, char *caller);
void PyKAdminError_raise_krb5_error(krb5_error_code code, char *caller);


#endif
