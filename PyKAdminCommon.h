
#ifndef PYKADMINCOMMON_H
#define PYKADMINCOMMON_H

#include <Python.h>

#include <kdb.h>
#include <kadm5/admin.h>
#include <krb5/krb5.h>
#include <string.h>

#include "PyKAdminXDR.h"
#include "PyKAdminObject.h"
#include <bytesobject.h>


#ifndef PYTHON3
#	define PyDateTime_DELTA_GET_DAYS(o)         (((PyDateTime_Delta*)o)->days)
#	define PyDateTime_DELTA_GET_SECONDS(o)      (((PyDateTime_Delta*)o)->seconds)
#	define PyDateTime_DELTA_GET_MICROSECONDS(o) (((PyDateTime_Delta*)o)->microseconds)
#endif


inline char *PyUnicode_or_PyBytes_asCString(PyObject *in_str);

int pykadmin_policy_exists(void *server_handle, const char *name);

inline PyObject *pykadmin_pydatetime_from_timestamp(time_t timestamp);
int pykadmin_timestamp_from_pydatetime(PyObject *datetime);

int pykadmin_seconds_from_pydatetime(PyObject *delta);


char *pykadmin_timestamp_as_isodate(time_t timestamp, const char *zero);
char *pykadmin_timestamp_as_deltastr(int seconds, const char *zero);



krb5_error_code pykadmin_kadm_from_kdb(PyKAdminObject *kadmin, krb5_db_entry *kdb, kadm5_principal_ent_rec *entry, long mask); 

krb5_error_code pykadmin_policy_kadm_from_osa(krb5_context ctx, osa_policy_ent_rec *osa, kadm5_policy_ent_rec *entry, long mask); 

int pykadmin_principal_ent_rec_compare(krb5_context ctx, kadm5_principal_ent_rec *a, kadm5_principal_ent_rec *b);
int pykadmin_policy_ent_rec_compare(krb5_context ctx, kadm5_policy_ent_rec *a, kadm5_policy_ent_rec *b);


// TODO
//krb5_error_code pykadmin_copy_kadm_ent_rec(PyKAdminObject *kadmin, kadm5_principal_ent_rec *src, kadm5_principal_ent_rec *dst);


#endif
