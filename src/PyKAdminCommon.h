
#ifndef PYKADMINCOMMON_H
#define PYKADMINCOMMON_H

#include <Python.h>

#include <kdb.h>
#include <kadm5/admin.h>
#include <krb5/krb5.h>
#include <string.h>

#include "pykadmin.h"
#include "PyKAdminXDR.h"
#include "PyKAdminObject.h"
#include <bytesobject.h>


#ifndef PYTHON3
#	define PyDateTime_DELTA_GET_DAYS(o)         (((PyDateTime_Delta*)o)->days)
#	define PyDateTime_DELTA_GET_SECONDS(o)      (((PyDateTime_Delta*)o)->seconds)
#	define PyDateTime_DELTA_GET_MICROSECONDS(o) (((PyDateTime_Delta*)o)->microseconds)
#endif


char *PyUnicode_or_PyBytes_asCString(PyObject *in_str);

int pykadmin_policy_exists(void *server_handle, const char *name);

PyObject *pykadmin_pydatetime_from_timestamp(time_t timestamp);
int pykadmin_timestamp_from_pydatetime(PyObject *datetime);

int pykadmin_seconds_from_pydatetime(PyObject *delta);


char *pykadmin_timestamp_as_isodate(time_t timestamp, const char *zero);
char *pykadmin_timestamp_as_deltastr(int seconds, const char *zero);

krb5_error_code pykadmin_kadm_from_kdb(PyKAdminObject *kadmin, krb5_db_entry *kdb, kadm5_principal_ent_rec *entry, long mask); 

krb5_error_code pykadmin_policy_kadm_from_osa(krb5_context ctx, osa_policy_ent_rec *osa, kadm5_policy_ent_rec *entry, long mask); 

int pykadmin_principal_ent_rec_compare(krb5_context ctx, kadm5_principal_ent_rec *a, kadm5_principal_ent_rec *b);
int pykadmin_policy_ent_rec_compare(krb5_context ctx, kadm5_policy_ent_rec *a, kadm5_policy_ent_rec *b);



/* db_args */

void pykadmin_append_tl_data(krb5_int16 *n_tl_datap, krb5_tl_data **tl_datap,
            krb5_int16 tl_type, krb5_ui_2 len, krb5_octet *contents);

// this call will handle parsing, tl_data copy, and freeing the db_args. 
//  resulting tl_data will be freed by the call to kadm5_free_principal_ent()

void pykadmin_principal_append_db_args(kadm5_principal_ent_rec *entry, PyObject *object);

char **pykadmin_parse_db_args(PyObject *args);
void pykadmin_free_db_args(char **db_args);




// TODO
//krb5_error_code pykadmin_copy_kadm_ent_rec(PyKAdminObject *kadmin, kadm5_principal_ent_rec *src, kadm5_principal_ent_rec *dst);


#endif
