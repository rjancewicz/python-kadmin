
#ifndef PYKADMINCOMMON_H
#define PYKADMINCOMMON_H

#include <Python.h>
#include <kdb.h>
#include <kadm5/admin.h>
#include <krb5/krb5.h>
#include <string.h>

#include "PyKAdminXDR.h"
#include "PyKAdminObject.h"

krb5_error_code pykadmin_kadm_from_kdb(PyKAdminObject *kadmin, krb5_db_entry *kdb, kadm5_principal_ent_rec *entry, long mask); 

krb5_error_code pykadmin_policy_kadm_from_osa(krb5_context ctx, osa_policy_ent_rec *osa, kadm5_policy_ent_rec *entry, long mask); 

int pykadmin_principal_ent_rec_compare(krb5_context ctx, kadm5_principal_ent_rec *a, kadm5_principal_ent_rec *b);
int pykadmin_policy_ent_rec_compare(krb5_context ctx, kadm5_policy_ent_rec *a, kadm5_policy_ent_rec *b);


// TODO
//krb5_error_code pykadmin_copy_kadm_ent_rec(PyKAdminObject *kadmin, kadm5_principal_ent_rec *src, kadm5_principal_ent_rec *dst);


#endif
