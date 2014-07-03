
#ifndef PYKADMINCOMMON_H
#define PYKADMINCOMMON_H

#include <Python.h>
#include <kdb.h>
#include <kadm5/admin.h>
#include <krb5/krb5.h>

#include "PyKadminXDR.h"
#include "PyKAdminObject.h"

krb5_error_code pykadmin_kadm_from_kdb(PyKAdminObject *kadmin, krb5_db_entry *kdb, kadm5_principal_ent_rec *entry, long mask); 

// TODO
//krb5_error_code pykadmin_copy_kadm_ent_rec(PyKAdminObject *kadmin, kadm5_principal_ent_rec *src, kadm5_principal_ent_rec *dst);


#endif
