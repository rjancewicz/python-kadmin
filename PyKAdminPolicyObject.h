
#ifndef PYKADMINPOLICYOBJECT_H
#define PYKADMINPOLICYOBJECT_H

#include <Python.h>
#include <kadm5/admin.h>
#include <krb5/krb5.h>
#include <stdio.h>
#include <string.h>
#include <structmember.h>

extern time_t get_date(char *);

/*
typedef struct _kadm5_policy_ent_t {
    char            *policy;
    long            pw_min_life;
    long            pw_max_life;
    long            pw_min_length;
    long            pw_min_classes;
    long            pw_history_num;
    long            policy_refcnt;

    // version 3 fields 
    int32 krb5_kvno       pw_max_fail;
    int32 krb5_deltat     pw_failcnt_interval;
    int32 krb5_deltat     pw_lockout_duration;
} kadm5_policy_ent_rec, *kadm5_policy_ent_t;
*/


typedef struct {
    PyObject_HEAD
    PyKAdminObject *kadmin;
    kadm5_policy_ent_rec policy; 
} PyKAdminPolicyObject;

PyTypeObject PyKAdminPolicyObject_Type;

PyKAdminPolicyObject *PyKAdminPolicyObject_policy_with_name(PyKAdminObject *kadmin, char *name);

//PyKAdminPolicyObject *PyKAdminPolicyObject_create(PyKAdminObject *kadmin, char *name);
void PyKAdminPolicyObject_destroy(PyKAdminPolicyObject *self);

#endif
