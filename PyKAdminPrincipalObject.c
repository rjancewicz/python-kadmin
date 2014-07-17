
#include "PyKAdminObject.h"
#include "PyKAdminErrors.h"
#include "PyKAdminIterator.h"
#include "PyKAdminPrincipalObject.h"
#include "PyKAdminPolicyObject.h"

#include "PyKAdminCommon.h"

#include <datetime.h>

#define TIME_NONE ((time_t) -1)

static const unsigned int kFLAG_MAX =
    ( KRB5_KDB_DISALLOW_POSTDATED 
    | KRB5_KDB_DISALLOW_FORWARDABLE 
    | KRB5_KDB_DISALLOW_TGT_BASED 
    | KRB5_KDB_DISALLOW_RENEWABLE 
    | KRB5_KDB_DISALLOW_PROXIABLE 
    | KRB5_KDB_DISALLOW_DUP_SKEY 
    | KRB5_KDB_DISALLOW_ALL_TIX 
    | KRB5_KDB_REQUIRES_PRE_AUTH 
    | KRB5_KDB_REQUIRES_HW_AUTH 
    | KRB5_KDB_REQUIRES_PWCHANGE 
    | KRB5_KDB_DISALLOW_SVR 
    | KRB5_KDB_PWCHANGE_SERVICE 
    | KRB5_KDB_SUPPORT_DESMD5 
    | KRB5_KDB_NEW_PRINC 
    | KRB5_KDB_OK_AS_DELEGATE 
    | KRB5_KDB_OK_TO_AUTH_AS_DELEGATE 
    | KRB5_KDB_NO_AUTH_DATA_REQUIRED );


static void PyKAdminPrincipal_dealloc(PyKAdminPrincipalObject *self) {
    
    kadm5_free_principal_ent(self->kadmin->server_handle, &self->entry);

    Py_XDECREF(self->kadmin);
   
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject *PyKAdminPrincipal_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {

    PyKAdminPrincipalObject *self;

    self = (PyKAdminPrincipalObject *)type->tp_alloc(type, 0);

    if (self) {
        memset(&self->entry, 0, sizeof(kadm5_principal_ent_rec));
    }

    return (PyObject *)self;

}

static int PyKAdminPrincipal_init(PyKAdminPrincipalObject *self, PyObject *args, PyObject *kwds) {
    return 0;
}

static int PyKAdminPrincipal_print(PyKAdminPrincipalObject *self, FILE *file, int flags){

    static const char *kPRINT_FORMAT = "%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s";

    krb5_error_code errno;
    char *client_name = NULL;

    if (self && self->kadmin) {

        errno = krb5_unparse_name(self->kadmin->context, self->entry.principal, &client_name);

        fprintf(file, kPRINT_FORMAT, 
            "Principal",                      client_name,
            "Expiration date",                NULL,
            "Last password change",           NULL,
            "Password expiration date",       NULL,
            "Maximum ticket life",            NULL,
            "Maximum renewable life",         NULL,
            "Last modified",                  NULL,
            "Last successful authentication", NULL,
            "Last failed authentication",     NULL,
            "Failed password attempts",       NULL,
            "Number of keys",                 NULL
            );
    }

    if (client_name)
        free(client_name);
    
    return 0;
}




static PyObject *PyKAdminPrincipal_set_attributes(PyKAdminPrincipalObject *self, PyObject *args, PyObject *kwds) {

    //kadm5_ret_t retval = KADM5_OK;
    unsigned int flag = 0; 

    if (!PyArg_ParseTuple(args, "i", &flag))
        return NULL;

    if (flag <= kFLAG_MAX) {

        self->entry.attributes |= flag;
        self->mask |= KADM5_ATTRIBUTES;

        //retval = kadm5_modify_principal(self->kadmin->server_handle, &self->entry, KADM5_ATTRIBUTES);
        //if (retval != KADM5_OK) { PyKAdmin_RaiseKAdminError(retval, "kadm5_modify_principal"); return NULL; }
    }

    Py_RETURN_TRUE;
}

static PyObject *PyKAdminPrincipal_unset_attributes(PyKAdminPrincipalObject *self, PyObject *args, PyObject *kwds) {

    //kadm5_ret_t retval = KADM5_OK;
    unsigned int flag = 0; 

    if (!PyArg_ParseTuple(args, "(i)", &flag))
        return NULL;

    if (flag <= kFLAG_MAX) {

        self->entry.attributes &= ~flag;
        self->mask |= KADM5_ATTRIBUTES;

        //retval = kadm5_modify_principal(self->kadmin->server_handle, &self->entry, KADM5_ATTRIBUTES);
        //if (retval != KADM5_OK) { PyKAdmin_RaiseKAdminError(retval, "kadm5_modify_principal"); return NULL; }
    }

    Py_RETURN_TRUE;
}



static PyObject *PyKAdminPrincipal_commit(PyKAdminPrincipalObject *self) {

    kadm5_ret_t retval = KADM5_OK; 

    if (self && self->mask) {

        retval = kadm5_modify_principal(self->kadmin->server_handle, &self->entry, self->mask);
        if (retval != KADM5_OK) { PyKAdmin_RaiseKAdminError(retval, "kadm5_modify_principal"); } 

        self->mask = 0;
    }

    Py_RETURN_TRUE;
}

static PyObject *PyKAdminPrincipal_reload(PyKAdminPrincipalObject *self) {

    krb5_error_code ret = 0;
    kadm5_ret_t retval = KADM5_OK; 

    krb5_principal temp = NULL;

    if (self) {

        // we need to free prior to fetching otherwise we leak memory since principal and policy are pointers, alternitively we could manually free those
        ret = krb5_copy_principal(self->kadmin->context, self->entry.principal, &temp);
        if (ret) {}

        retval = kadm5_free_principal_ent(self->kadmin->server_handle, &self->entry);
        if (retval != KADM5_OK) { PyKAdmin_RaiseKAdminError(retval, "kadm5_free_principal_ent"); } 

        if (retval == KADM5_OK) {
            retval = kadm5_get_principal(self->kadmin->server_handle, temp, &self->entry, KADM5_PRINCIPAL_NORMAL_MASK);
            if (retval != KADM5_OK) { PyKAdmin_RaiseKAdminError(retval, "kadm5_get_principal"); }
        }

        krb5_free_principal(self->kadmin->context, temp);

        if (retval != KADM5_OK) { return NULL; }        
    }

    Py_RETURN_TRUE;
}


static PyObject *PyKAdminPrincipal_unlock(PyKAdminPrincipalObject *self) {
    return NULL;
}


static PyObject *PyKAdminPrincipal_change_password(PyKAdminPrincipalObject *self, PyObject *args, PyObject *kwds) {

    kadm5_ret_t retval = KADM5_OK; 
    char *password     = NULL;

    if (!PyArg_ParseTuple(args, "s", &password))
        return NULL; 

    retval = kadm5_chpass_principal(self->kadmin->server_handle, self->entry.principal, password);
    if (retval != KADM5_OK) { PyKAdmin_RaiseKAdminError(retval, "kadm5_chpass_principal"); return NULL; }

    Py_RETURN_TRUE;
}

static PyObject *PyKAdminPrincipal_randomize_key(PyKAdminPrincipalObject *self) {

    kadm5_ret_t retval = KADM5_OK; 

    retval = kadm5_randkey_principal(self->kadmin->server_handle, self->entry.principal, NULL, NULL);
    if (retval != KADM5_OK) { PyKAdmin_RaiseKAdminError(retval, "kadm5_randkey_principal"); return NULL; }

    Py_RETURN_TRUE;
}

PyObject *PyKAdminPrincipal_RichCompare(PyObject *o1, PyObject *o2, int opid) {

    PyKAdminPrincipalObject *a = (PyKAdminPrincipalObject *)o1;
    PyKAdminPrincipalObject *b = (PyKAdminPrincipalObject *)o2;

    PyObject *result = NULL; 
        
    int equal = pykadmin_principal_ent_rec_compare(a->kadmin->context, &a->entry, &b->entry);

    switch (opid) {

        case Py_EQ:
            result = ((a == b) || equal) ? Py_True : Py_False;
            break;
        case Py_NE:
            result = ((a != b) && !equal) ? Py_True : Py_False;
            break;
        case Py_LT:
        case Py_LE:
        case Py_GT:
        case Py_GE:
        default: 
            result = Py_NotImplemented;
            goto done;
    }


done:
    Py_XINCREF(result);
    return result;


}

/*
 *  GETTERS
 */

static PyObject *PyKAdminPrincipal_get_principal(PyKAdminPrincipalObject *self, void *closure) {
  
    krb5_error_code ret = 0;
    PyObject *principal = NULL;
    char *client_name   = NULL;
    
    // todo: handle error
    ret = krb5_unparse_name(self->kadmin->context, self->entry.principal, &client_name);

    if (client_name) {
        principal = PyString_FromString(client_name);
        free(client_name);
    }

    return principal;
}


static PyObject *PyKAdminPrincipal_get_mod_name(PyKAdminPrincipalObject *self, void *closure) {
  
    krb5_error_code ret = 0;
    PyObject *principal = NULL;
    char *client_name   = NULL;
    
    // todo: handle error
    ret = krb5_unparse_name(self->kadmin->context, self->entry.mod_name, &client_name);

    if (client_name) {
        principal = PyString_FromString(client_name);
        free(client_name);
    }

    return principal;
}

static PyObject *PyKAdminPrincipal_get_last_pwd_change(PyKAdminPrincipalObject *self, void *closure) {
    return pykadmin_pydatetime_from_timestamp(self->entry.last_pwd_change);
}

static PyObject *PyKAdminPrincipal_get_expire(PyKAdminPrincipalObject *self, void *closure) {
    return pykadmin_pydatetime_from_timestamp(self->entry.princ_expire_time);
}

static PyObject *PyKAdminPrincipal_get_pwexpire(PyKAdminPrincipalObject *self, void *closure) {
    return pykadmin_pydatetime_from_timestamp(self->entry.pw_expiration);
}

static PyObject *PyKAdminPrincipal_get_mod_date(PyKAdminPrincipalObject *self, void *closure) {
    return pykadmin_pydatetime_from_timestamp(self->entry.mod_date);
}

static PyObject *PyKAdminPrincipal_get_last_success(PyKAdminPrincipalObject *self, void *closure) {
    return pykadmin_pydatetime_from_timestamp(self->entry.last_success);
}

static PyObject *PyKAdminPrincipal_get_last_failed(PyKAdminPrincipalObject *self, void *closure) {
    return pykadmin_pydatetime_from_timestamp(self->entry.last_failed);
}

static PyObject *PyKAdminPrincipal_get_maxrenewlife(PyKAdminPrincipalObject *self, void *closure) {

    PyDateTime_IMPORT;

    PyObject *delta = PyDelta_FromDSU(0, self->entry.max_renewable_life, 0);
    if (!delta) { PyErr_SetString(PyExc_AttributeError, NULL); }

    return delta;
}


static PyObject *PyKAdminPrincipal_get_maxlife(PyKAdminPrincipalObject *self, void *closure) {

    PyDateTime_IMPORT;

    PyObject *delta = PyDelta_FromDSU(0, self->entry.max_life, 0);
    if (!delta) { PyErr_SetString(PyExc_AttributeError, NULL); }

    return delta;
}

static PyObject *PyKAdminPrincipal_get_attributes(PyKAdminPrincipalObject *self, void *closure) {


    unsigned int mask = 1;
    PyObject *attrs = PyList_New(0);

    while (mask < kFLAG_MAX) {

        if (mask & self->entry.attributes) {
            PyList_Append(attrs, PyInt_FromLong(mask));
        }

        mask = mask << 1;
    }

    return attrs;

}

static PyObject *PyKAdminPrincipal_get_policy(PyKAdminPrincipalObject *self, void *closure) {

    PyObject *result = Py_None;
    
    if (self) {

        if (self->entry.policy) {
            result = PyString_FromString(self->entry.policy);
        }
    }

    Py_XINCREF(result);
    return result;
}

static PyObject *PyKAdminPrincipal_get_kvno(PyKAdminPrincipalObject *self, void *closure) {

    PyObject *result = NULL;
    
    if (self) {
#if PY_MAJOR_VERSION > 2
            result = PyLong_FromLong((long) self->entry.kvno);
#else
            result = PyInt_FromLong((long) self->entry.kvno);
#endif
    }

    Py_XINCREF(result);
    return result;
}


/*
 *  SETTERS 
 */

static krb5_deltat _decode_timedelta_input(PyObject *timedelta) {

    PyDateTime_IMPORT;

    time_t now;
    krb5_deltat delta = TIME_NONE;  

    if (timedelta) {

        char *date_string = NULL;

        if (PyDelta_CheckExact(timedelta)) {
            delta = pykadmin_seconds_from_pydatetime(timedelta);
        } else if (PyUnicode_CheckExact(timedelta)) {
            // TODO: unicode
        } else if (PyString_CheckExact(timedelta)) {
            date_string = PyString_AsString(timedelta);

        } else if (timedelta == Py_None) {
            date_string = "never";
        }
        
        if (date_string) {
            delta = get_date(date_string);
        }

    }

    if (delta == TIME_NONE) {
        PyErr_SetString(PyExc_ValueError, "Invalid input");
    } else if (delta != 0) {
        time(&now);
        delta -= now;
    }

    return delta;

}

static krb5_timestamp _decode_datetime_input(PyObject *date) {

    PyDateTime_IMPORT;

    krb5_timestamp timestamp = TIME_NONE;  

    //static const char *kDATE_NEVER = "never";

    if (date) {

        char *date_string = NULL;

        if (PyDate_CheckExact(date) || PyDateTime_CheckExact(date)) {
            timestamp = pykadmin_timestamp_from_pydatetime(date);

        } else if (PyUnicode_CheckExact(date)) {
            // TODO: unicode
        } else if (PyString_CheckExact(date)) {
            date_string = PyString_AsString(date);

        } else if (date == Py_None) {
            date_string = "never";

        }
        
        if (date_string) {
            timestamp = get_date(date_string);
        }

    }

    if (timestamp == TIME_NONE)
        PyErr_SetString(PyExc_ValueError, "Invalid input");

    return timestamp;
}


int PyKAdminPrincipal_set_expire(PyKAdminPrincipalObject *self, PyObject *value, void *closure) {

    krb5_timestamp timestamp = _decode_datetime_input(value);

    if (timestamp == TIME_NONE) {
        return 1; 
    }

    self->entry.princ_expire_time = timestamp;
    self->mask |= KADM5_PRINC_EXPIRE_TIME;

    return 0;
}

int PyKAdminPrincipal_set_pwexpire(PyKAdminPrincipalObject *self, PyObject *value, void *closure) {

    krb5_timestamp timestamp = _decode_datetime_input(value);

    if (timestamp == TIME_NONE) {
        return 1; 
    }

    self->entry.princ_expire_time = timestamp;
    self->mask |= KADM5_PW_EXPIRATION;

    return 0;

}

int PyKAdminPrincipal_set_maxlife(PyKAdminPrincipalObject *self, PyObject *value, void *closure) {

    krb5_timestamp timestamp = _decode_timedelta_input(value);

    if (timestamp == TIME_NONE) {
        return 1; 
    }

    self->entry.max_life = timestamp;
    self->mask |= KADM5_MAX_LIFE;

    return 0;

}

int PyKAdminPrincipal_set_maxrenewlife(PyKAdminPrincipalObject *self, PyObject *value, void *closure) {

    krb5_timestamp timestamp = _decode_timedelta_input(value);

    if (timestamp == TIME_NONE) {
        return 1; 
    }

    self->entry.max_renewable_life = timestamp;
    self->mask |= KADM5_MAX_RLIFE;

    return 0;

}


int PyKAdminPrincipal_set_kvno(PyKAdminPrincipalObject *self, PyObject *value, void *closure) {

    unsigned long kvno = 0;

    if (self) {
#if PY_MAJOR_VERSION > 2
            kvno = PyLong_AsUnsignedLong(value);
#else
            kvno = PyInt_AsUnsignedLongMask(value);
#endif
    }
 
    if (!PyErr_Occurred()) {
        self->entry.kvno = (unsigned int)kvno;
        self->mask |= KADM5_KVNO;
    }

    return 0;

}

int PyKAdminPrincipal_set_policy(PyKAdminPrincipalObject *self, PyObject *value, void *closure) {

    char *policy_string = NULL;

    if (self) {

        if (value) {

            if (value == Py_None) {
                self->mask &= ~KADM5_POLICY;
                self->mask |= KADM5_POLICY_CLR; 
            }

            if (PyUnicode_CheckExact(value)) {
                // TODO 
            } else if (PyString_CheckExact(value)) {

                policy_string = PyString_AsString(value);

            } else if (PyKAdminPolicyObject_CheckExact(value)) {

                policy_string = PyKAdminPolicyObject_policy_name((PyKAdminPolicyObject *)value);

            }

            if (policy_string) {
                
                if (pykadmin_policy_exists(self->kadmin->server_handle, policy_string)) {

                    if (self->entry.policy) {
                        free(self->entry.policy);
                    }

                    self->entry.policy = policy_string;
                    // set policy flag and remove policy clear flag if set.
                    self->mask |= KADM5_POLICY;
                    self->mask &= ~KADM5_POLICY_CLR;
                }
            }

        }
    }

    return 0;

}


static PyMethodDef PyKAdminPrincipal_methods[] = {

    {"cpw",             (PyCFunction)PyKAdminPrincipal_change_password, METH_VARARGS,  "doc string"},
    {"change_password", (PyCFunction)PyKAdminPrincipal_change_password, METH_VARARGS,  "doc string"},
    {"randkey",         (PyCFunction)PyKAdminPrincipal_randomize_key,   METH_NOARGS,   "doc string"},
    {"randomize_key",   (PyCFunction)PyKAdminPrincipal_randomize_key,   METH_NOARGS,   "doc string"},

    // TODO: principal.modify(expire=a, pwexpire=b, maxlife=c, maxrenewlife=d, attributes=e, policy=f, kvno=g)
    //{"modify"           (PyCFunction)NULL,                              METH_KEYWORDS, "doc string"}

    {"commit",           (PyCFunction)PyKAdminPrincipal_commit,          METH_NOARGS,   "doc string"},
    {"reload",           (PyCFunction)PyKAdminPrincipal_reload,          METH_NOARGS,   "doc string"},
    {"unlock",           (PyCFunction)PyKAdminPrincipal_unlock,          METH_NOARGS,   "doc string"},

    {"set_flags",        (PyCFunction)PyKAdminPrincipal_set_attributes,          METH_NOARGS,   "doc string"},
    {"unset_flags",      (PyCFunction)PyKAdminPrincipal_unset_attributes, METH_NOARGS,   "doc string"},
    

    {NULL, NULL, 0, NULL}
};


static PyGetSetDef PyKAdminPrincipal_getters_setters[] = {

    {"principal",       (getter)PyKAdminPrincipal_get_principal,       NULL, "doc string", NULL},
    {"name",            (getter)PyKAdminPrincipal_get_principal,       NULL, "doc string", NULL},

    {"mod_name",        (getter)PyKAdminPrincipal_get_mod_name,        NULL, "doc string", NULL},
    {"mod_date",        (getter)PyKAdminPrincipal_get_mod_date,        NULL, "doc string", NULL},

    {"last_pwd_change", (getter)PyKAdminPrincipal_get_last_pwd_change, NULL, "doc string", NULL},
    {"last_success",    (getter)PyKAdminPrincipal_get_last_success,    NULL, "doc string", NULL},
    {"last_failure",    (getter)PyKAdminPrincipal_get_last_failed,     NULL, "doc string", NULL},

    // setter attributes

    {"expire",       (getter)PyKAdminPrincipal_get_expire,       (setter)PyKAdminPrincipal_set_expire,       "doc string", NULL},
    {"pwexpire",     (getter)PyKAdminPrincipal_get_pwexpire,     (setter)PyKAdminPrincipal_set_pwexpire,     "doc string", NULL},

    {"maxlife",      (getter)PyKAdminPrincipal_get_maxlife,      (setter)PyKAdminPrincipal_set_maxlife,      "doc string", NULL},
    {"maxrenewlife", (getter)PyKAdminPrincipal_get_maxrenewlife, (setter)PyKAdminPrincipal_set_maxrenewlife, "doc string", NULL},
    {"attributes",   (getter)PyKAdminPrincipal_get_attributes,   (setter)PyKAdminPrincipal_set_attributes,   "doc string", NULL},
  
    {"policy",       (getter)PyKAdminPrincipal_get_policy,       (setter)PyKAdminPrincipal_set_policy,       "doc string", NULL},
    {"kvno",         (getter)PyKAdminPrincipal_get_kvno,         (setter)PyKAdminPrincipal_set_kvno,         "doc string", NULL},

    {NULL, NULL, NULL, NULL, NULL}
};


static PyMemberDef PyKAdminPrincipal_members[] = {
  
    {"failures",   T_INT, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, fail_auth_count), READONLY, "doc string"},
    {"mkvno",      T_INT, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, mkvno),           READONLY, "doc string"},

    {NULL}
};


PyTypeObject PyKAdminPrincipalObject_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    //PyObject_HEAD_INIT(NULL)
    //0,                         /*ob_size*/
    "kadmin.Principal",             /*tp_name*/
    sizeof(PyKAdminPrincipalObject),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)PyKAdminPrincipal_dealloc, /*tp_dealloc*/
    (printfunc)PyKAdminPrincipal_print,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0, //PyKAdminPrincipal_str,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,   /*tp_flags*/
    "KAdminPrincipal objects",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    PyKAdminPrincipal_RichCompare,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    PyKAdminPrincipal_methods,             /* tp_methods */
    PyKAdminPrincipal_members,             /* tp_members */
    PyKAdminPrincipal_getters_setters,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)PyKAdminPrincipal_init,      /* tp_init */
    0,                         /* tp_alloc */
    PyKAdminPrincipal_new,                 /* tp_new */
};


PyKAdminPrincipalObject *PyKAdminPrincipalObject_principal_with_name(PyKAdminObject *kadmin, char *client_name) {
        
    krb5_error_code errno;

    PyKAdminPrincipalObject *principal = (PyKAdminPrincipalObject *)Py_None;

    if (client_name) {

        principal = (PyKAdminPrincipalObject *)PyKAdminPrincipal_new(&PyKAdminPrincipalObject_Type, NULL, NULL);

        if (principal) {

            Py_INCREF(kadmin);
            principal->kadmin = kadmin;

            errno = krb5_parse_name(kadmin->context, client_name, &principal->entry.principal);
            PyObject *result = PyKAdminPrincipal_reload(principal);

            if (!result || errno) {
                Py_INCREF(Py_None);
                PyKAdminPrincipal_dealloc(principal);
                principal = (PyKAdminPrincipalObject *)Py_None;
            }

        }
    }

    return principal;
}

PyKAdminPrincipalObject *PyKAdminPrincipalObject_principal_with_db_entry(PyKAdminObject *kadmin, krb5_db_entry *kdb) {

    kadm5_ret_t retval = KADM5_OK;

    PyKAdminPrincipalObject *principal = (PyKAdminPrincipalObject *)PyKAdminPrincipal_new(&PyKAdminPrincipalObject_Type, NULL, NULL);

    if (kdb) {

        Py_XINCREF(kadmin);
        principal->kadmin = kadmin;

        retval = pykadmin_kadm_from_kdb(kadmin, kdb, &principal->entry, KADM5_PRINCIPAL_NORMAL_MASK);

        if (retval) {

            PyKAdminPrincipal_dealloc(principal);
            
            // todo: set exception
            principal = NULL;

        } 
    }

    return principal;
}

void PyKAdminPrincipalObject_destroy(PyKAdminPrincipalObject *self) {
    PyKAdminPrincipal_dealloc(self);
}



