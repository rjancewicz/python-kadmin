
#include "PyKAdminObject.h"
#include "PyKAdminErrors.h"
#include "PyKAdminIterator.h"
#include "PyKAdminPrincipalObject.h"
#include "PyKAdminPolicyObject.h"

#include "PyKAdminCommon.h"

#include <bytesobject.h>
#include <datetime.h>

#define TIME_NONE ((time_t) -1)


static PyObject *PyKAdminPrincipal_get_keys(PyKAdminPrincipalObject *self, void *closure);

static char kNEVER[] = "never";

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
   
    //self->ob_type->tp_free((PyObject*)self);
    Py_TYPE(self)->tp_free((PyObject *)self);
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


static PyObject *PyKAdminPrincipal_str(PyKAdminPrincipalObject *self) {
    return NULL;
}


static void _PyKAdminPrincipal_print_keys(PyKAdminPrincipalObject *self, FILE *file, int flags) {

    PyObject *keys = PyKAdminPrincipal_get_keys(self, NULL);

    PyObject *kvno;
    PyObject *value;
    PyObject *tuple;
    PyObject *enctype;
    PyObject *salttype;

    ssize_t pos = 0;
    ssize_t index = 0; 

    if (keys) {

        while (PyDict_Next(keys, &pos, &kvno, &value)) {

            if (PyList_Check(value)) {

                for (index = 0; index < PyList_Size(value); index++) {

                    tuple = PyList_GetItem(value, index);

                    if (PyTuple_Check(tuple)) {

                        if (PyTuple_Size(tuple) == 2) {

                            enctype = PyTuple_GetItem(tuple, 0);
                            salttype = PyTuple_GetItem(tuple, 1);

                            fprintf(file, "Key: vno %ld, %s, %s\n", PyUnifiedLongInt_AsLong(kvno), PyUnicode_or_PyBytes_asCString(enctype), PyUnicode_or_PyBytes_asCString(salttype));

                        }
                    }
                }
            }
        }

        Py_DECREF(keys);
    }

}

static int PyKAdminPrincipal_print(PyKAdminPrincipalObject *self, FILE *file, int flags){

    static char kNEVER_DATE[] = "[never]";
    static char kNONE_DATE[]  = "[none]";

    //static const char *kPRINT_FORMAT = "%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %d\n%s: %d\n%s: %s";

    krb5_error_code errno;
    char *client_name = NULL;
    char *expire      = NULL;
    char *pwchange    = NULL;
    char *pwexpire    = NULL;
    char *maxlife     = NULL;
    char *maxrlife    = NULL;
    char *moddate     = NULL;
    char *success     = NULL;
    char *failure     = NULL;

    if (self && self->kadmin) {

        errno = krb5_unparse_name(self->kadmin->context, self->entry.principal, &client_name);

        expire   = pykadmin_timestamp_as_isodate(self->entry.princ_expire_time, kNEVER_DATE);
        pwchange = pykadmin_timestamp_as_isodate(self->entry.last_pwd_change, kNEVER_DATE);
        pwexpire = pykadmin_timestamp_as_isodate(self->entry.pw_expiration, kNEVER_DATE);
        moddate  = pykadmin_timestamp_as_isodate(self->entry.mod_date, kNEVER_DATE);
        success  = pykadmin_timestamp_as_isodate(self->entry.last_success, kNEVER_DATE);
        failure  = pykadmin_timestamp_as_isodate(self->entry.last_failed, kNEVER_DATE);

        maxlife  = pykadmin_timestamp_as_deltastr(self->entry.max_life, kNONE_DATE);
        maxrlife = pykadmin_timestamp_as_deltastr(self->entry.max_renewable_life, kNONE_DATE);

        //fprintf(file, kPRINT_FORMAT, 
        fprintf(file, "Principal: %s\n",                      client_name);
        fprintf(file, "Expiration date: %s\n",                expire);
        fprintf(file, "Last password change: %s\n",           pwchange);
        fprintf(file, "Password expiration date: %s\n",       pwexpire);
        fprintf(file, "Maximum ticket life: %s\n",            maxlife);
        fprintf(file, "Maximum renewable life: %s\n",         maxrlife);
        fprintf(file, "Last modified: %s\n",                  moddate);
        fprintf(file, "Last successful authentication: %s\n", success);
        fprintf(file, "Last failed authentication: %s\n",     failure);
        fprintf(file, "Failed password attempts: %d\n",       self->entry.fail_auth_count);
        fprintf(file, "Number of keys: %d\n",                 self->entry.n_key_data);

        _PyKAdminPrincipal_print_keys(self, file, flags);

        fprintf(file, "Policy: %s", self->entry.policy ? self->entry.policy : kNONE_DATE );

    }

    if (client_name) { free(client_name); }
    if (expire)      { free(expire);      }
    if (pwchange)    { free(pwchange);    }
    if (pwexpire)    { free(pwexpire);    }
    if (maxlife)     { free(maxlife);     }
    if (maxrlife)    { free(maxrlife);    }
    if (moddate)     { free(moddate);     }
    if (success)     { free(success);     }
    if (failure)     { free(failure);     }
    


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
        //if (retval != KADM5_OK) { raise_error(retval, "kadm5_modify_principal"); return NULL; }
    }

    Py_RETURN_TRUE;
}

static PyObject *PyKAdminPrincipal_unset_attributes(PyKAdminPrincipalObject *self, PyObject *args, PyObject *kwds) {

    unsigned int flag = 0; 

    if (!PyArg_ParseTuple(args, "(i)", &flag))
        return NULL;

    if (flag <= kFLAG_MAX) {

        self->entry.attributes &= ~flag;
        self->mask |= KADM5_ATTRIBUTES;
    }

    Py_RETURN_TRUE;
}



static PyObject *PyKAdminPrincipal_commit(PyKAdminPrincipalObject *self) {

    PyObject *result = NULL;
    kadm5_ret_t retval = KADM5_OK; 

    if (self && self->mask) {

        retval = kadm5_modify_principal(self->kadmin->server_handle, &self->entry, self->mask);
        
        if (retval == KADM5_OK) {
            result = Py_True;
        } else { 
            PyKAdminError_raise_error(retval, "kadm5_modify_principal"); 
            goto cleanup;
        } 

        self->mask = 0;
    }

cleanup:

    Py_XINCREF(result);
    return result;
}

static PyObject *PyKAdminPrincipal_reload(PyKAdminPrincipalObject *self) {

    PyObject *result = NULL;

    krb5_error_code code = 0;

    kadm5_ret_t retval = KADM5_OK; 

    krb5_principal temp = NULL;

    if (self) {

        code = krb5_copy_principal(self->kadmin->context, self->entry.principal, &temp);
        if (code) {
            PyKAdminError_raise_error(code, "krb5_copy_principal");
            goto cleanup;
        }

        retval = kadm5_free_principal_ent(self->kadmin->server_handle, &self->entry);
        if (retval != KADM5_OK) { 
            PyKAdminError_raise_error(retval, "kadm5_free_principal_ent"); 
            goto cleanup;
        } 

        retval = kadm5_get_principal(self->kadmin->server_handle, temp, &self->entry, KADM5_PRINCIPAL_NORMAL_MASK);
        if (retval != KADM5_OK) { 
            PyKAdminError_raise_error(retval, "kadm5_get_principal"); 
            goto cleanup;
        }    

    }

cleanup:
    
    krb5_free_principal(self->kadmin->context, temp);

    Py_XINCREF(result);
    return result;
}

/* taken from mit-krb5 kadmin.c - why's it in kadmin.c and not libkadm5
 * anyways? */
/* Construct a tl_data element and add it to the tail of *tl_datap. */
static int
add_tl_data(krb5_int16 *n_tl_datap, krb5_tl_data **tl_datap,
            krb5_int16 tl_type, krb5_ui_2 len, krb5_octet *contents)
{
    krb5_tl_data *tl_data;
    krb5_octet *copy;

    copy = malloc(len);
    tl_data = calloc(1, sizeof(*tl_data));
    if (copy == NULL || tl_data == NULL)
        return ENOMEM;
    memcpy(copy, contents, len);

    tl_data->tl_data_type = tl_type;
    tl_data->tl_data_length = len;
    tl_data->tl_data_contents = copy;
    tl_data->tl_data_next = NULL;

    for (; *tl_datap != NULL; tl_datap = &(*tl_datap)->tl_data_next);
    *tl_datap = tl_data;
    (*n_tl_datap)++;

    return 0;
}

/* taken from k5-platform.h */
static inline void
store_32_le (unsigned int val, void *vp)
{
    unsigned char *p = (unsigned char *) vp;
    p[3] = (val >> 24) & 0xff;
    p[2] = (val >> 16) & 0xff;
    p[1] = (val >>  8) & 0xff;
    p[0] = (val      ) & 0xff;
}

static PyObject *PyKAdminPrincipal_unlock(PyKAdminPrincipalObject *self) {
    krb5_error_code retval;
    krb5_timestamp now;
    krb5_octet timebuf[4];

    /* Zero out the failed auth count. */
    self->entry.fail_auth_count = 0;
    self->mask |= KADM5_FAIL_AUTH_COUNT;

    /* Record the timestamp of this unlock operation so that slave KDCs will
     * see it, since fail_auth_count is unreplicated. */
    retval = krb5_timeofday(self->kadmin->context, &now);
    if (retval) {
        PyKAdminError_raise_error(retval, "krb5_timeofday");
        return NULL;
    }
    store_32_le((krb5_int32)now, timebuf);
    retval = add_tl_data(&self->entry.n_tl_data, &self->entry.tl_data,
        KRB5_TL_LAST_ADMIN_UNLOCK, 4, timebuf);
    if (retval) {
        PyKAdminError_raise_error(retval, "add_tl_data");
        return NULL;
    }

    self->mask |= KADM5_TL_DATA;

    Py_RETURN_TRUE;
}


static PyObject *PyKAdminPrincipal_change_password(PyKAdminPrincipalObject *self, PyObject *args, PyObject *kwds) {

    PyObject *result   = Py_True;
    kadm5_ret_t retval = KADM5_OK; 
    char *password     = NULL;

    if (!PyArg_ParseTuple(args, "s", &password))
        return NULL; 

    retval = kadm5_chpass_principal(self->kadmin->server_handle, self->entry.principal, password);
    if (retval != KADM5_OK) {
        PyKAdminError_raise_error(retval, "kadm5_chpass_principal");
        result = NULL;
    }

    Py_XINCREF(result);
    return result;
}

static PyObject *PyKAdminPrincipal_randomize_key(PyKAdminPrincipalObject *self) {

    PyObject *result   = Py_True;
    kadm5_ret_t retval = KADM5_OK; 

    retval = kadm5_randkey_principal(self->kadmin->server_handle, self->entry.principal, NULL, NULL);
    if (retval != KADM5_OK)  {
        PyKAdminError_raise_error(retval, "kadm5_randkey_principal");
        result = NULL;
    }

    Py_XINCREF(result);
    return result;
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
            PyErr_SetString(PyExc_TypeError, "kadmin.Principal does not support operation"); 
    }

    Py_XINCREF(result);
    return result;

}

/*
 *  GETTERS
 */

static PyObject *PyKAdminPrincipal_get_principal(PyKAdminPrincipalObject *self, void *closure) {
  
    krb5_error_code code = 0;
    PyObject *principal  = NULL;
    char *client_name    = NULL;
    
    code = krb5_unparse_name(self->kadmin->context, self->entry.principal, &client_name);
    if (code) {
        PyKAdminError_raise_error(code, "krb5_unparse_name");
        goto cleanup;
    }

    principal = PyUnicode_FromString(client_name);

cleanup:

    if (client_name)
        free(client_name);

    return principal;
}


static PyObject *PyKAdminPrincipal_get_mod_name(PyKAdminPrincipalObject *self, void *closure) {
  
    krb5_error_code code = 0;
    PyObject *principal  = NULL;
    char *client_name    = NULL;
    
    code = krb5_unparse_name(self->kadmin->context, self->entry.mod_name, &client_name);
    if (code) {
        PyKAdminError_raise_error(code, "krb5_unparse_name");
        goto cleanup;
    }

    principal = PyUnicode_FromString(client_name);

cleanup:

    if (client_name)
        free(client_name);

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

            PyList_Append(attrs, PyUnifiedLongInt_FromLong(mask));
            
        }

        mask = mask << 1;
    }

    return attrs;

}

static PyObject *PyKAdminPrincipal_get_policy(PyKAdminPrincipalObject *self, void *closure) {

    PyObject *result = Py_None;
    
    if (self) {

        if (self->entry.policy) {
            result = PyUnicode_FromString(self->entry.policy);
        }
    }

    Py_XINCREF(result);
    return result;
}

static PyObject *PyKAdminPrincipal_get_kvno(PyKAdminPrincipalObject *self, void *closure) {

    PyObject *result = NULL;
    
    if (self) {
        result = PyUnifiedLongInt_FromLong(self->entry.kvno);
    }

    Py_XINCREF(result);
    return result;
}



PyObject *pykadmin_key_enctype_name(krb5_key_data *key_data) {

    PyObject *enctype = NULL;
    // make sure this is enough. 
    char buffer[1024];

    if (krb5_enctype_to_name(key_data->key_data_type[0], FALSE, buffer, sizeof(buffer)))
        snprintf(buffer, sizeof(buffer), "<Encryption type 0x%x>", key_data->key_data_type[0]);

    enctype = PyUnicode_FromString(buffer);

    return enctype;
}

PyObject *pykadmin_key_salttype_name(krb5_key_data *key_data) {

    PyObject *salttype = NULL;
    // make sure this is enough. 
    char buffer[1024];

    if (krb5_salttype_to_string(key_data->key_data_type[1], buffer, sizeof(buffer)))
        snprintf(buffer, sizeof(buffer), "<Salt type 0x%x>", key_data->key_data_type[0]);

    salttype = PyUnicode_FromString(buffer);

    return salttype;
}

static PyObject *PyKAdminPrincipal_get_keys(PyKAdminPrincipalObject *self, void *closure) { 

    /*

    key structure:

        {
            kvno: [("enctype", "salt"), ("enctype", "salt")],
            kvno: ...
        }

    */

    PyObject *kvno     = NULL;
    PyObject *enctype  = NULL;
    PyObject *salttype = NULL;
    PyObject *tuple    = NULL;
    PyObject *list     = NULL;

    PyObject *keys = PyDict_New();

    ssize_t index = 0; 

    for (; index < self->entry.n_key_data; index++) {

        krb5_key_data *key_data = &self->entry.key_data[index];

        kvno = PyUnifiedLongInt_FromLong(key_data->key_data_kvno);

        enctype  = pykadmin_key_enctype_name(key_data);
        salttype = pykadmin_key_salttype_name(key_data);

        tuple = PyTuple_Pack(2, enctype, salttype);


        if (kvno) {
            if (PyDict_Contains(keys, kvno)) {
                list = PyDict_GetItem(keys, kvno);
            } else {
                list = PyList_New(0);
                PyDict_SetItem(keys, kvno, list);
            }
        }

        if (list && tuple) {
            PyList_Append(list, tuple);
        }

    }

    return keys;
}


/*
 *  SETTERS 
 */


static krb5_deltat _decode_timedelta_input(PyObject *timedelta) {

    PyDateTime_IMPORT;

    time_t now = 0; 
    krb5_deltat delta = TIME_NONE;  

    if (timedelta) {

        char *date_string = NULL;

        if (PyDelta_CheckExact(timedelta)) {
            delta = pykadmin_seconds_from_pydatetime(timedelta);
        } else if (PyUnicodeBytes_Check(timedelta)) {
            date_string = PyUnicode_or_PyBytes_asCString(timedelta);
        } else if (timedelta == Py_None) {
            date_string = kNEVER;
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

static krb5_timestamp _decode_timestamp_input(PyObject *date) {

    PyDateTime_IMPORT;

    krb5_timestamp timestamp = TIME_NONE;  

    if (date) {

        char *date_string = NULL;

        if (PyDate_CheckExact(date) || PyDateTime_CheckExact(date)) {
            timestamp = pykadmin_timestamp_from_pydatetime(date);
        } else if (PyUnicodeBytes_Check(date)) {
            date_string = PyUnicode_or_PyBytes_asCString(date);
        } else if (date == Py_None) {
            date_string = kNEVER;
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

    krb5_timestamp timestamp = _decode_timestamp_input(value);

    if (timestamp == TIME_NONE) {
        return 1; 
    }

    self->entry.princ_expire_time = timestamp;
    self->mask |= KADM5_PRINC_EXPIRE_TIME;

    return 0;
}

int PyKAdminPrincipal_set_pwexpire(PyKAdminPrincipalObject *self, PyObject *value, void *closure) {

    krb5_timestamp timestamp = _decode_timestamp_input(value);

    if (timestamp == TIME_NONE) {
        return 1; 
    }

    self->entry.pw_expiration = timestamp;
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
        kvno = PyUnifiedLongInt_AsUnsignedLong(value);
    }
 
    if (!PyErr_Occurred()) {
        self->entry.kvno = (unsigned int)kvno;
        self->mask |= KADM5_KVNO;
    }

    return 0;

}

int PyKAdminPrincipal_set_policy(PyKAdminPrincipalObject *self, PyObject *value, void *closure) {

    int result = 1; 
    char *policy_string = NULL;

    if (self) {

        if (value) {

            if (value == Py_None) {
                self->mask &= ~KADM5_POLICY;
                self->mask |= KADM5_POLICY_CLR; 
            }

            policy_string = PyUnicode_or_PyBytes_asCString(value);

            if (PyKAdminPolicyObject_CheckExact(value)) {
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
                    result = 0; 
                }
            }
        }
    }

    if (result)
        PyErr_SetString(PyExc_ValueError, "Invalid input");

    return result;

}

/*
    Set each of the requested attributes using their internal setter routine. 
    Fails at first error and should raise the error of the setter which failed.
    
    If all setters finish the commit function will automatically be called and flush changes to the database.

    returns Py_True on success NULL otherwise

*/
static PyObject *PyKAdminPrincipal_modify(PyKAdminPrincipalObject *self, PyObject *args, PyObject *kwds) {

    // TODO: principal.modify(expire=a, pwexpire=b, maxlife=c, maxrenewlife=d, policy=f, kvno=g, attributes=e, commit=False)
    /* 
        equivilent to 

        principal.expire = a
        principal.pwexpire = b 
        principal.maxlife = c 
        principal.maxrenewlife = d 
        principal.policy = e 
        principal.kvno = f 
        principal.attributes = g 

        principal.commit()
    */

    PyObject *expire       = NULL;
    PyObject *pwexpire     = NULL;
    PyObject *maxlife      = NULL;
    PyObject *maxrenewlife = NULL;
    PyObject *attributes   = NULL;
    PyObject *policy       = NULL;
    PyObject *kvno         = NULL;

    int result = 0; 

    static char *kwlist[] = {"expire", "pwexpire", "maxlife", "maxrenewlife", "policy", "kvno", "attributes", NULL};
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OOOOOOO", kwlist, &expire, &pwexpire, &maxlife, &maxrenewlife, &policy, &kvno, &attributes))
        return NULL;

    if (!result && expire)
        result |= PyKAdminPrincipal_set_expire(self, expire, NULL);

    if (!result && pwexpire)
        result |= PyKAdminPrincipal_set_pwexpire(self, pwexpire, NULL);

    if (!result && maxlife)
        result |= PyKAdminPrincipal_set_maxlife(self, maxlife, NULL);
    
    if (!result && maxrenewlife)
        result |= PyKAdminPrincipal_set_maxrenewlife(self, maxrenewlife, NULL);
    
    if (!result && attributes) {

        PyObject *tuple = PyTuple_Pack(1, attributes);
        PyObject *success = NULL;
        if (tuple) {
            success = PyKAdminPrincipal_set_attributes(self, tuple, NULL);
            
            result |= (success != Py_True);    
            Py_DECREF(tuple);
        }
    }
    
    if (!result && policy) 
        result |= PyKAdminPrincipal_set_policy(self, policy, NULL);
    
    if (!result && kvno)
        result |= PyKAdminPrincipal_set_kvno(self, kvno, NULL);


    if (!result) {
        return PyKAdminPrincipal_commit(self);
    } else {
        return NULL;
    }
}


/*
 * Documentation Strings
 */

static char kDOCSTRING_COMMIT[]          = "commit()\n\tCommit all staged changes to the kerberos database.";
static char kDOCSTRING_CPW[]             = "change_password(str)\n\tChange the password for the given principal.";
static char kDOCSTRING_RANDKEY[]         = "randkey()\n\tRandomize the key for the given principal.";
static char kDOCSTRING_RELOAD[]          = "reload()\n\tReload the local entry from the kerberos database.";
static char kDOCSTRING_UNLOCK[]          = "unlock()\n\tUnlock the principal.";
static char kDOCSTRING_SET_FLAGS[]       = "set_flags(KADM5_ATTRIBUTES)\n\tSet attributes to their enabled (1) state.";
static char kDOCSTRING_UNSET_FLAGS[]     = "unset_flags(KADM5_ATTRIBUTES)\n\tSet attributes to their diabled (0) state.";
static char kDOCSTRING_NAME[]            = "str\n\tPrincipal name as a string.";
static char kDOCSTRING_MOD_NAME[]        = "str\n\tThe account which last modified the principal as a string.";
static char kDOCSTRING_MOD_DATE[]        = "datetime.datetime\n\tThe datetime at which the principal was last modified.";
static char kDOCSTRING_LAST_PWD_CHANGE[] = "datetime.datetime\n\tThe datetime at which the password was last changed.";
static char kDOCSTRING_LAST_SUCCESS[]    = "datetime.datetime\n\tThe last successful authentication.";
static char kDOCSTRING_LAST_FAILURE[]    = "datetime.datetime\n\tThe last failed authentication.";
static char kDOCSTRING_ATTRIBUTES[]      = "list\n\tlist of all attributes which have been set.";
static char kDOCSTRING_EXPIRE[]          = "getter: datetime.datetime\n\tsetter: [datetime.date|datetime.datetime|str|None]\n\twhen the account expires.";
static char kDOCSTRING_PWEXPIRE[]        = "getter: datetime.datetime\n\tsetter: [datetime.date|datetime.datetime|str|None]\n\twhen the current password expires.";
static char kDOCSTRING_MAXLIFE[]         = "getter: datetime.timedelta\n\tsetter: [datetime.timedelta|str|None]\n\tthe maximum ticket life.";
static char kDOCSTRING_MAXRENEWLIFE[]    = "getter: datetime.timedelta\n\tsetter: [datetime.timedelta|str|None]\n\tthe maximum renewable life.";
static char kDOCSTRING_POLICY[]          = "getter: [str|None]\n\tsetter: [str|kadmin.Policy|None]\n\tpolicy enabled for the principal.";
static char kDOCSTRING_KVNO[]            = "getter: int\n\tsetter: [int]\n\tcurrent key version number.";
static char kDOCSTRING_FAILURES[]        = "failed authentication count.";
static char kDOCSTRING_MKVNO[]           = "master key version number.";

static char kDOCSTRING_MODIFY[]          = "principal.modify(expire=a, pwexpire=b, maxlife=c, maxrenewlife=d, attributes=e, policy=f, kvno=g)\n\tshorthand for calling setters and commit";

static PyMethodDef PyKAdminPrincipal_methods[] = {

    {"cpw",             (PyCFunction)PyKAdminPrincipal_change_password,  METH_VARARGS,  kDOCSTRING_CPW},
    {"change_password", (PyCFunction)PyKAdminPrincipal_change_password,  METH_VARARGS,  kDOCSTRING_CPW},
    {"randkey",         (PyCFunction)PyKAdminPrincipal_randomize_key,    METH_NOARGS,   kDOCSTRING_RANDKEY},
    {"randomize_key",   (PyCFunction)PyKAdminPrincipal_randomize_key,    METH_NOARGS,   kDOCSTRING_RANDKEY},

    {"modify",           (PyCFunction)PyKAdminPrincipal_modify,            METH_VARARGS | METH_KEYWORDS, kDOCSTRING_MODIFY},

    {"commit",           (PyCFunction)PyKAdminPrincipal_commit,           METH_NOARGS,   kDOCSTRING_COMMIT},
    {"reload",           (PyCFunction)PyKAdminPrincipal_reload,           METH_NOARGS,   kDOCSTRING_RELOAD},
    {"unlock",           (PyCFunction)PyKAdminPrincipal_unlock,           METH_NOARGS,   kDOCSTRING_UNLOCK},

    {"set_flags",        (PyCFunction)PyKAdminPrincipal_set_attributes,   METH_VARARGS,  kDOCSTRING_SET_FLAGS},
    {"unset_flags",      (PyCFunction)PyKAdminPrincipal_unset_attributes, METH_VARARGS,  kDOCSTRING_UNSET_FLAGS},
    

    {NULL, NULL, 0, NULL}
};


static PyGetSetDef PyKAdminPrincipal_getters_setters[] = {

    {"principal",       (getter)PyKAdminPrincipal_get_principal,       NULL, kDOCSTRING_NAME,            NULL},
    {"name",            (getter)PyKAdminPrincipal_get_principal,       NULL, kDOCSTRING_NAME,            NULL},

    {"mod_name",        (getter)PyKAdminPrincipal_get_mod_name,        NULL, kDOCSTRING_MOD_NAME,        NULL},
    {"mod_date",        (getter)PyKAdminPrincipal_get_mod_date,        NULL, kDOCSTRING_MOD_DATE,        NULL},

    {"last_pwd_change", (getter)PyKAdminPrincipal_get_last_pwd_change, NULL, kDOCSTRING_LAST_PWD_CHANGE, NULL},
    {"last_success",    (getter)PyKAdminPrincipal_get_last_success,    NULL, kDOCSTRING_LAST_SUCCESS,    NULL},
    {"last_failure",    (getter)PyKAdminPrincipal_get_last_failed,     NULL, kDOCSTRING_LAST_FAILURE,    NULL},

    {"attributes",      (getter)PyKAdminPrincipal_get_attributes,      NULL, kDOCSTRING_ATTRIBUTES,      NULL},

    {"keys",            (getter)PyKAdminPrincipal_get_keys,            NULL, "",                         NULL},

    // setter attributes

    {"expire",       (getter)PyKAdminPrincipal_get_expire,       (setter)PyKAdminPrincipal_set_expire,       kDOCSTRING_EXPIRE,       NULL},
    {"pwexpire",     (getter)PyKAdminPrincipal_get_pwexpire,     (setter)PyKAdminPrincipal_set_pwexpire,     kDOCSTRING_PWEXPIRE,     NULL},

    {"maxlife",      (getter)PyKAdminPrincipal_get_maxlife,      (setter)PyKAdminPrincipal_set_maxlife,      kDOCSTRING_MAXLIFE,      NULL},
    {"maxrenewlife", (getter)PyKAdminPrincipal_get_maxrenewlife, (setter)PyKAdminPrincipal_set_maxrenewlife, kDOCSTRING_MAXRENEWLIFE, NULL},
  
    {"policy",       (getter)PyKAdminPrincipal_get_policy,       (setter)PyKAdminPrincipal_set_policy,       kDOCSTRING_POLICY,       NULL},
    {"kvno",         (getter)PyKAdminPrincipal_get_kvno,         (setter)PyKAdminPrincipal_set_kvno,         kDOCSTRING_KVNO,         NULL},

    {NULL, NULL, NULL, NULL, NULL}
};

static PyMemberDef PyKAdminPrincipal_members[] = {
  
    {"failures",   T_INT, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, fail_auth_count), READONLY, kDOCSTRING_FAILURES},
    {"mkvno",      T_INT, offsetof(PyKAdminPrincipalObject, entry) + offsetof(kadm5_principal_ent_rec, mkvno),           READONLY, kDOCSTRING_MKVNO},

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
        
    krb5_error_code code;
    kadm5_ret_t retval = KADM5_OK;

    PyKAdminPrincipalObject *principal = (PyKAdminPrincipalObject *)Py_None;
    krb5_principal temp = NULL;

    if (kadmin && client_name) {

        principal = (PyKAdminPrincipalObject *)PyKAdminPrincipal_new(&PyKAdminPrincipalObject_Type, NULL, NULL);

        if (principal) {

            Py_INCREF(kadmin);
            principal->kadmin = kadmin;

            code = krb5_parse_name(kadmin->context, client_name, &temp);

            retval = kadm5_get_principal(kadmin->server_handle, temp, &principal->entry, (KADM5_PRINCIPAL_NORMAL_MASK | KADM5_KEY_DATA));

            krb5_free_principal(kadmin->context, temp);

            if ((retval != KADM5_OK) || code) {
                PyKAdminPrincipal_dealloc(principal);
                if (retval == KADM5_AUTH_GET)
                    PyKAdminError_raise_error(retval, "kadm5_get_principal");
                principal = (PyKAdminPrincipalObject *)Py_None;
            }

        }
    }

    return principal;
}

PyKAdminPrincipalObject *PyKAdminPrincipalObject_principal_with_db_entry(PyKAdminObject *kadmin, krb5_db_entry *kdb) {

    kadm5_ret_t retval = KADM5_OK;

    PyKAdminPrincipalObject *principal = (PyKAdminPrincipalObject *)PyKAdminPrincipal_new(&PyKAdminPrincipalObject_Type, NULL, NULL);

    if (kadmin && kdb) {

        Py_INCREF(kadmin);
        principal->kadmin = kadmin;

        retval = pykadmin_kadm_from_kdb(kadmin, kdb, &principal->entry, (KADM5_PRINCIPAL_NORMAL_MASK | KADM5_KEY_DATA));

        if (retval) {
            PyKAdminPrincipal_dealloc(principal);
            principal = NULL;
        } 
    }

    return principal;
}


void PyKAdminPrincipalObject_destroy(PyKAdminPrincipalObject *self) {
    PyKAdminPrincipal_dealloc(self);
}



