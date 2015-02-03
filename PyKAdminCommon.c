
/* we are going to reuse the internal get_principal function as the foundation of our 
	kdb_entry to kadm5_principal_ent_t mapper
    
    svr_principal.c
	kadm5_ret_t
kadm5_get_principal(void *server_handle, krb5_principal principal,
                    kadm5_principal_ent_t entry,
                    long in_mask)

	*/

#include "PyKAdminCommon.h"
#include <datetime.h>

#define TIME_NONE ((time_t) -1)

inline char *PyUnicode_or_PyBytes_asCString(PyObject *in_str) {

    char *out_str = NULL;

    if (PyUnicode_CheckExact(in_str)) {

        PyObject *ascii = PyUnicode_AsASCIIString(in_str);

        if (ascii) {
            out_str = PyBytes_AsString(ascii);
            Py_XDECREF(ascii);
        }

    } else if (PyBytes_CheckExact(in_str)) {
        
        out_str = PyBytes_AsString(in_str);
    }

    out_str = strdup(out_str);

    return out_str;
}


char *pykadmin_timestamp_as_isodate(time_t timestamp, const char *zero) {

    struct tm *timeinfo; 
    char *isodate = NULL;

    if (timestamp) { 
        isodate = malloc(32);

        if (isodate) {

            timeinfo = localtime(&timestamp);
            strftime(isodate, 32, "%FT%T%z", timeinfo);
        }
    } else {
        isodate = strdup(zero);
    }

    return isodate;
}

char *pykadmin_timestamp_as_deltastr(int seconds, const char *zero) {

    char *deltastr = NULL;
    int negative, days, hours, minutes; 

    if (seconds != 0) {

        if (seconds < 0) {
            seconds *= -1; 
            negative = 1; 
        }

        days    = seconds / (24 * 3600);
        seconds %= 24 * 3600;
        hours   = seconds / 3600;
        seconds %= 3600;
        minutes = seconds / 60;
        seconds %= 60;

        deltastr = malloc(64);

        if (deltastr) {
            snprintf(deltastr, 64, "%s%d %s %02d:%02d:%02d", negative ? "-" : "",  days, days == 1 ? "day" : "days", hours, minutes, seconds);
        }

    } else {

        deltastr = strdup(zero);
    }
    
    return deltastr;
}



inline PyObject *pykadmin_pydatetime_from_timestamp(time_t timestamp) {

    PyDateTime_IMPORT;

    if (timestamp) {
        PyObject *datetime = NULL;
        PyObject *args     = NULL;

        args = Py_BuildValue("(i)", timestamp);

        if (args) {
            datetime = PyDateTime_FromTimestamp(args);
            Py_DECREF(args);
        }

        if (!datetime)
            PyErr_SetString(PyExc_AttributeError, NULL);

        return datetime;
    } else {
        Py_RETURN_NONE;
    }
}

int pykadmin_timestamp_from_pydatetime(PyObject *datetime) {
    
    PyDateTime_IMPORT;

    time_t timestamp = 0; 
    struct tm *timeinfo; 

    if (datetime) {

        timeinfo = localtime ( &timestamp );

        timeinfo->tm_year = PyDateTime_GET_YEAR(datetime) - 1900;
        timeinfo->tm_mon  = PyDateTime_GET_MONTH(datetime) - 1;
        timeinfo->tm_mday = PyDateTime_GET_DAY(datetime);

        if (PyDateTime_Check(datetime)) {
            timeinfo->tm_hour = PyDateTime_DATE_GET_HOUR(datetime) - 1 ;
            timeinfo->tm_min  = PyDateTime_DATE_GET_MINUTE(datetime);
            timeinfo->tm_sec  = PyDateTime_DATE_GET_SECOND(datetime);
        }

        timestamp = mktime(timeinfo);
    } else {
        timestamp = TIME_NONE;
    }

    return timestamp;
}

int pykadmin_seconds_from_pydatetime(PyObject *delta) {
    
    PyDateTime_IMPORT;

    time_t seconds = 0; 

    if (delta) {
        seconds += PyDateTime_DELTA_GET_SECONDS(delta);
        seconds += PyDateTime_DELTA_GET_DAYS(delta) * 24 * 3600;
    }

    return seconds;

}

int pykadmin_policy_exists(void *server_handle, const char *name) {

    kadm5_ret_t retval = KADM5_OK;
    kadm5_policy_ent_rec policy; 

    retval = kadm5_get_policy(server_handle, (char *)name, &policy);
    if (retval == KADM5_OK) 
        kadm5_free_policy_ent(server_handle, &policy);

    return (retval == KADM5_OK);
}

krb5_error_code pykadmin_unpack_xdr_osa_princ_ent_rec(PyKAdminObject *kadmin, krb5_db_entry *kdb, osa_princ_ent_rec *adb) {

    krb5_error_code retval = 0; 

    XDR xdrs;
    krb5_tl_data tl_data;

    tl_data.tl_data_type = KRB5_TL_KADM_DATA;

    if ((retval = krb5_dbe_lookup_tl_data(kadmin->context, kdb, &tl_data)) || (tl_data.tl_data_length == 0)) {
        adb->admin_history_kvno = 0;
    }

    if (tl_data.tl_data_length) {
        xdrmem_create(&xdrs, (caddr_t)tl_data.tl_data_contents, tl_data.tl_data_length, XDR_DECODE);

        if (!pykadmin_xdr_osa_princ_ent_rec(&xdrs, adb)) {
            xdr_destroy(&xdrs);
            retval = KADM5_XDR_FAILURE;
            goto done;
        }

        xdr_destroy(&xdrs);
    }

    //retval = KADM5_OK;
done: 

    return retval;
}


/*
    
    The following two functions are taken directly from svr_principal.c 
        the comment preceeding them indicates that they *may* be released into the public api.
        until that point there they will simply be copied here as static versions

*/

static kadm5_ret_t krb5_copy_key_data_contents(context, from, to)
    krb5_context context;
    krb5_key_data *from, *to;
{
    int i, idx;

    *to = *from;

    idx = (from->key_data_ver == 1 ? 1 : 2);

    for (i = 0; i < idx; i++) {
        if ( from->key_data_length[i] ) {
            to->key_data_contents[i] = malloc(from->key_data_length[i]);
            if (to->key_data_contents[i] == NULL) {
                for (i = 0; i < idx; i++) {
                    if (to->key_data_contents[i]) {
                        memset(to->key_data_contents[i], 0,
                               to->key_data_length[i]);
                        free(to->key_data_contents[i]);
                    }
                }
                return ENOMEM;
            }
            memcpy(to->key_data_contents[i], from->key_data_contents[i],
                   from->key_data_length[i]);
        }
    }
    return 0;
}

static krb5_tl_data *dup_tl_data(krb5_tl_data *tl)
{
    krb5_tl_data *n;

    n = (krb5_tl_data *) malloc(sizeof(krb5_tl_data));
    if (n == NULL)
        return NULL;
    n->tl_data_contents = malloc(tl->tl_data_length);
    if (n->tl_data_contents == NULL) {
        free(n);
        return NULL;
    }
    memcpy(n->tl_data_contents, tl->tl_data_contents, tl->tl_data_length);
    n->tl_data_type = tl->tl_data_type;
    n->tl_data_length = tl->tl_data_length;
    n->tl_data_next = NULL;
    return n;
}

krb5_error_code pykadmin_kadm_from_kdb(PyKAdminObject *kadmin, krb5_db_entry *kdb, kadm5_principal_ent_rec *entry, long mask) {

    krb5_error_code retval = 0; 
    int i;

    osa_princ_ent_rec *adb = NULL;

    memset(entry, 0, sizeof(kadm5_principal_ent_rec));
    adb = calloc(1, sizeof(osa_princ_ent_rec));

    //memset(adb, 0, sizeof(osa_princ_ent_rec));

    /* principal */

    if (mask & KADM5_PRINCIPAL) {
        if ((retval = krb5_copy_principal(kadmin->context, kdb->princ, &entry->principal)))
            goto done;
    }

    /* members with a direct relationship */

    if (mask & KADM5_PRINC_EXPIRE_TIME)
        entry->princ_expire_time = kdb->expiration;
    
    if (mask & KADM5_PW_EXPIRATION)
        entry->pw_expiration = kdb->pw_expiration;

    if (mask & KADM5_MAX_LIFE)
        entry->max_life = kdb->max_life;

    if (mask & KADM5_MAX_RLIFE)
        entry->max_renewable_life = kdb->max_renewable_life;

    if (mask & KADM5_LAST_SUCCESS)
        entry->last_success = kdb->last_success;

    if (mask & KADM5_LAST_FAILED)
        entry->last_failed = kdb->last_failed;

    if (mask & KADM5_FAIL_AUTH_COUNT)
        entry->fail_auth_count = kdb->fail_auth_count;

    if (mask & KADM5_ATTRIBUTES)
        entry->attributes = kdb->attributes;

    /* members with computed values */

    if (mask & KADM5_LAST_PWD_CHANGE) {
        if ((retval = krb5_dbe_lookup_last_pwd_change(kadmin->context, kdb, &entry->last_pwd_change)))
            goto done; 
    }

    if ((mask & KADM5_MOD_NAME) || (mask & KADM5_MOD_TIME)) {
        if ((retval = krb5_dbe_lookup_mod_princ_data(kadmin->context, kdb, &(entry->mod_date), &(entry->mod_name))))
            goto done;

        if (! (mask & KADM5_MOD_TIME))
            entry->mod_date = 0;

        if (! (mask & KADM5_MOD_NAME)) {
            krb5_free_principal(kadmin->context, entry->mod_name);
            entry->mod_name = NULL;
        }
    }  


    if (mask & KADM5_KVNO) {
        entry->kvno = 0;
        for (i = 0; i < kdb->n_key_data; i++) {
            if ((krb5_kvno) kdb->key_data[i].key_data_kvno > entry->kvno)
                entry->kvno = (krb5_kvno) kdb->key_data[i].key_data_kvno;
        }
    }

    if (mask & KADM5_MKVNO) {
        if ((retval = krb5_dbe_lookup_mkvno(kadmin->context, kdb, &entry->mkvno)))
            goto done;
    }
    


    /* key data */

    if (mask & KADM5_TL_DATA) {
        krb5_tl_data *tl, *tl2;

        entry->tl_data = NULL;

        tl = kdb->tl_data;
        while (tl) {
            if (tl->tl_data_type > 255) {
                if ((tl2 = dup_tl_data(tl)) == NULL) {
                    goto done;
                }
                tl2->tl_data_next = entry->tl_data;
                entry->tl_data = tl2;
                entry->n_tl_data++;
            }

            tl = tl->tl_data_next;
        }
    }


    if (mask & KADM5_KEY_DATA) {

        entry->n_key_data = kdb->n_key_data;

        if(entry->n_key_data) {
            entry->key_data = calloc(entry->n_key_data, sizeof(krb5_key_data));
            if (!entry->key_data)
                goto done;
        } else
            entry->key_data = NULL;

            for (i = 0; i < entry->n_key_data; i++)
                retval = krb5_copy_key_data_contents(kadmin->context, &kdb->key_data[i], &entry->key_data[i]);
        if (retval)
            goto done;
    }


    /* 
        compute adb value of kadm5_get_principal function using the internal mechanism kdb_get_entry
 
        krb5/src/lib/kadm5/srv/svr_principal.c
        kadm5_get_principal()

        krb5/src/lib/kadm5/srv/server_kdb.c 
        kdb_get_entry()

    */

    if ((retval = pykadmin_unpack_xdr_osa_princ_ent_rec(kadmin, kdb, adb))) {
        goto done;
    }

    /* load data stored into the entry rec */

    if (mask & KADM5_POLICY) {
        if ((adb->aux_attributes & KADM5_POLICY) && adb->policy) {
            entry->policy = strdup(adb->policy);
        }
    }

    if (mask & KADM5_AUX_ATTRIBUTES)
        entry->aux_attributes = adb->aux_attributes;

    pykadmin_xdr_osa_free_princ_ent(adb);

    retval = KADM5_OK;

done: 
    if (retval && entry->principal) {
        krb5_free_principal(kadmin->context, entry->principal);
        entry->principal = NULL;
    }
    
    return retval;

}



/*
typedef struct _kadm5_policy_ent_t {
    char            *policy;
    long            pw_min_life;
    long            pw_max_life;
    long            ;
    long            ;
    long            ;
    long            ;

    // version 3 fields 
    int32 krb5_kvno       pw_max_fail;
    int32 krb5_deltat     pw_failcnt_interval;
    int32 krb5_deltat     pw_lockout_duration;
} kadm5_policy_ent_rec, *kadm5_policy_ent_t;

typedef struct _osa_policy_ent_t {
    int               version;
    char      *name;
    krb5_ui_4       pw_min_life;
    krb5_ui_4       pw_max_life;
    krb5_ui_4       pw_min_length;
    krb5_ui_4       pw_min_classes;
    krb5_ui_4       pw_history_num;
    krb5_ui_4       policy_refcnt;

    // Only valid if version > 1 
    krb5_ui_4       pw_max_fail;                // pwdMaxFailure 
    krb5_ui_4       pw_failcnt_interval;        // pwdFailureCountInterval 
    krb5_ui_4       pw_lockout_duration;        // pwdLockoutDuration 
} osa_policy_ent_rec, *osa_policy_ent_t;


*/


krb5_error_code pykadmin_policy_kadm_from_osa(krb5_context ctx, osa_policy_ent_rec *osa, kadm5_policy_ent_rec *entry, long mask) {

    krb5_error_code retval = 0; 

    memset(entry, 0, sizeof(kadm5_policy_ent_rec));

    entry->policy = strdup(osa->name);
    entry->pw_min_life = osa->pw_min_life;
    entry->pw_max_life = osa->pw_max_life;
    entry->pw_min_length = osa->pw_min_length;
    entry->pw_min_classes = osa->pw_min_classes;
    entry->pw_history_num = osa->pw_history_num;
    entry->policy_refcnt = osa->policy_refcnt;

    if (osa->version > 1) {
        entry->pw_max_fail = osa->pw_max_fail;
        entry->pw_failcnt_interval = osa->pw_failcnt_interval;
        entry->pw_lockout_duration = osa->pw_lockout_duration;
    }

    return retval;
}



int pykadmin_compare_tl_data(krb5_context ctx, krb5_tl_data *a, krb5_tl_data *b) {

    int result = 1; 

    if (a && b) {

        result &= (a->tl_data_type == b->tl_data_type);
        result &= (a->tl_data_length == b->tl_data_length);

        if (result)
            result &= (memcmp(a->tl_data_contents, b->tl_data_contents, a->tl_data_length) == 0);


        if (result && a->tl_data_next) 
            result &= pykadmin_compare_tl_data(ctx, a->tl_data_next, b->tl_data_next);

    } else {

        result &= (a == b);
    }


    return result;
}



int pykadmin_compare_key_data(krb5_context ctx, krb5_key_data *a, krb5_key_data *b) {
    
    int result = 1; 
    int i, idx; 

    if (a && b) {
        result &= (a->key_data_ver == b->key_data_ver);
        result &= (a->key_data_kvno == b->key_data_kvno);

        if (result) {

            idx = (a->key_data_ver == 1 ? 1 : 2);
            for (i = 0; i < idx; i++) {

                result &= (a->key_data_type[i] == b->key_data_type[i]);
                result &= (a->key_data_length[i] == b->key_data_length[i]);

                if (result)
                    result &= (memcmp(a->key_data_contents[i], b->key_data_contents[i], a->key_data_length[i]) == 0);
            }
        }
    } else {

        result &= (a == b);
    }


    return result;
}

int pykadmin_principal_ent_rec_compare(krb5_context ctx, kadm5_principal_ent_rec *a, kadm5_principal_ent_rec *b) {

    int result = 1; 

    result &= krb5_principal_compare(ctx, a->principal, b->principal);

    result &= (a->princ_expire_time == b->princ_expire_time);
    result &= (a->last_pwd_change == b->last_pwd_change);
    result &= (a->pw_expiration == b->pw_expiration);
    result &= (a->max_life == b->max_life);
    
    result &= krb5_principal_compare(ctx, a->mod_name, b->mod_name);

    result &= (a->mod_date == b->mod_date);
    result &= (a->attributes == b->attributes);

    result &= (a->kvno == b->kvno);
    result &= (a->mkvno == b->mkvno);

    if (a->policy && b->policy)
        result &= (strcmp(a->policy, b->policy) == 0);

    result &= (a->max_renewable_life == b->max_renewable_life);
    result &= (a->last_success == b->last_success);
    result &= (a->last_failed == b->last_failed);
    result &= (a->fail_auth_count == b->fail_auth_count);
    result &= (a->n_key_data == b->n_key_data);
    result &= (a->n_tl_data == b->n_tl_data);

    result &= pykadmin_compare_tl_data(ctx, a->tl_data, b->tl_data);

    result &= pykadmin_compare_key_data(ctx, a->key_data, b->key_data);

    return result; 
}

int pykadmin_policy_ent_rec_compare(krb5_context ctx, kadm5_policy_ent_rec *a, kadm5_policy_ent_rec *b) {

    int result = 1; 

    result &= (strcmp(a->policy, b->policy) == 0);

    result &= (a->pw_min_life == b->pw_min_life);
    result &= (a->pw_max_life == b->pw_max_life);
    result &= (a->pw_min_length == b->pw_min_length);
    result &= (a->pw_min_classes == b->pw_min_classes);
    result &= (a->pw_history_num == b->pw_history_num);
    result &= (a->policy_refcnt == b->policy_refcnt);
    result &= (a->pw_max_fail == b->pw_max_fail);
    result &= (a->pw_failcnt_interval == b->pw_failcnt_interval);
    result &= (a->pw_lockout_duration == b->pw_lockout_duration);

    return result;
}


/* this is taken from the kadmin.c source
    https://github.com/krb5/krb5/blob/master/src/kadmin/cli/kadmin.c */
void pykadmin_append_tl_data(krb5_int16 *n_tl_datap, krb5_tl_data **tl_datap,
            krb5_int16 tl_type, krb5_ui_2 len, krb5_octet *contents) {
    krb5_tl_data *tl_data;
    krb5_octet *copy;

    copy = malloc(len);
    tl_data = calloc(1, sizeof(*tl_data));
    if (copy == NULL || tl_data == NULL) {
        exit(1);
    }
    memcpy(copy, contents, len);

    tl_data->tl_data_type = tl_type;
    tl_data->tl_data_length = len;
    tl_data->tl_data_contents = copy;
    tl_data->tl_data_next = NULL;

    for (; *tl_datap != NULL; tl_datap = &(*tl_datap)->tl_data_next);
    *tl_datap = tl_data;
    (*n_tl_datap)++;
}

char **pykadmin_parse_db_args(PyObject *object) {

    static const char DB_ARGS_ERROR[] = "Unable to parse db_args; valid types are set, list, tuple or dictionary.";
    static const char FORMAT_STR[] = "%s=%s";

    char **db_args = NULL;
    size_t n_args  = 0;

    Py_ssize_t index = 0;

    if (object) {

        if (PyDict_Check(object)) {

            PyObject *key    = NULL;
            PyObject *value  = NULL;
            
            char *key_cstr   = NULL;
            char *value_cstr = NULL;
            char *argument   = NULL;

            size_t length    = 0; 

            while (PyDict_Next(object, &index, &key, &value)) {

                if (PyUnicodeBytes_Check(key) && PyUnicodeBytes_Check(value)) {

                    key_cstr = PyUnicode_or_PyBytes_asCString(key);
                    value_cstr = PyUnicode_or_PyBytes_asCString(value);

                    length = strlen(key_cstr) + strlen(value_cstr) + 4; // strlen("=\"\"\0") == 4
                    argument = calloc(length, sizeof(char));

                    if (argument) { 
                        snprintf(argument, length, FORMAT_STR, key_cstr, value_cstr);

                        db_args = realloc(db_args, sizeof(intptr_t) * (n_args + 1));
                        if (!db_args) {
                            // todo unable to allocate memory!
                        }

                        db_args[n_args++] = argument;
                    }
                }
            }
        }
        else if (PySequence_Check(object)) {

            PyObject *item     = NULL;
            PyObject *sequence = NULL;

            char *item_cstr    = NULL;
            
            Py_ssize_t size    = 0;

            sequence = PySequence_Fast(object, DB_ARGS_ERROR);
            size = PySequence_Size(object);

            for (; index < size; index++) {

                item = PySequence_Fast_GET_ITEM(sequence, index);

                if (PyUnicodeBytes_Check(item)) {

                    item_cstr = PyUnicode_or_PyBytes_asCString(item);

                    db_args = realloc(db_args, sizeof(intptr_t) * (n_args + 1));
                    if (!db_args) {
                        // todo unable to allocate memory!
                        // raise MemoryError (PyExc_MemoryError)
                    }

                    db_args[n_args++] = item_cstr;
                }

            }

            Py_DECREF(sequence);
        }
        else {
            PyErr_SetString(PyExc_TypeError, DB_ARGS_ERROR);
            db_args = NULL;
        }

        if (db_args) {
            // NULL terminate arguments 
            db_args = realloc(db_args, sizeof(intptr_t) * (n_args + 1));
            db_args[n_args] = NULL;
        }

    }

    return db_args; 
}


void pykadmin_principal_append_db_args(kadm5_principal_ent_rec *entry, PyObject *args) {

    char **db_args = pykadmin_parse_db_args(args);

    Py_ssize_t index = 0;

    if (db_args) {

        while(db_args[index] != NULL) {

            pykadmin_append_tl_data(&entry->n_tl_data, &entry->tl_data, 
                KRB5_TL_DB_ARGS, strlen(db_args[index]) + 1, (krb5_octet *)db_args[index]);
            index ++;
        }

    }

    pykadmin_free_db_args(db_args);

}
 
void pykadmin_free_db_args(char **db_args) {

    size_t index = 0;

    if (db_args) {

        while(db_args[index] != NULL) {
            free(db_args[index++]);
        }

        free(db_args);
    }

}

