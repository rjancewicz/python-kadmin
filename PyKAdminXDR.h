
#ifndef PYKADMINXDR_H
#define PYKADMINXDR_H

#include <krb5.h>
#include <kdb.h>
#include <gssrpc/rpc.h>

/* structures from the krb5 source; 
	these are not exported anywhere so we must custom build them to extract xdr data wihout breaking APIs
	*/

#define OSA_ADB_PRINC_VERSION_1  0x12345C01

typedef struct _osa_pw_hist_t {
    int n_key_data;
    krb5_key_data *key_data;
} osa_pw_hist_ent, *osa_pw_hist_t;

typedef struct _osa_princ_ent_t {
    int                         version;
    char                        *policy;
    long                        aux_attributes;
    unsigned int                old_key_len;
    unsigned int                old_key_next;
    krb5_kvno                   admin_history_kvno;
    osa_pw_hist_ent             *old_keys;
} osa_princ_ent_rec, *osa_princ_ent_t;

void pykadmin_xdr_osa_free_princ_ent(osa_princ_ent_rec *entry); 
int pykadmin_xdr_nullstring(XDR *xdrs, char **string);
int pykadmin_xdr_osa_pw_hist_ent(XDR *xdrs, osa_pw_hist_ent *objp);
int pykadmin_xdr_osa_princ_ent_rec(XDR *xdrs, osa_princ_ent_rec *entry);


#endif