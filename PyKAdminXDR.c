
#include "PyKAdminXDR.h"
#include <string.h>

int pykadmin_xdr_osa_princ_ent_rec(XDR *xdrs, osa_princ_ent_rec *entry) {

	int result = 0; 

	memset(entry, 0, sizeof(osa_princ_ent_rec));

	switch (xdrs->x_op) {

		case XDR_ENCODE:
			entry->version = OSA_ADB_PRINC_VERSION_1;
		case XDR_FREE:
			if (!xdr_int(xdrs, &entry->version))
				goto done;
		case XDR_DECODE:
			if (!xdr_int(xdrs, &entry->version) || (entry->version != OSA_ADB_PRINC_VERSION_1))
				goto done;
	}

    if (!pykadmin_xdr_nullstring(xdrs, &entry->policy))
		goto done;

    if (!xdr_long(xdrs, &entry->aux_attributes))
		goto done;

    if (!xdr_u_int(xdrs, &entry->old_key_next))
		goto done;

	if (!xdr_u_char(xdrs, (unsigned char *)&entry->admin_history_kvno))
		goto done;

    if (!xdr_array(xdrs, (caddr_t *) &entry->old_keys, (unsigned int *) &entry->old_key_len, ~0, sizeof(osa_pw_hist_ent), pykadmin_xdr_osa_pw_hist_ent))
   		goto done;

	result = 1;

done:
	
	return result;
}

int pykadmin_xdr_nullstring(XDR *xdrs, char **string) {

   	unsigned int size;
   	int result = 0;

   	if (xdrs->x_op == XDR_ENCODE)
   		size = (*string) ? strlen(*string) + 1 : 0; 

   	if (!xdr_u_int(xdrs, &size))
   		goto done;

  	switch (xdrs->x_op) {

  		case XDR_DECODE:
  			if (size) {
  				*string = malloc(size);
  				if (!*string)
  					goto done;
  			} else {
  				*string = NULL;
  			}
  			if (!xdr_opaque(xdrs, *string, size))
  				goto done;
  			break;

  		case XDR_ENCODE:
  			if (size) {
  				if (!xdr_opaque(xdrs, *string, size))
  					goto done;
  			}
  			break;
  		case XDR_FREE:
  			if (*string) {
  				free(*string);
  				*string = NULL;
  			}
  			break;
  	}

  	result = 1;
done:
	return result;
}

int pykadmin_xdr_int16(XDR *xdrs, int *data) {

	int result = 0;
	if (!xdr_int(xdrs, data))
		goto done;

	result = 1;
done:
	return result;
}

int pykadmin_xdr_uint16(XDR *xdrs, unsigned int *data) {

	int result = 0;
	if (!xdr_u_int(xdrs, data))
		goto done;

	result = 1;
done:
	return result;
}

int pykadmin_xdr_krb5_key_data(XDR *xdrs, krb5_key_data *key_data) {
    
    int result = 0;
    unsigned int temp;

    if (!pykadmin_xdr_int16(xdrs, (int *)&key_data->key_data_ver))
		goto done;

    if (!pykadmin_xdr_int16(xdrs, (int *)&key_data->key_data_kvno))
	    goto done;

    if (!pykadmin_xdr_int16(xdrs, (int *)&key_data->key_data_type[0]))
	    goto done;

    if (!pykadmin_xdr_int16(xdrs, (int *)&key_data->key_data_type[1]))
	    goto done;

    if (!pykadmin_xdr_uint16(xdrs, (unsigned int *)&key_data->key_data_length[0]))
	    goto done;

    if (!pykadmin_xdr_uint16(xdrs, (unsigned int *)&key_data->key_data_length[1]))
	    goto done;

    temp = (unsigned int) key_data->key_data_length[0];
    if (!xdr_bytes(xdrs, (char **) &key_data->key_data_contents[0], &temp, ~0))
		goto done;

    temp = (unsigned int) key_data->key_data_length[1];
    if (!xdr_bytes(xdrs, (char **) &key_data->key_data_contents[1], &temp, ~0))
		goto done;

    result = 1;
done:
	return result;
}

int pykadmin_xdr_osa_pw_hist_ent(XDR *xdrs, osa_pw_hist_ent *pw_hist) {
    
	int result = 0;
    if (!xdr_array(xdrs, (caddr_t *) &pw_hist->key_data, (unsigned int *) &pw_hist->n_key_data, ~0, sizeof(krb5_key_data), pykadmin_xdr_krb5_key_data))
    	goto done;

    result = 1;
done:
	return result;

}

void pykadmin_xdr_osa_free_princ_ent(osa_princ_ent_rec *entry) {
    
    XDR xdrs;

    xdrmem_create(&xdrs, NULL, 0, XDR_FREE);

    pykadmin_xdr_osa_princ_ent_rec(&xdrs, entry);

    free(entry);
}

// not exactly sure why this needs to exist, it just appears to cast a bunch of things.
//int pykadmin_xdr_krb5_kvno(XDR *xdrs, krb5_kvno *kvno) {}

