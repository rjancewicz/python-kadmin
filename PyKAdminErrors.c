
#include "PyKAdminErrors.h"

static PyObject *_pykadmin_error_base;
static PyObject *_pykadmin_errors;

//static PyObject *_pykadmin_kadm_errors; 
//static PyObject *_pykadmin_krb5_errors;

/* 
    Initialize Error Classes

    kadmin.KAdminError(exceptions.Exception)
        AdminErrors
            ... All kadm5_ret_t Errors
        KerberosErrors
            ... All krb5_error_code Errors

*/

int PyKAdminError_init_kadm(PyObject *module, PyObject *base);
int PyKAdminError_init_krb5(PyObject *module, PyObject *base);
int PyKAdminError_init_kdb(PyObject *module, PyObject *base);


PyObject *PyKAdminError_init(PyObject *module) {
    
    static const char kBASE_ERROR[] = "KAdminError";
    static const char kKADM_ERROR[] = "AdminError";
    static const char kKRB5_ERROR[] = "KerberosError";
    static const char kKDB_ERROR[] = "DatabaseError";

    PyObject *PyKAdminError_kadm = NULL;
    PyObject *PyKAdminError_krb5 = NULL;
    PyObject *PyKAdminError_kdb = NULL;

    // initialize the global statics

    _pykadmin_errors = PyDict_New();
    _pykadmin_error_base = NULL;
    //_pykadmin_kadm_errors = NULL;
    //_pykadmin_krb5_errors = NULL;


    size_t length = sizeof(kMODULE_NAME) + 0x10;
    char *cname = malloc(length);

    if (cname) {

        snprintf(cname, length, "%s.%s", kMODULE_NAME, kBASE_ERROR);

        _pykadmin_error_base = PyErr_NewException(cname, NULL, NULL);

        if (_pykadmin_error_base) {

            //Py_INCREF(_pykadmin_error_base);
            PyModule_AddObject(module, kBASE_ERROR, _pykadmin_error_base);

            snprintf(cname, length, "%s.%s", kMODULE_NAME, kKADM_ERROR);
            PyKAdminError_kadm = PyErr_NewException(cname, _pykadmin_error_base, NULL);

            snprintf(cname, length, "%s.%s", kMODULE_NAME, kKRB5_ERROR);
            PyKAdminError_krb5 = PyErr_NewException(cname, _pykadmin_error_base, NULL);

            snprintf(cname, length, "%s.%s", kMODULE_NAME, kKDB_ERROR);
            PyKAdminError_kdb = PyErr_NewException(cname, _pykadmin_error_base, NULL);

            if (PyKAdminError_kadm) {
                //Py_INCREF(PyKAdminError_kadm);
                PyModule_AddObject(module, kKADM_ERROR, PyKAdminError_kadm);
                PyKAdminError_init_kadm(module, PyKAdminError_kadm);
            }

             if (PyKAdminError_krb5) {
                //Py_INCREF(PyKAdminError_krb5);
                PyModule_AddObject(module, kKRB5_ERROR, PyKAdminError_krb5);
                PyKAdminError_init_krb5(module, PyKAdminError_krb5);
            }

             if (PyKAdminError_kdb) {
                //Py_INCREF(PyKAdminError_krb5);
                PyModule_AddObject(module, kKDB_ERROR, PyKAdminError_kdb);
                PyKAdminError_init_kdb(module, PyKAdminError_kdb);
            }
        }

        free(cname);
    }

    return _pykadmin_error_base;
}


static void _PyKAdminError_raise_exception(PyObject *storage, PyObject *error, char *caller) {

    static const char *kERROR_NUMBER = "errno";
    static const char *kERROR_STRING = "message";

    PyObject *error_string = NULL;
    PyObject *error_object = NULL;
    PyObject *error_tuple  = NULL;
    PyObject *error_dict   = PyDict_New();

    if (error && error_dict) {

        PyDict_SetItemString(error_dict, kERROR_NUMBER, error);

        if (storage) {

            error_tuple = PyDict_GetItem(storage, error);

            if (error_tuple && (PyTuple_GET_SIZE(error_tuple) == 2)) {
                error_object = PyTuple_GetItem(error_tuple, 0); 
                error_string = PyTuple_GetItem(error_tuple, 1); 
            }

        }

        if (!error_string) {
            error_string = PyUnicode_FromString(caller);
        }

        PyDict_SetItemString(error_dict, kERROR_STRING, error_string);

        if (!error_object) {
            error_object = _pykadmin_error_base;
        }

        PyErr_SetObject(error_object, error_dict);

    }

    Py_XDECREF(error_dict);

}

void PyKAdminError_raise_error(long value, char *caller) {
    PyObject *error  = PyLong_FromLong((long)value);
    _PyKAdminError_raise_exception(_pykadmin_errors, error, caller);
}

/*

void PyKAdminError_raise_error(krb5_error_code code, char *caller) {
    PyObject *error  = PyLong_FromLong((long)code);
    _PyKAdminError_raise_exception(_pykadmin_errors, error, caller);
}

void PyKAdminError_raise_error(kadm5_ret_t retval, char *caller) {
    PyObject *error  = PyLong_FromLong((long)retval);
    _PyKAdminError_raise_exception(_pykadmin_errors, error, caller);
}
*/


static int PyKAdminErrors_new_exception(PyObject *module, PyObject *base, PyObject *storage, PyObject *error, char *name, char *cname, char *message) {

    int result = 0; 
    PyObject *exception = NULL;
    PyObject *tuple     = NULL;

    if (module && base && storage && error && name && cname && message) {

        exception = PyErr_NewException(cname, base, NULL);
        
        if (exception) {

            result = PyModule_AddObject(module, name, exception);

            if (!result) {

                tuple = Py_BuildValue("(Os)", exception, message);
                result = (PyDict_SetItem(storage, error, tuple) == 0);

            }

        }
    }

    return result;
}

static int _pykadminerror_error_insert(PyObject *module, PyObject *base, krb5_error_code code, char *name, char *message) {
    
    int result       = 0; 
    char *cname      = NULL;
    size_t length    = strlen(kMODULE_NAME) + strlen(name) + 0xF;
    PyObject *error  = PyLong_FromLong((long)code);

    if (error) {

        cname = malloc(length);

        if (cname) { 
            snprintf(cname, length, "%s.%s", kMODULE_NAME, name);
            result = PyKAdminErrors_new_exception(module, base, _pykadmin_errors, error, name, cname, message);
            free(cname);
        }
    }

    return result;
}

/*
static int _pykadminerror_error_insert(PyObject *module, PyObject *base, krb5_error_code code, char *name, char *message) {
    
    int result       = 0; 
    char *cname      = NULL;
    size_t length    = strlen(kMODULE_NAME) + strlen(name) + 0xF;
    PyObject *error  = PyLong_FromLong(code);

    if (error) {

        cname = malloc(length);

        if (cname) { 
            snprintf(cname, length, "%s.%s", kMODULE_NAME, name);
            result = PyKAdminErrors_new_exception(module, base, _pykadmin_krb5_errors, error, name, cname, message);
            free(cname);
        }
    }

    return result;
}


static int _pykadminerror_error_insert(PyObject *module, PyObject *base, kadm5_ret_t retval, char *name, char *message) {
    
    int result       = 0; 
    char *cname      = NULL;
    size_t length    = strlen(kMODULE_NAME) + strlen(name) + 0xF;
    PyObject *error  = PyLong_FromUnsignedLong(retval);

    if (error) {

        cname = malloc(length);

        if (cname) { 
            snprintf(cname, length, "%s.%s", kMODULE_NAME, name);
            result = PyKAdminErrors_new_exception(module, base, _pykadmin_kadm_errors, error, name, cname, message);
            free(cname);
        }
    }

    return result;
}
*/


int PyKAdminError_init_krb5(PyObject *module, PyObject *base) {

    int result = 0; 
    //_pykadmin_krb5_errors = PyDict_New();

    if (_pykadmin_errors) {

        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_NONE,                                 "KDCNoneError",               "No error");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_NAME_EXP,                             "KDCClientExpiredError",      "Client's entry in database has expired");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_SERVICE_EXP,                          "KDCServerExpireError",       "Server's entry in database has expired");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_BAD_PVNO,                             "KDCProtocolVersionError",    "Requested protocol version not supported");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_C_OLD_MAST_KVNO,                      "KDCClientOldMasterKeyError", "Client's key is encrypted in an old master key");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_S_OLD_MAST_KVNO,                      "KDCServerOldMasterKeyError", "Server's key is encrypted in an old master key");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN,                  "KDCClientNotFoundError",     "Client not found in Kerberos database");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN,                  "KDCServerNotFoundError",     "Server not found in Kerberos database");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE,                 "KDCPrincipalUniqueError",    "Principal has multiple entries in Kerberos database");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_NULL_KEY,                             "KDCNullKeyError",            "Client or server has a null key");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_CANNOT_POSTDATE,                      "KDCCannotPostdateError",     "Ticket is ineligible for postdating");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_NEVER_VALID,                          "KDCNeverValidError",         "Requested effective lifetime is negative or too short");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_POLICY,                               "KDCPolicyError",             "KDC policy rejects request");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_BADOPTION,                            "KDCOptionError",             "KDC can't fulfill requested option");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_ETYPE_NOSUPP,                         "KDCEncryptionSupportError",  "KDC has no support for encryption type");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_SUMTYPE_NOSUPP,                       "KDCChecksumSupportError",    "KDC has no support for checksum type");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_PADATA_TYPE_NOSUPP,                   "KDCPADataSupportError",      "KDC has no support for padata type");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_TRTYPE_NOSUPP,                        "KDCTypeSupportError",        "KDC has no support for transited type");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_CLIENT_REVOKED,                       "KDCClientRevokedError",      "Clients credentials have been revoked");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_SERVICE_REVOKED,                      "KDCServerRevokedError",      "Credentials for server have been revoked");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_TGT_REVOKED,                          "KDCTGTRevokedError",         "TGT has been revoked");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_CLIENT_NOTYET,                        "KDCClientNotYetValidError",  "Client not yet valid - try again later");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_SERVICE_NOTYET,                       "KDCServerNotYetValidError",  "Server not yet valid - try again later");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_KEY_EXP,                              "KDCPasswordExpiredError",    "Password has expired");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_PREAUTH_FAILED,                       "KDCPreauthFailedError",      "Preauthentication failed");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_PREAUTH_REQUIRED,                     "KDCPreauthRequiredError",    "Additional pre-authentication required");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_SERVER_NOMATCH,                       "KDCServerMatchError",        "Requested server and ticket don't match");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_MUST_USE_USER2USER,                   "KDCRequireUser2UserError",   "Server principal valid for user2user only");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_PATH_NOT_ACCEPTED,                    "KDCPathError",               "KDC policy rejects transited path");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_SVC_UNAVAILABLE,                      "KDCServiceUnavailableError", "A service is not available that is required to process the request");
        
        // think AP stands for authentication or application protocol ? not sure
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_BAD_INTEGRITY,                     "APIntegrityError",         "Decrypt integrity check failed");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_TKT_EXPIRED,                       "APTicketExpiredError",     "Ticket expired");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_TKT_NYV,                           "APTicketNotYetValidError", "Ticket not yet valid");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_REPEAT,                            "APReplayError",            "Request is a replay");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_NOT_US,                            "APNotUsError",             "The ticket isn't for us");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_BADMATCH,                          "APMismatchError",          "Ticket/authenticator don't match");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_SKEW,                              "APClockSkewError",         "Clock skew too great");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_BADADDR,                           "APAddressAPError",         "Incorrect net address");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_BADVERSION,                        "APVersionError",           "Protocol version mismatch");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_MSG_TYPE,                          "APMessageTypeError",       "Invalid message type");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_MODIFIED,                          "APMessageModifiedError",   "Message stream modified");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_BADORDER,                          "APMessageOrderError",      "Message out of order");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_ILL_CR_TKT,                        "APCrossRealmTicketError",  "Illegal cross-realm ticket");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_BADKEYVER,                         "APKeyVersionError",        "Key version is not available");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_NOKEY,                             "APNoKeyError",             "Service key not available");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_MUT_FAIL,                          "APMutualAuthError",        "Mutual authentication failed");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_BADDIRECTION,                      "APMessageDirectionError",  "Incorrect message direction");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_METHOD,                            "APMethodError",            "Alternative authentication method required");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_BADSEQ,                            "APSequenceError",          "Incorrect sequence number in message");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_INAPP_CKSUM,                       "APChecksumError",          "Inappropriate type of checksum in message");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_PATH_NOT_ACCEPTED,                     "APPathError",              "Policy rejects transited path");

        _pykadminerror_error_insert(module, base, KRB5KRB_ERR_RESPONSE_TOO_BIG,                     "ResponseTooBigError", "Response too big for UDP, retry with TCP");
        _pykadminerror_error_insert(module, base, KRB5KRB_ERR_GENERIC,                              "GenericError",        "Generic error (see e-text)");
        _pykadminerror_error_insert(module, base, KRB5KRB_ERR_FIELD_TOOLONG,                        "FieldTooLongError",   "Field is too long for this implementation");

        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_CLIENT_NOT_TRUSTED,                   "KDCClientNotTrustedError", "Client not trusted");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_KDC_NOT_TRUSTED,                      "KDCNotTrustedError",       "KDC not trusted");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_INVALID_SIG,                          "KDCInvalidSignatureError", "Invalid signature");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED,       "KDCKeyParamsError",        "Key parameters not accepted");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_CERTIFICATE_MISMATCH,                 "KDCCertMismatchError",     "Certificate mismatch");

        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_NO_TGT,                            "APNoTGTError", "No ticket granting ticket");

        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_WRONG_REALM,                          "KDCWrongRealmError", "Realm not local to KDC");

        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_USER_TO_USER_REQUIRED,             "APRequireUser2UserError", "User to user required");

        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE,              "KDCCertVerifyError",             "Can't verify certificate");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_INVALID_CERTIFICATE,                  "KDCCertInvalidError",            "Invalid certificate");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_REVOKED_CERTIFICATE,                  "KDCCertRevokedError",            "Revoked certificate");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN,            "KDCRevokeUnknownError",          "Revocation status unknown");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE,        "KDCRevokeUnavailabeError",       "Revocation status unavailable");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_CLIENT_NAME_MISMATCH,                 "KDCClientNameMismatchError",     "Client name mismatch");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_KDC_NAME_MISMATCH,                    "KDCNameMismatchError",           "KDC name mismatch");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE,             "KDCInconsistentKeyPurposeError", "Inconsistent key purpose");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED,          "KDCCertDigestError",             "Digest in certificate not accepted");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED,         "KDCChecksumMissingError",        "Checksum must be included");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED,   "KDCSignedDataDigestError",       "Digest in signed-data not accepted");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED,  "KDCPublicKeyEncryptionError",    "Public key encryption not supported");

        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_IAKERB_KDC_NOT_FOUND,              "APIAKERBNotFoundError",   "The IAKERB proxy could not find a KDC");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE,            "APIAKERBNoResponseError", "The KDC did not respond to the IAKERB proxy");

        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION,         "KDCUnsupportedFASTOptionError", "An unsupported critical FAST option was requested");
        _pykadminerror_error_insert(module, base, KRB5KDC_ERR_NO_ACCEPTABLE_KDF,                    "KDCNoAcceptableKDFError", "No acceptable KDF offered");

        _pykadminerror_error_insert(module, base, KRB5_ERR_RCSID,                                   "RCSIDError", "$Id$");

        _pykadminerror_error_insert(module, base, KRB5_LIBOS_BADLOCKFLAG,                           "Error", "Invalid flag for file lock mode");
        _pykadminerror_error_insert(module, base, KRB5_LIBOS_CANTREADPWD,                           "Error", "Cannot read password");
        _pykadminerror_error_insert(module, base, KRB5_LIBOS_BADPWDMATCH,                           "Error", "Password mismatch");
        _pykadminerror_error_insert(module, base, KRB5_LIBOS_PWDINTR,                               "Error", "Password read interrupted");

        _pykadminerror_error_insert(module, base, KRB5_PARSE_ILLCHAR,                               "ParseIllegalCharacterError", "Illegal character in component name");
        _pykadminerror_error_insert(module, base, KRB5_PARSE_MALFORMED,                             "ParseMalformedError",        "Malformed representation of principal");

        _pykadminerror_error_insert(module, base, KRB5_CONFIG_CANTOPEN,                             "ConifgCantOpenError", "Can't open/find Kerberos configuration file");
        _pykadminerror_error_insert(module, base, KRB5_CONFIG_BADFORMAT,                            "ConifgFormatError",   "Improper format of Kerberos configuration file");
        _pykadminerror_error_insert(module, base, KRB5_CONFIG_NOTENUFSPACE,                         "ConifgSpaceError",    "Insufficient space to return complete information");

        _pykadminerror_error_insert(module, base, KRB5_BADMSGTYPE,                                  "MessageTypeError", "Invalid message type specified for encoding");

        _pykadminerror_error_insert(module, base, KRB5_CC_BADNAME,                                  "CCBadNameError",     "Credential cache name malformed");
        _pykadminerror_error_insert(module, base, KRB5_CC_UNKNOWN_TYPE,                             "CCUnknownTypeError", "Unknown credential cache type" );
        _pykadminerror_error_insert(module, base, KRB5_CC_NOTFOUND,                                 "CCNotFoundError",    "Matching credential not found");
        _pykadminerror_error_insert(module, base, KRB5_CC_END,                                      "CCEndError",         "End of credential cache reached");

        _pykadminerror_error_insert(module, base, KRB5_NO_TKT_SUPPLIED,                             "NoTicketError", "Request did not supply a ticket");

        _pykadminerror_error_insert(module, base, KRB5KRB_AP_WRONG_PRINC,                           "APWrongPrincipalError", "Wrong principal in request");
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_TKT_INVALID,                       "APTicketFlagError",     "Ticket has invalid flag set");

        _pykadminerror_error_insert(module, base, KRB5_PRINC_NOMATCH,                               "PrincipalMismatchError",     "Requested principal and ticket don't match");
        _pykadminerror_error_insert(module, base, KRB5_KDCREP_MODIFIED,                             "KDCReplyModifiedError",      "KDC reply did not match expectations");
        _pykadminerror_error_insert(module, base, KRB5_KDCREP_SKEW,                                 "KDCReplyClockSkewError",     "Clock skew too great in KDC reply");
        _pykadminerror_error_insert(module, base, KRB5_IN_TKT_REALM_MISMATCH,                       "TicketRealmMismatchError",   "Client/server realm mismatch in initial ticket request");
        _pykadminerror_error_insert(module, base, KRB5_PROG_ETYPE_NOSUPP,                           "EncryptionSupportError",     "Program lacks support for encryption type");
        _pykadminerror_error_insert(module, base, KRB5_PROG_KEYTYPE_NOSUPP,                         "KeyTypeSupportError",        "Program lacks support for key type");
        _pykadminerror_error_insert(module, base, KRB5_WRONG_ETYPE,                                 "EncryptionTypeError",        "Requested encryption type not used in message");
        _pykadminerror_error_insert(module, base, KRB5_PROG_SUMTYPE_NOSUPP,                         "ProgamChecksumSupportError", "Program lacks support for checksum type");
        _pykadminerror_error_insert(module, base, KRB5_REALM_UNKNOWN,                               "RealmUnknownError",          "Cannot find KDC for requested realm");
        _pykadminerror_error_insert(module, base, KRB5_SERVICE_UNKNOWN,                             "ServiceUnknownError",        "Kerberos service unknown");
        _pykadminerror_error_insert(module, base, KRB5_KDC_UNREACH,                                 "ContactKDCError",            "Cannot contact any KDC for requested realm");
        _pykadminerror_error_insert(module, base, KRB5_NO_LOCALNAME,                                "LocalNameError",             "No local name found for principal name");
        _pykadminerror_error_insert(module, base, KRB5_MUTUAL_FAILED,                               "MutualAuthError",            "Mutual authentication failed");

        // Reply Cache [RC] & RC Input Output [IO] Errors
        _pykadminerror_error_insert(module, base, KRB5_RC_TYPE_EXISTS,                              "RCTypeExistsError",   "Replay cache type is already registered");
        _pykadminerror_error_insert(module, base, KRB5_RC_MALLOC,                                   "RCMallocError",       "No more memory to allocate (in replay cache code)");
        _pykadminerror_error_insert(module, base, KRB5_RC_TYPE_NOTFOUND,                            "RCTypeUnknownError",  "Replay cache type is unknown");
        _pykadminerror_error_insert(module, base, KRB5_RC_UNKNOWN,                                  "RCGenericError",      "Generic unknown RC error");
        _pykadminerror_error_insert(module, base, KRB5_RC_REPLAY,                                   "RCReplayError",       "Message is a replay");
        _pykadminerror_error_insert(module, base, KRB5_RC_IO,                                       "RCIOError",           "Replay cache I/O operation failed");
        _pykadminerror_error_insert(module, base, KRB5_RC_NOIO,                                     "RCNoIOError",         "Replay cache type does not support non-volatile storage");
        _pykadminerror_error_insert(module, base, KRB5_RC_PARSE,                                    "RCParseError",        "Replay cache name parse/format error");
        _pykadminerror_error_insert(module, base, KRB5_RC_IO_EOF,                                   "RCIOEOFError",        "End-of-file on replay cache I/O");
        _pykadminerror_error_insert(module, base, KRB5_RC_IO_MALLOC,                                "RCIOMallocError",     "No more memory to allocate (in replay cache I/O code)");
        _pykadminerror_error_insert(module, base, KRB5_RC_IO_PERM,                                  "RCIOPermissionError", "Permission denied in replay cache code");
        _pykadminerror_error_insert(module, base, KRB5_RC_IO_IO,                                    "RCIOIOError",         "I/O error in replay cache i/o code");
        _pykadminerror_error_insert(module, base, KRB5_RC_IO_UNKNOWN,                               "RCIOGenericError",    "Generic unknown RC/IO error");
        _pykadminerror_error_insert(module, base, KRB5_RC_IO_SPACE,                                 "RCIOSpaceError",      "Insufficient system space to store replay information");

        _pykadminerror_error_insert(module, base, KRB5_TRANS_CANTOPEN,                              "TranslationCantOpenError", "Can't open/find realm translation file");
        _pykadminerror_error_insert(module, base, KRB5_TRANS_BADFORMAT,                             "TranslationFormatError",   "Improper format of realm translation file");

        _pykadminerror_error_insert(module, base, KRB5_LNAME_CANTOPEN,                              "LNameCantOpenError",      "Can't open/find lname translation database");
        _pykadminerror_error_insert(module, base, KRB5_LNAME_NOTRANS,                               "LNameNoTranslationError", "No translation available for requested principal");
        _pykadminerror_error_insert(module, base, KRB5_LNAME_BADFORMAT,                             "LNameFormatError",        "Improper format of translation database entry");

        _pykadminerror_error_insert(module, base, KRB5_CRYPTO_INTERNAL,                             "CryptoInternalError", "Cryptosystem internal error");
        _pykadminerror_error_insert(module, base, KRB5_KT_BADNAME,                                  "KTNameError",         "Key table name malformed");
        _pykadminerror_error_insert(module, base, KRB5_KT_UNKNOWN_TYPE,                             "KTTypeUnknownError",  "Unknown Key table type" );
        _pykadminerror_error_insert(module, base, KRB5_KT_NOTFOUND,                                 "KTNotFoundError",     "Key table entry not found");
        _pykadminerror_error_insert(module, base, KRB5_KT_END,                                      "KTEndError",          "End of key table reached");
        _pykadminerror_error_insert(module, base, KRB5_KT_NOWRITE,                                  "KTNoWriteError",      "Cannot write to specified key table");
        _pykadminerror_error_insert(module, base, KRB5_KT_IOERR,                                    "KTIOError",           "Error writing to key table");

        _pykadminerror_error_insert(module, base, KRB5_NO_TKT_IN_RLM,                               "TicketNotInRealmError", "Cannot find ticket for requested realm");

        _pykadminerror_error_insert(module, base, KRB5DES_BAD_KEYPAR,                               "DESKeyParityError", "DES key has bad parity");
        _pykadminerror_error_insert(module, base, KRB5DES_WEAK_KEY,                                 "DESKeyWeakError",   "DES key is a weak key");

        _pykadminerror_error_insert(module, base, KRB5_BAD_ENCTYPE,                                 "EncryptionTypeError", "Bad encryption type");
        _pykadminerror_error_insert(module, base, KRB5_BAD_KEYSIZE,                                 "KeySizeError",        "Key size is incompatible with encryption type");
        _pykadminerror_error_insert(module, base, KRB5_BAD_MSIZE,                                   "MessageSizeError",    "Message size is incompatible with encryption type");
        
        _pykadminerror_error_insert(module, base, KRB5_CC_TYPE_EXISTS,                              "CCTypeExistsError", "Credentials cache type is already registered.");
        _pykadminerror_error_insert(module, base, KRB5_KT_TYPE_EXISTS,                              "KTTypeExistsError", "Key table type is already registered.");

        _pykadminerror_error_insert(module, base, KRB5_CC_IO,                                       "CCIOError",             "Credentials cache I/O operation failed XXX");
        _pykadminerror_error_insert(module, base, KRB5_FCC_PERM,                                    "CCPermissionsError",    "Credentials cache permissions incorrect");
        _pykadminerror_error_insert(module, base, KRB5_FCC_NOFILE,                                  "CCNotFoundError",       "No credentials cache found");
        _pykadminerror_error_insert(module, base, KRB5_FCC_INTERNAL,                                "CCInternalError",       "Internal credentials cache error");
        _pykadminerror_error_insert(module, base, KRB5_CC_WRITE,                                    "CCWriteError",          "Error writing to credentials cache");
        _pykadminerror_error_insert(module, base, KRB5_CC_NOMEM,                                    "CCMemoryError",         "No more memory to allocate (in credentials cache code)");
        _pykadminerror_error_insert(module, base, KRB5_CC_FORMAT,                                   "CCFormatError",         "Bad format in credentials cache");
        _pykadminerror_error_insert(module, base, KRB5_CC_NOT_KTYPE,                                "CCEncryptionTypeError", "No credentials found with supported encryption types");

        _pykadminerror_error_insert(module, base, KRB5_INVALID_FLAGS,                               "InvalidFlagsError",               "Invalid KDC option combination (library internal error)");
        _pykadminerror_error_insert(module, base, KRB5_NO_2ND_TKT,                                  "SecondTicketError",               "Request missing second ticket");
        _pykadminerror_error_insert(module, base, KRB5_NOCREDS_SUPPLIED,                            "NoCredentialsSuppliedError",      "No credentials supplied to library routine");
        _pykadminerror_error_insert(module, base, KRB5_SENDAUTH_BADAUTHVERS,                        "SendAuthVersionError",            "Bad sendauth version was sent");
        _pykadminerror_error_insert(module, base, KRB5_SENDAUTH_BADAPPLVERS,                        "SendAuthApplicationVersionError", "Bad application version was sent (via sendauth)");
        _pykadminerror_error_insert(module, base, KRB5_SENDAUTH_BADRESPONSE,                        "SendAuthResponseError",           "Bad response (during sendauth exchange)");
        _pykadminerror_error_insert(module, base, KRB5_SENDAUTH_REJECTED,                           "SendAuthRejectedError",           "Server rejected authentication (during sendauth exchange)");
        _pykadminerror_error_insert(module, base, KRB5_PREAUTH_BAD_TYPE,                            "PreauthTypeError",                "Unsupported preauthentication type");
        _pykadminerror_error_insert(module, base, KRB5_PREAUTH_NO_KEY,                              "PreauthKeyError",                 "Required preauthentication key not supplied");
        _pykadminerror_error_insert(module, base, KRB5_PREAUTH_FAILED,                              "PreauthGenericError",             "Generic preauthentication failure");
        
        _pykadminerror_error_insert(module, base, KRB5_RCACHE_BADVNO,                               "RCVserionNumberError", "Unsupported replay cache format version number");
        _pykadminerror_error_insert(module, base, KRB5_CCACHE_BADVNO,                               "CCVserionNumberError", "Unsupported credentials cache format version number");
        _pykadminerror_error_insert(module, base, KRB5_KEYTAB_BADVNO,                               "KTVersionNumberError", "Unsupported key table format version number");

        _pykadminerror_error_insert(module, base, KRB5_PROG_ATYPE_NOSUPP,                           "ProgramAddressTypeError", "Program lacks support for address type");
        
        _pykadminerror_error_insert(module, base, KRB5_RC_REQUIRED,                                 "RCRequiredError", "Message replay detection requires rcache parameter");
        
        _pykadminerror_error_insert(module, base, KRB5_ERR_BAD_HOSTNAME,                            "HostnameError",               "Hostname cannot be canonicalized");
        _pykadminerror_error_insert(module, base, KRB5_ERR_HOST_REALM_UNKNOWN,                      "HostRealmUnknownError",       "Cannot determine realm for host");
        _pykadminerror_error_insert(module, base, KRB5_SNAME_UNSUPP_NAMETYPE,                       "ServiceNameUnsupportedError", "Conversion to service principal undefined for name type");
        
        _pykadminerror_error_insert(module, base, KRB5KRB_AP_ERR_V4_REPLY,                          "APV4ReplyError", "Initial Ticket response appears to be Version 4 error");
        
        _pykadminerror_error_insert(module, base, KRB5_REALM_CANT_RESOLVE,                          "RealmResolveError",             "Cannot resolve network address for KDC in requested realm");
        _pykadminerror_error_insert(module, base, KRB5_TKT_NOT_FORWARDABLE,                         "TicketNotForwardableError",     "Requesting ticket can't get forwardable tickets");
        _pykadminerror_error_insert(module, base, KRB5_FWD_BAD_PRINCIPAL,                           "ForwardPrincipalError",         "Bad principal name while trying to forward credentials");
        _pykadminerror_error_insert(module, base, KRB5_GET_IN_TKT_LOOP,                             "GetTGTLoopError",               "Looping detected inside krb5_get_in_tkt");
        _pykadminerror_error_insert(module, base, KRB5_CONFIG_NODEFREALM,                           "ConfigNoDefaultRealmError",     "Configuration file does not specify default realm");
        _pykadminerror_error_insert(module, base, KRB5_SAM_UNSUPPORTED,                             "SAMUnsupportedError",           "Bad SAM flags in obtain_sam_padata");
        _pykadminerror_error_insert(module, base, KRB5_SAM_INVALID_ETYPE,                           "SAMInvalidEncryptionTypeError", "Invalid encryption type in SAM challenge");
        _pykadminerror_error_insert(module, base, KRB5_SAM_NO_CHECKSUM,                             "SAMNoChecksumError",            "Missing checksum in SAM challenge");
        _pykadminerror_error_insert(module, base, KRB5_SAM_BAD_CHECKSUM,                            "SAMChecksumError",              "Bad checksum in SAM challenge");
        _pykadminerror_error_insert(module, base, KRB5_KT_NAME_TOOLONG,                             "KTNameTooLongError",            "Keytab name too long");
        _pykadminerror_error_insert(module, base, KRB5_KT_KVNONOTFOUND,                             "KTKVNOError",                   "Key version number for principal in key table is incorrect");
        _pykadminerror_error_insert(module, base, KRB5_APPL_EXPIRED,                                "ApplicationExpiredError",       "This application has expired");
        _pykadminerror_error_insert(module, base, KRB5_LIB_EXPIRED,                                 "LibraryExpiredError",           "This Krb5 library has expired");
        _pykadminerror_error_insert(module, base, KRB5_CHPW_PWDNULL,                                "NullPasswordError",             "New password cannot be zero length");
        _pykadminerror_error_insert(module, base, KRB5_CHPW_FAIL,                                   "PasswordChangeError",           "Password change failed");
        _pykadminerror_error_insert(module, base, KRB5_KT_FORMAT,                                   "KTFormatError",                 "Bad format in keytab");
        _pykadminerror_error_insert(module, base, KRB5_NOPERM_ETYPE,                                "EncryptionTypeError",           "Encryption type not permitted");
        _pykadminerror_error_insert(module, base, KRB5_CONFIG_ETYPE_NOSUPP,                         "ConfigEncryptionTypeError",     "No supported encryption types (config file error?)");
        _pykadminerror_error_insert(module, base, KRB5_OBSOLETE_FN,                                 "ObsoleteFunctionError",         "Program called an obsolete, deleted function");
        
        _pykadminerror_error_insert(module, base, KRB5_EAI_FAIL,                                    "EAIGenericError",         "unknown getaddrinfo failure");
        _pykadminerror_error_insert(module, base, KRB5_EAI_NODATA,                                  "EAINoDataError",          "no data available for host/domain name");
        _pykadminerror_error_insert(module, base, KRB5_EAI_NONAME,                                  "EAINoNameError",          "host/domain name not found");
        _pykadminerror_error_insert(module, base, KRB5_EAI_SERVICE,                                 "EAIServiceUnknownError",  "service name unknown");
        _pykadminerror_error_insert(module, base, KRB5_ERR_NUMERIC_REALM,                           "NumericRealmError",       "Cannot determine realm for numeric host address");
        _pykadminerror_error_insert(module, base, KRB5_ERR_BAD_S2K_PARAMS,                          "KeyParamsError",          "Invalid key generation parameters from KDC");
        _pykadminerror_error_insert(module, base, KRB5_ERR_NO_SERVICE,                              "ServiceUnavailableError", "service not available");

        _pykadminerror_error_insert(module, base, KRB5_CC_READONLY,                                 "CCReadOnlyError",     "Ccache function not supported: read-only ccache type");
        _pykadminerror_error_insert(module, base, KRB5_CC_NOSUPP,                                   "CCNotSupportedError", "Ccache function not supported: not implemented");

        _pykadminerror_error_insert(module, base, KRB5_DELTAT_BADFORMAT,                            "DeltaFormatError",           "Invalid format of Kerberos lifetime or clock skew string");
        _pykadminerror_error_insert(module, base, KRB5_PLUGIN_NO_HANDLE,                            "PluginHandleError",          "Supplied data not handled by this plugin");
        _pykadminerror_error_insert(module, base, KRB5_PLUGIN_OP_NOTSUPP,                           "PluginSupportError",         "Plugin does not support the operation");
        _pykadminerror_error_insert(module, base, KRB5_ERR_INVALID_UTF8,                            "UTF8Error",                  "Invalid UTF-8 string");
        _pykadminerror_error_insert(module, base, KRB5_ERR_FAST_REQUIRED,                           "FASTRequiredError",          "FAST protected pre-authentication required but not supported by KDC");
        _pykadminerror_error_insert(module, base, KRB5_LOCAL_ADDR_REQUIRED,                         "LocalAddressRequiredError",  "Auth context must contain local address");
        _pykadminerror_error_insert(module, base, KRB5_REMOTE_ADDR_REQUIRED,                        "RemoteAddressRequiredError", "Auth context must contain remote address");
        _pykadminerror_error_insert(module, base, KRB5_TRACE_NOSUPP,                                "TraceSupportError",          "Tracing unsupported");
    
        result = 1;   
    }

    return result;

}



int PyKAdminError_init_kadm(PyObject *module, PyObject *base) {

    int result = 0;
    //_pykadmin_kadm_errors = PyDict_New();

    if (_pykadmin_errors) {
 
        _pykadminerror_error_insert(module, base, KADM5_FAILURE,                  "FailureError",                 "Operation failed for unspecified reason");
        _pykadminerror_error_insert(module, base, KADM5_AUTH_GET,                 "AuthGetError",                 "Operation requires ``get'' privilege");
        _pykadminerror_error_insert(module, base, KADM5_AUTH_ADD,                 "AuthAddError",                 "Operation requires ``add'' privilege");
        _pykadminerror_error_insert(module, base, KADM5_AUTH_MODIFY,              "AuthModifyError",              "Operation requires ``modify'' privilege");
        _pykadminerror_error_insert(module, base, KADM5_AUTH_DELETE,              "AuthDeleteError",              "Operation requires ``delete'' privilege");
        _pykadminerror_error_insert(module, base, KADM5_AUTH_INSUFFICIENT,        "AuthInsufficientError",        "Insufficient authorization for operation");
        _pykadminerror_error_insert(module, base, KADM5_BAD_DB,                   "DadtabaseError",               "Database inconsistency detected");
        _pykadminerror_error_insert(module, base, KADM5_DUP,                      "DuplicateError",               "Principal or policy already exists");
        _pykadminerror_error_insert(module, base, KADM5_RPC_ERROR,                "RPCErrorError",                "Communication failure with server");
        _pykadminerror_error_insert(module, base, KADM5_NO_SRV,                   "NoServerError",                "No administration server found for realm");
        _pykadminerror_error_insert(module, base, KADM5_BAD_HIST_KEY,             "HistoryKeyError",              "Password history principal key version mismatch");
        _pykadminerror_error_insert(module, base, KADM5_NOT_INIT,                 "NotInitializedError",          "Connection to server not initialized");
        _pykadminerror_error_insert(module, base, KADM5_UNK_PRINC,                "UnknownPrincipalError",        "Principal does not exist");
        _pykadminerror_error_insert(module, base, KADM5_UNK_POLICY,               "UnknownPolicyError",           "Policy does not exist");
        _pykadminerror_error_insert(module, base, KADM5_BAD_MASK,                 "MaskError",                    "Invalid field mask for operation");
        _pykadminerror_error_insert(module, base, KADM5_BAD_CLASS,                "ClassError",                   "Invalid number of character classes");
        _pykadminerror_error_insert(module, base, KADM5_BAD_LENGTH,               "LengthError",                  "Invalid password length");
        _pykadminerror_error_insert(module, base, KADM5_BAD_POLICY,               "PolicyError",                  "Illegal policy name");
        _pykadminerror_error_insert(module, base, KADM5_BAD_PRINCIPAL,            "PrincipalError",               "Illegal principal name");
        _pykadminerror_error_insert(module, base, KADM5_BAD_AUX_ATTR,             "AuxAttrError",                 "Invalid auxillary attributes");
        _pykadminerror_error_insert(module, base, KADM5_BAD_HISTORY,              "HistoryError",                 "Invalid password history count");
        _pykadminerror_error_insert(module, base, KADM5_BAD_MIN_PASS_LIFE,        "MinPasswordLifeError",         "Password minimum life is greater then password maximum life");
        _pykadminerror_error_insert(module, base, KADM5_PASS_Q_TOOSHORT,          "PasswordTooShortError",        "Password is too short");
        _pykadminerror_error_insert(module, base, KADM5_PASS_Q_CLASS,             "PasswordClassError",           "Password does not contain enough character classes");
        _pykadminerror_error_insert(module, base, KADM5_PASS_Q_DICT,              "PasswordDictError",            "Password is in the password dictionary");
        _pykadminerror_error_insert(module, base, KADM5_PASS_REUSE,               "PasswordReuseError",           "Cannot resuse password");
        _pykadminerror_error_insert(module, base, KADM5_PASS_TOOSOON,             "PasswordTooSoonError",         "Current password's minimum life has not expired");
        _pykadminerror_error_insert(module, base, KADM5_POLICY_REF,               "PolicyRefError",               "Policy is in use");
        _pykadminerror_error_insert(module, base, KADM5_INIT,                     "InitializedError",             "Connection to server already initialized");
        _pykadminerror_error_insert(module, base, KADM5_BAD_PASSWORD,             "PasswordError",                "Incorrect password");
        _pykadminerror_error_insert(module, base, KADM5_PROTECT_PRINCIPAL,        "ProtectedPrincipalError",      "Cannot change protected principal");
        _pykadminerror_error_insert(module, base, KADM5_BAD_SERVER_HANDLE,        "ServerHandleError",            "Programmer error! Bad Admin server handle");
        _pykadminerror_error_insert(module, base, KADM5_BAD_STRUCT_VERSION,       "StructVersionError",           "Programmer error! Bad API structure version");
        _pykadminerror_error_insert(module, base, KADM5_OLD_STRUCT_VERSION,       "OldStructVersionError",        "API structure version specified by application is no longer supported (to fix, recompile application against current Admin API header files and libraries)");
        _pykadminerror_error_insert(module, base, KADM5_NEW_STRUCT_VERSION,       "NewStructVersionError",        "API structure version specified by application is unknown to libraries (to fix, obtain current Admin API header files and libraries and recompile application)");
        _pykadminerror_error_insert(module, base, KADM5_BAD_API_VERSION,          "APIVersionError",              "Programmer error! Bad API version");
        _pykadminerror_error_insert(module, base, KADM5_OLD_LIB_API_VERSION,      "OldLibraryAPIVersionError",    "API version specified by application is no longer supported by libraries (to fix, update application to adhere to current API version and recompile)");
        _pykadminerror_error_insert(module, base, KADM5_OLD_SERVER_API_VERSION,   "OldServerAPIVersionError",     "API version specified by application is no longer supported by server (to fix, update application to adhere to current API version and recompile)");
        _pykadminerror_error_insert(module, base, KADM5_NEW_LIB_API_VERSION,      "NewLibraryAPIVersionError",    "API version specified by application is unknown to libraries (to fix, obtain current Admin API header files and libraries and recompile application)");
        _pykadminerror_error_insert(module, base, KADM5_NEW_SERVER_API_VERSION,   "NewServerAPIVersionError",     "API version specified by application is unknown to server (to fix, obtain and install newest Admin Server)");
        _pykadminerror_error_insert(module, base, KADM5_SECURE_PRINC_MISSING,     "SecurePrincipalMissingError",  "Database error! Required principal missing");
        _pykadminerror_error_insert(module, base, KADM5_NO_RENAME_SALT,           "NoRenameSaltError",            "The salt type of the specified principal does not support renaming");
        _pykadminerror_error_insert(module, base, KADM5_BAD_CLIENT_PARAMS,        "ClientParamsError",            "Illegal configuration parameter for remote KADM5 client");
        _pykadminerror_error_insert(module, base, KADM5_BAD_SERVER_PARAMS,        "ServerParamsError",            "Illegal configuration parameter for local KADM5 client.");
        _pykadminerror_error_insert(module, base, KADM5_AUTH_LIST,                "AuthListError",                "Operation requires ``list'' privilege");
        _pykadminerror_error_insert(module, base, KADM5_AUTH_CHANGEPW,            "AuthChangePasswordError",      "Operation requires ``change-password'' privilege");
        _pykadminerror_error_insert(module, base, KADM5_GSS_ERROR,                "GSSAPIErrorError",             "GSS-API (or Kerberos) error");
        _pykadminerror_error_insert(module, base, KADM5_BAD_TL_TYPE,              "TLTypeError",                  "Programmer error! Illegal tagged data list element type");
        _pykadminerror_error_insert(module, base, KADM5_MISSING_CONF_PARAMS,      "MissingConfParamsError",       "Required parameters in kdc.conf missing");
        _pykadminerror_error_insert(module, base, KADM5_BAD_SERVER_NAME,          "ServerNameError",              "Bad krb5 admin server hostname");
        _pykadminerror_error_insert(module, base, KADM5_AUTH_SETKEY,              "AuthSetKeyError",              "Operation requires ``set-key'' privilege");
        _pykadminerror_error_insert(module, base, KADM5_SETKEY_DUP_ENCTYPES,      "SetKeyDuplicateEnctypesError", "Multiple values for single or folded enctype");
        _pykadminerror_error_insert(module, base, KADM5_SETV4KEY_INVAL_ENCTYPE,   "Setv4KeyInvalEnctypeError",    "Invalid enctype for setv4key");
        _pykadminerror_error_insert(module, base, KADM5_SETKEY3_ETYPE_MISMATCH,   "SetKey3EnctypeMismatchError",  "Mismatched enctypes for setkey3");
        _pykadminerror_error_insert(module, base, KADM5_MISSING_KRB5_CONF_PARAMS, "MissingKrb5ConfParamsError",   "Missing parameters in krb5.conf required for kadmin client");
        _pykadminerror_error_insert(module, base, KADM5_XDR_FAILURE,              "XDRFailureError",              "XDR encoding error");
#       ifdef KADM5_CANT_RESOLVE
            _pykadminerror_error_insert(module, base, KADM5_CANT_RESOLVE,             "CantResolveError",             "");
#       endif
#       ifdef KADM5_PASS_Q_GENERIC
            _pykadminerror_error_insert(module, base, KADM5_PASS_Q_GENERIC,           "PasswordGenericError",         "Database synchronization failed");
#       endif
    
        result = 1;
    }


    return result;
}


int PyKAdminError_init_kdb(PyObject *module, PyObject *base) {

    int result = 0;
    //_pykadmin_kadm_errors = PyDict_New();

    if (_pykadmin_errors) {

        _pykadminerror_error_insert(module, base, KRB5_KDB_INUSE,                  "KDBInUseError",               "Entry already exists in database");
        _pykadminerror_error_insert(module, base, KRB5_KDB_UK_SERROR,              "KDBStoreError",               "Database store error");
        _pykadminerror_error_insert(module, base, KRB5_KDB_UK_RERROR,              "KDBReadError",                "Database read error");
        _pykadminerror_error_insert(module, base, KRB5_KDB_UNAUTH,                 "KDBInsufficientAccessError",  "Insufficient access to perform requested operation");
        _pykadminerror_error_insert(module, base, KRB5_KDB_NOENTRY,                "KDBNoEntryError",             "No such entry in the database");
        _pykadminerror_error_insert(module, base, KRB5_KDB_ILL_WILDCARD,           "KDBWildcardError",            "Illegal use of wildcard");
        _pykadminerror_error_insert(module, base, KRB5_KDB_DB_INUSE,               "KDBLockedError",              "Database is locked or in use--try again later");
        _pykadminerror_error_insert(module, base, KRB5_KDB_DB_CHANGED,             "KDBChangedError",             "Database was modified during read");
        _pykadminerror_error_insert(module, base, KRB5_KDB_TRUNCATED_RECORD,       "KDBTruncatedError",           "Database record is incomplete or corrupted");
        _pykadminerror_error_insert(module, base, KRB5_KDB_RECURSIVELOCK,          "KDBRecursiveLockError",       "Attempt to lock database twice");
        _pykadminerror_error_insert(module, base, KRB5_KDB_NOTLOCKED,              "KDBNotLockedError",           "Attempt to unlock database when not locked");
        _pykadminerror_error_insert(module, base, KRB5_KDB_BADLOCKMODE,            "KDBLockModeError",            "Invalid kdb lock mode");
        _pykadminerror_error_insert(module, base, KRB5_KDB_DBNOTINITED,            "KDBNotInitializedError",      "Database has not been initialized");
        _pykadminerror_error_insert(module, base, KRB5_KDB_DBINITED,               "KDBInitializedError",         "Database has already been initialized");
        _pykadminerror_error_insert(module, base, KRB5_KDB_ILLDIRECTION,           "KDBDirectionError",           "Bad direction for converting keys");
        _pykadminerror_error_insert(module, base, KRB5_KDB_NOMASTERKEY,            "KDBNoMKeyError",              "Cannot find master key record in database");
        _pykadminerror_error_insert(module, base, KRB5_KDB_BADMASTERKEY,           "KDBBadMKeyError",             "Master key does not match database");
        _pykadminerror_error_insert(module, base, KRB5_KDB_INVALIDKEYSIZE,         "KDBKeySizeError",             "Key size in database is invalid");
        _pykadminerror_error_insert(module, base, KRB5_KDB_CANTREAD_STORED,        "KDBCantReadError",            "Cannot find/read stored master key");
        _pykadminerror_error_insert(module, base, KRB5_KDB_BADSTORED_MKEY,         "KDBCorruptedMKeyError",       "Stored master key is corrupted");
        _pykadminerror_error_insert(module, base, KRB5_KDB_NOACTMASTERKEY,         "KDBNoActiveMKeyError",        "Cannot find active master key");
        _pykadminerror_error_insert(module, base, KRB5_KDB_KVNONOMATCH,            "KDBMKeyMismatchError",        "KVNO of new master key does not match expected value");
        _pykadminerror_error_insert(module, base, KRB5_KDB_STORED_MKEY_NOTCURRENT, "KDBMKeyNotCurrentError",      "Stored master key is not current");
        _pykadminerror_error_insert(module, base, KRB5_KDB_CANTLOCK_DB,            "KDBCantLockError",            "Insufficient access to lock database");
        _pykadminerror_error_insert(module, base, KRB5_KDB_DB_CORRUPT,             "KDBFormatError",              "Database format error");
        _pykadminerror_error_insert(module, base, KRB5_KDB_BAD_VERSION,            "KDBVersionError",             "Unsupported version in database entry");
        _pykadminerror_error_insert(module, base, KRB5_KDB_BAD_SALTTYPE,           "KDBSaltSupportError",         "Unsupported salt type");
        _pykadminerror_error_insert(module, base, KRB5_KDB_BAD_ENCTYPE,            "KDBEncryptionSupportError",   "Unsupported encryption type");
        _pykadminerror_error_insert(module, base, KRB5_KDB_BAD_CREATEFLAGS,        "KDBCreateFlagsError",         "Bad database creation flags");
        _pykadminerror_error_insert(module, base, KRB5_KDB_NO_PERMITTED_KEY,       "KDBNoPermittedKeyError",      "No matching key in entry having a permitted enctype");
        _pykadminerror_error_insert(module, base, KRB5_KDB_NO_MATCHING_KEY,        "KDBNoMatchingKeyError",       "No matching key in entry");
        _pykadminerror_error_insert(module, base, KRB5_KDB_DBTYPE_NOTFOUND,        "KDBTypeNotFoundError",        "Unable to find requested database type");
        _pykadminerror_error_insert(module, base, KRB5_KDB_DBTYPE_NOSUP,           "KDBTypeSupportError",         "Database type not supported");
        _pykadminerror_error_insert(module, base, KRB5_KDB_DBTYPE_INIT,            "KDBTypeInitializeError",      "Database library failed to initialize");
        _pykadminerror_error_insert(module, base, KRB5_KDB_SERVER_INTERNAL_ERR,    "KDBServerError",              "Server error");
        _pykadminerror_error_insert(module, base, KRB5_KDB_ACCESS_ERROR,           "KDBAccessError",              "Unable to access Kerberos database");
        _pykadminerror_error_insert(module, base, KRB5_KDB_INTERNAL_ERROR,         "KDBInternalError",            "Kerberos database internal error");
        _pykadminerror_error_insert(module, base, KRB5_KDB_CONSTRAINT_VIOLATION,   "KDBConstraintViolationError", "Kerberos database constraints violated");

        _pykadminerror_error_insert(module, base, KRB5_LOG_CONV,                   "LOGUpdateConversionError",    "Update log conversion error");
        _pykadminerror_error_insert(module, base, KRB5_LOG_UNSTABLE,               "LOGUnstableError",            "Update log is unstable");
        _pykadminerror_error_insert(module, base, KRB5_LOG_CORRUPT,                "LOGCorruptError",             "Update log is corrupt");
        _pykadminerror_error_insert(module, base, KRB5_LOG_ERROR,                  "LOGGenericError",             "Generic update log error");

        _pykadminerror_error_insert(module, base, KRB5_KDB_DBTYPE_MISMATCH,        "KDBTypeMismatchError",        "Database module does not match KDC version");
        _pykadminerror_error_insert(module, base, KRB5_KDB_POLICY_REF,             "KDBPolicyError",              "Policy is in use");
        _pykadminerror_error_insert(module, base, KRB5_KDB_STRINGS_TOOLONG,        "KDBStringsTooLongError",      "Too much string mapping data");


        result = 1;
    }


    return result;
}
