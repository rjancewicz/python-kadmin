
#include "PyKAdminErrors.h"

static PyObject *_pykadmin_kadm_errors; 
static PyObject *_pykadmin_krb5_errors;


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
            error_string = PyString_FromString(caller);
        }

        PyDict_SetItemString(error_dict, kERROR_STRING, error_string);

        if (!error_object) {
            error_object = PyKAdminError_base;
        }

        PyErr_SetObject(error_object, error_dict);

    }

    Py_XDECREF(error_dict);

}

void PyKAdminError_raise_krb5_error(krb5_error_code code, char *caller) {
    PyObject *error  = PyLong_FromLong(code);
    _PyKAdminError_raise_exception(_pykadmin_krb5_errors, error, caller);
}

void PyKAdminError_raise_kadm_error(kadm5_ret_t retval, char *caller) {
    PyObject *error  = PyLong_FromUnsignedLong(retval);
    _PyKAdminError_raise_exception(_pykadmin_kadm_errors, error, caller);
}



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



static int PyKAdminError_krb5_insert(PyObject *module, krb5_error_code code, char *name, char *message) {
    
    int result       = 0; 
    char *cname      = NULL;
    size_t length    = strlen(kMODULE_NAME) + strlen(name) + 0xF;
    PyObject *error  = PyLong_FromLong(code);

    if (error) {

        cname = malloc(length);

        if (cname) { 
            snprintf(cname, length, "%s.%s", kMODULE_NAME, name);
            result = PyKAdminErrors_new_exception(module, PyKAdminError_krb5, _pykadmin_krb5_errors, error, name, cname, message);
            free(cname);
        }
    }

    return result;
}


static int PyKAdminError_kadm_insert(PyObject *module, kadm5_ret_t retval, char *name, char *message) {
    
    int result       = 0; 
    char *cname      = NULL;
    size_t length    = strlen(kMODULE_NAME) + strlen(name) + 0xF;
    PyObject *error  = PyLong_FromUnsignedLong(retval);

    if (error) {

        cname = malloc(length);

        if (cname) { 
            snprintf(cname, length, "%s.%s", kMODULE_NAME, name);
            result = PyKAdminErrors_new_exception(module, PyKAdminError_kadm, _pykadmin_kadm_errors, error, name, cname, message);
            free(cname);
        }
    }

    return result;
}




int PyKAdminError_init_krb5(PyObject *module) {

    int result = 0; 
    _pykadmin_krb5_errors = PyDict_New();

    if (_pykadmin_krb5_errors) {

        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_NONE,                                 "KDCNoneError",               "No error");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_NAME_EXP,                             "KDCClientExpiredError",      "Client's entry in database has expired");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_SERVICE_EXP,                          "KDCServerExpireError",       "Server's entry in database has expired");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_BAD_PVNO,                             "KDCProtocolVersionError",    "Requested protocol version not supported");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_C_OLD_MAST_KVNO,                      "KDCClientOldMasterKeyError", "Client's key is encrypted in an old master key");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_S_OLD_MAST_KVNO,                      "KDCServerOldMasterKeyError", "Server's key is encrypted in an old master key");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN,                  "KDCClientNotFoundError",     "Client not found in Kerberos database");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN,                  "KDCServerNotFoundError",     "Server not found in Kerberos database");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE,                 "KDCPrincipalUniqueError",    "Principal has multiple entries in Kerberos database");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_NULL_KEY,                             "KDCNullKeyError",            "Client or server has a null key");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_CANNOT_POSTDATE,                      "KDCCannotPostdateError",     "Ticket is ineligible for postdating");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_NEVER_VALID,                          "KDCNeverValidError",         "Requested effective lifetime is negative or too short");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_POLICY,                               "KDCPolicyError",             "KDC policy rejects request");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_BADOPTION,                            "KDCOptionError",             "KDC can't fulfill requested option");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_ETYPE_NOSUPP,                         "KDCEncryptionSupportError",  "KDC has no support for encryption type");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_SUMTYPE_NOSUPP,                       "KDCChecksumSupportError",    "KDC has no support for checksum type");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_PADATA_TYPE_NOSUPP,                   "KDCPADataSupportError",      "KDC has no support for padata type");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_TRTYPE_NOSUPP,                        "KDCTypeSupportError",        "KDC has no support for transited type");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_CLIENT_REVOKED,                       "KDCClientRevokedError",      "Clients credentials have been revoked");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_SERVICE_REVOKED,                      "KDCServerRevokedError",      "Credentials for server have been revoked");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_TGT_REVOKED,                          "KDCTGTRevokedError",         "TGT has been revoked");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_CLIENT_NOTYET,                        "KDCClientNotYetValidError",  "Client not yet valid - try again later");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_SERVICE_NOTYET,                       "KDCServerNotYetValidError",  "Server not yet valid - try again later");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_KEY_EXP,                              "KDCPasswordExpiredError",    "Password has expired");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_PREAUTH_FAILED,                       "KDCPreauthFailedError",      "Preauthentication failed");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_PREAUTH_REQUIRED,                     "KDCPreauthRequiredError",    "Additional pre-authentication required");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_SERVER_NOMATCH,                       "KDCServerMatchError",        "Requested server and ticket don't match");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_MUST_USE_USER2USER,                   "KDCRequireUser2UserError",   "Server principal valid for user2user only");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_PATH_NOT_ACCEPTED,                    "KDCPathError",               "KDC policy rejects transited path");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_SVC_UNAVAILABLE,                      "KDCServiceUnavailableError", "A service is not available that is required to process the request");
        
        // think AP stands for authentication or application protocol ? not sure
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_BAD_INTEGRITY,                     "APIntegrityError",         "Decrypt integrity check failed");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_TKT_EXPIRED,                       "APTicketExpiredError",     "Ticket expired");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_TKT_NYV,                           "APTicketNotYetValidError", "Ticket not yet valid");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_REPEAT,                            "APReplayError",            "Request is a replay");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_NOT_US,                            "APNotUsError",             "The ticket isn't for us");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_BADMATCH,                          "APMismatchError",          "Ticket/authenticator don't match");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_SKEW,                              "APClockSkewError",         "Clock skew too great");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_BADADDR,                           "APAddressAPError",         "Incorrect net address");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_BADVERSION,                        "APVersionError",           "Protocol version mismatch");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_MSG_TYPE,                          "APMessageTypeError",       "Invalid message type");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_MODIFIED,                          "APMessageModifiedError",   "Message stream modified");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_BADORDER,                          "APMessageOrderError",      "Message out of order");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_ILL_CR_TKT,                        "APCrossRealmTicketError",  "Illegal cross-realm ticket");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_BADKEYVER,                         "APKeyVersionError",        "Key version is not available");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_NOKEY,                             "APNoKeyError",             "Service key not available");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_MUT_FAIL,                          "APMutualAuthError",        "Mutual authentication failed");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_BADDIRECTION,                      "APMessageDirectionError",  "Incorrect message direction");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_METHOD,                            "APMethodError",            "Alternative authentication method required");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_BADSEQ,                            "APSequenceError",          "Incorrect sequence number in message");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_INAPP_CKSUM,                       "APChecksumError",          "Inappropriate type of checksum in message");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_PATH_NOT_ACCEPTED,                     "APPathError",              "Policy rejects transited path");

        PyKAdminError_krb5_insert(module, KRB5KRB_ERR_RESPONSE_TOO_BIG,                     "ResponseTooBigError", "Response too big for UDP, retry with TCP");
        PyKAdminError_krb5_insert(module, KRB5KRB_ERR_GENERIC,                              "GenericError",        "Generic error (see e-text)");
        PyKAdminError_krb5_insert(module, KRB5KRB_ERR_FIELD_TOOLONG,                        "FieldTooLongError",   "Field is too long for this implementation");

        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_CLIENT_NOT_TRUSTED,                   "KDCClientNotTrustedError", "Client not trusted");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_KDC_NOT_TRUSTED,                      "KDCNotTrustedError",       "KDC not trusted");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_INVALID_SIG,                          "KDCInvalidSignatureError", "Invalid signature");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED,       "KDCKeyParametersError",    "Key parameters not accepted");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_CERTIFICATE_MISMATCH,                 "KDCCertMismatchError",     "Certificate mismatch");

        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_NO_TGT,                            "APNoTGTError", "No ticket granting ticket");

        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_WRONG_REALM,                          "KDCWrongRealmError", "Realm not local to KDC");

        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_USER_TO_USER_REQUIRED,             "APRequireUser2UserError", "User to user required");

        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE,              "KDCCertVerifyError",             "Can't verify certificate");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_INVALID_CERTIFICATE,                  "KDCCertInvalidError",            "Invalid certificate");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_REVOKED_CERTIFICATE,                  "KDCCertRevokedError",            "Revoked certificate");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN,            "KDCRevokeUnknownError",          "Revocation status unknown");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE,        "KDCRevokeUnavailabeError",       "Revocation status unavailable");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_CLIENT_NAME_MISMATCH,                 "KDCClientNameMismatchError",     "Client name mismatch");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_KDC_NAME_MISMATCH,                    "KDCNameMismatchError",           "KDC name mismatch");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE,             "KDCInconsistentKeyPurposeError", "Inconsistent key purpose");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED,          "KDCCertDigestError",             "Digest in certificate not accepted");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED,         "KDCChecksumMissingError",        "Checksum must be included");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED,   "KDCSignedDataDigestError",       "Digest in signed-data not accepted");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED,  "KDCPublicKeyEncryptionError",    "Public key encryption not supported");

        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_IAKERB_KDC_NOT_FOUND,              "APIAKERBNotFoundError",   "The IAKERB proxy could not find a KDC");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE,            "APIAKERBNoResponseError", "The KDC did not respond to the IAKERB proxy");

        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION,         "KDCUnsupportedFASTOptionError", "An unsupported critical FAST option was requested");
        PyKAdminError_krb5_insert(module, KRB5KDC_ERR_NO_ACCEPTABLE_KDF,                    "KDCNoAcceptableKDFError", "No acceptable KDF offered");

        PyKAdminError_krb5_insert(module, KRB5_ERR_RCSID,                                   "RCSIDError", "$Id$");

        PyKAdminError_krb5_insert(module, KRB5_LIBOS_BADLOCKFLAG,                           "Error", "Invalid flag for file lock mode");
        PyKAdminError_krb5_insert(module, KRB5_LIBOS_CANTREADPWD,                           "Error", "Cannot read password");
        PyKAdminError_krb5_insert(module, KRB5_LIBOS_BADPWDMATCH,                           "Error", "Password mismatch");
        PyKAdminError_krb5_insert(module, KRB5_LIBOS_PWDINTR,                               "Error", "Password read interrupted");

        PyKAdminError_krb5_insert(module, KRB5_PARSE_ILLCHAR,                               "ParseIllegalCharacterError", "Illegal character in component name");
        PyKAdminError_krb5_insert(module, KRB5_PARSE_MALFORMED,                             "ParseMalformedError",        "Malformed representation of principal");

        PyKAdminError_krb5_insert(module, KRB5_CONFIG_CANTOPEN,                             "ConifgCantOpenError", "Can't open/find Kerberos configuration file");
        PyKAdminError_krb5_insert(module, KRB5_CONFIG_BADFORMAT,                            "ConifgFormatError",   "Improper format of Kerberos configuration file");
        PyKAdminError_krb5_insert(module, KRB5_CONFIG_NOTENUFSPACE,                         "ConifgSpaceError",    "Insufficient space to return complete information");

        PyKAdminError_krb5_insert(module, KRB5_BADMSGTYPE,                                  "MessageTypeError", "Invalid message type specified for encoding");

        PyKAdminError_krb5_insert(module, KRB5_CC_BADNAME,                                  "CCBadNameError",     "Credential cache name malformed");
        PyKAdminError_krb5_insert(module, KRB5_CC_UNKNOWN_TYPE,                             "CCUnknownTypeError", "Unknown credential cache type" );
        PyKAdminError_krb5_insert(module, KRB5_CC_NOTFOUND,                                 "CCNotFoundError",    "Matching credential not found");
        PyKAdminError_krb5_insert(module, KRB5_CC_END,                                      "CCEndError",         "End of credential cache reached");

        PyKAdminError_krb5_insert(module, KRB5_NO_TKT_SUPPLIED,                             "NoTicketError", "Request did not supply a ticket");

        PyKAdminError_krb5_insert(module, KRB5KRB_AP_WRONG_PRINC,                           "APWrongPrincipalError", "Wrong principal in request");
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_TKT_INVALID,                       "APTicketFlagError",     "Ticket has invalid flag set");

        PyKAdminError_krb5_insert(module, KRB5_PRINC_NOMATCH,                               "PrincipalMismatchError",     "Requested principal and ticket don't match");
        PyKAdminError_krb5_insert(module, KRB5_KDCREP_MODIFIED,                             "KDCReplyModifiedError",      "KDC reply did not match expectations");
        PyKAdminError_krb5_insert(module, KRB5_KDCREP_SKEW,                                 "KDCReplyClockSkewError",     "Clock skew too great in KDC reply");
        PyKAdminError_krb5_insert(module, KRB5_IN_TKT_REALM_MISMATCH,                       "TicketRealmMismatchError",   "Client/server realm mismatch in initial ticket request");
        PyKAdminError_krb5_insert(module, KRB5_PROG_ETYPE_NOSUPP,                           "EncryptionSupportError",     "Program lacks support for encryption type");
        PyKAdminError_krb5_insert(module, KRB5_PROG_KEYTYPE_NOSUPP,                         "KeyTypeSupportError",        "Program lacks support for key type");
        PyKAdminError_krb5_insert(module, KRB5_WRONG_ETYPE,                                 "EncryptionTypeError",        "Requested encryption type not used in message");
        PyKAdminError_krb5_insert(module, KRB5_PROG_SUMTYPE_NOSUPP,                         "ProgamChecksumSupportError", "Program lacks support for checksum type");
        PyKAdminError_krb5_insert(module, KRB5_REALM_UNKNOWN,                               "RealmUnknownError",          "Cannot find KDC for requested realm");
        PyKAdminError_krb5_insert(module, KRB5_SERVICE_UNKNOWN,                             "ServiceUnknownError",        "Kerberos service unknown");
        PyKAdminError_krb5_insert(module, KRB5_KDC_UNREACH,                                 "ContactKDCError",            "Cannot contact any KDC for requested realm");
        PyKAdminError_krb5_insert(module, KRB5_NO_LOCALNAME,                                "LocalNameError",             "No local name found for principal name");
        PyKAdminError_krb5_insert(module, KRB5_MUTUAL_FAILED,                               "MutualAuthError",            "Mutual authentication failed");

        // Reply Cache [RC] & RC Input Output [IO] Errors
        PyKAdminError_krb5_insert(module, KRB5_RC_TYPE_EXISTS,                              "RCTypeExistsError",   "Replay cache type is already registered");
        PyKAdminError_krb5_insert(module, KRB5_RC_MALLOC,                                   "RCMallocError",       "No more memory to allocate (in replay cache code)");
        PyKAdminError_krb5_insert(module, KRB5_RC_TYPE_NOTFOUND,                            "RCTypeUnknownError",  "Replay cache type is unknown");
        PyKAdminError_krb5_insert(module, KRB5_RC_UNKNOWN,                                  "RCGenericError",      "Generic unknown RC error");
        PyKAdminError_krb5_insert(module, KRB5_RC_REPLAY,                                   "RCReplayError",       "Message is a replay");
        PyKAdminError_krb5_insert(module, KRB5_RC_IO,                                       "RCIOError",           "Replay cache I/O operation failed");
        PyKAdminError_krb5_insert(module, KRB5_RC_NOIO,                                     "RCNoIOError",         "Replay cache type does not support non-volatile storage");
        PyKAdminError_krb5_insert(module, KRB5_RC_PARSE,                                    "RCParseError",        "Replay cache name parse/format error");
        PyKAdminError_krb5_insert(module, KRB5_RC_IO_EOF,                                   "RCIOEOFError",        "End-of-file on replay cache I/O");
        PyKAdminError_krb5_insert(module, KRB5_RC_IO_MALLOC,                                "RCIOMallocError",     "No more memory to allocate (in replay cache I/O code)");
        PyKAdminError_krb5_insert(module, KRB5_RC_IO_PERM,                                  "RCIOPermissionError", "Permission denied in replay cache code");
        PyKAdminError_krb5_insert(module, KRB5_RC_IO_IO,                                    "RCIOIOError",         "I/O error in replay cache i/o code");
        PyKAdminError_krb5_insert(module, KRB5_RC_IO_UNKNOWN,                               "RCIOGenericError",    "Generic unknown RC/IO error");
        PyKAdminError_krb5_insert(module, KRB5_RC_IO_SPACE,                                 "RCIOSpaceError",      "Insufficient system space to store replay information");

        PyKAdminError_krb5_insert(module, KRB5_TRANS_CANTOPEN,                              "TranslationCantOpenError", "Can't open/find realm translation file");
        PyKAdminError_krb5_insert(module, KRB5_TRANS_BADFORMAT,                             "TranslationFormatError",   "Improper format of realm translation file");

        PyKAdminError_krb5_insert(module, KRB5_LNAME_CANTOPEN,                              "LNameCantOpenError",      "Can't open/find lname translation database");
        PyKAdminError_krb5_insert(module, KRB5_LNAME_NOTRANS,                               "LNameNoTranslationError", "No translation available for requested principal");
        PyKAdminError_krb5_insert(module, KRB5_LNAME_BADFORMAT,                             "LNameFormatError",        "Improper format of translation database entry");

        PyKAdminError_krb5_insert(module, KRB5_CRYPTO_INTERNAL,                             "CryptoInternalError", "Cryptosystem internal error");
        PyKAdminError_krb5_insert(module, KRB5_KT_BADNAME,                                  "KTNameError",         "Key table name malformed");
        PyKAdminError_krb5_insert(module, KRB5_KT_UNKNOWN_TYPE,                             "KTTypeUnknownError",  "Unknown Key table type" );
        PyKAdminError_krb5_insert(module, KRB5_KT_NOTFOUND,                                 "KTNotFoundError",     "Key table entry not found");
        PyKAdminError_krb5_insert(module, KRB5_KT_END,                                      "KTEndError",          "End of key table reached");
        PyKAdminError_krb5_insert(module, KRB5_KT_NOWRITE,                                  "KTNoWriteError",      "Cannot write to specified key table");
        PyKAdminError_krb5_insert(module, KRB5_KT_IOERR,                                    "KTIOError",           "Error writing to key table");

        PyKAdminError_krb5_insert(module, KRB5_NO_TKT_IN_RLM,                               "TicketNotInRealmError", "Cannot find ticket for requested realm");

        PyKAdminError_krb5_insert(module, KRB5DES_BAD_KEYPAR,                               "DESKeyParityError", "DES key has bad parity");
        PyKAdminError_krb5_insert(module, KRB5DES_WEAK_KEY,                                 "DESKeyWeakError",   "DES key is a weak key");

        PyKAdminError_krb5_insert(module, KRB5_BAD_ENCTYPE,                                 "EncryptionTypeError", "Bad encryption type");
        PyKAdminError_krb5_insert(module, KRB5_BAD_KEYSIZE,                                 "KeySizeError",        "Key size is incompatible with encryption type");
        PyKAdminError_krb5_insert(module, KRB5_BAD_MSIZE,                                   "MessageSizeError",    "Message size is incompatible with encryption type");
        
        PyKAdminError_krb5_insert(module, KRB5_CC_TYPE_EXISTS,                              "CCTypeExistsError", "Credentials cache type is already registered.");
        PyKAdminError_krb5_insert(module, KRB5_KT_TYPE_EXISTS,                              "KTTypeExistsError", "Key table type is already registered.");

        PyKAdminError_krb5_insert(module, KRB5_CC_IO,                                       "CCIOError",             "Credentials cache I/O operation failed XXX");
        PyKAdminError_krb5_insert(module, KRB5_FCC_PERM,                                    "CCPermissionsError",    "Credentials cache permissions incorrect");
        PyKAdminError_krb5_insert(module, KRB5_FCC_NOFILE,                                  "CCNotFoundError",       "No credentials cache found");
        PyKAdminError_krb5_insert(module, KRB5_FCC_INTERNAL,                                "CCInternalError",       "Internal credentials cache error");
        PyKAdminError_krb5_insert(module, KRB5_CC_WRITE,                                    "CCWriteError",          "Error writing to credentials cache");
        PyKAdminError_krb5_insert(module, KRB5_CC_NOMEM,                                    "CCMemoryError",         "No more memory to allocate (in credentials cache code)");
        PyKAdminError_krb5_insert(module, KRB5_CC_FORMAT,                                   "CCFormatError",         "Bad format in credentials cache");
        PyKAdminError_krb5_insert(module, KRB5_CC_NOT_KTYPE,                                "CCEncryptionTypeError", "No credentials found with supported encryption types");

        PyKAdminError_krb5_insert(module, KRB5_INVALID_FLAGS,                               "InvalidFlagsError",               "Invalid KDC option combination (library internal error)");
        PyKAdminError_krb5_insert(module, KRB5_NO_2ND_TKT,                                  "SecondTicketError",               "Request missing second ticket");
        PyKAdminError_krb5_insert(module, KRB5_NOCREDS_SUPPLIED,                            "NoCredentialsSuppliedError",      "No credentials supplied to library routine");
        PyKAdminError_krb5_insert(module, KRB5_SENDAUTH_BADAUTHVERS,                        "SendAuthVersionError",            "Bad sendauth version was sent");
        PyKAdminError_krb5_insert(module, KRB5_SENDAUTH_BADAPPLVERS,                        "SendAuthApplicationVersionError", "Bad application version was sent (via sendauth)");
        PyKAdminError_krb5_insert(module, KRB5_SENDAUTH_BADRESPONSE,                        "SendAuthResponseError",           "Bad response (during sendauth exchange)");
        PyKAdminError_krb5_insert(module, KRB5_SENDAUTH_REJECTED,                           "SendAuthRejectedError",           "Server rejected authentication (during sendauth exchange)");
        PyKAdminError_krb5_insert(module, KRB5_PREAUTH_BAD_TYPE,                            "PreauthTypeError",                "Unsupported preauthentication type");
        PyKAdminError_krb5_insert(module, KRB5_PREAUTH_NO_KEY,                              "PreauthKeyError",                 "Required preauthentication key not supplied");
        PyKAdminError_krb5_insert(module, KRB5_PREAUTH_FAILED,                              "PreauthGenericError",             "Generic preauthentication failure");
        
        PyKAdminError_krb5_insert(module, KRB5_RCACHE_BADVNO,                               "RCVserionNumberError", "Unsupported replay cache format version number");
        PyKAdminError_krb5_insert(module, KRB5_CCACHE_BADVNO,                               "CCVserionNumberError", "Unsupported credentials cache format version number");
        PyKAdminError_krb5_insert(module, KRB5_KEYTAB_BADVNO,                               "KTVersionNumberError", "Unsupported key table format version number");

        PyKAdminError_krb5_insert(module, KRB5_PROG_ATYPE_NOSUPP,                           "ProgramAddressTypeError", "Program lacks support for address type");
        
        PyKAdminError_krb5_insert(module, KRB5_RC_REQUIRED,                                 "RCRequiredError", "Message replay detection requires rcache parameter");
        
        PyKAdminError_krb5_insert(module, KRB5_ERR_BAD_HOSTNAME,                            "HostnameError",               "Hostname cannot be canonicalized");
        PyKAdminError_krb5_insert(module, KRB5_ERR_HOST_REALM_UNKNOWN,                      "HostRealmUnknownError",       "Cannot determine realm for host");
        PyKAdminError_krb5_insert(module, KRB5_SNAME_UNSUPP_NAMETYPE,                       "ServiceNameUnsupportedError", "Conversion to service principal undefined for name type");
        
        PyKAdminError_krb5_insert(module, KRB5KRB_AP_ERR_V4_REPLY,                          "APV4ReplyError", "Initial Ticket response appears to be Version 4 error");
        
        PyKAdminError_krb5_insert(module, KRB5_REALM_CANT_RESOLVE,                          "RealmResolveError",             "Cannot resolve network address for KDC in requested realm");
        PyKAdminError_krb5_insert(module, KRB5_TKT_NOT_FORWARDABLE,                         "TicketNotForwardableError",     "Requesting ticket can't get forwardable tickets");
        PyKAdminError_krb5_insert(module, KRB5_FWD_BAD_PRINCIPAL,                           "ForwardPrincipalError",         "Bad principal name while trying to forward credentials");
        PyKAdminError_krb5_insert(module, KRB5_GET_IN_TKT_LOOP,                             "GetTGTLoopError",               "Looping detected inside krb5_get_in_tkt");
        PyKAdminError_krb5_insert(module, KRB5_CONFIG_NODEFREALM,                           "ConfigNoDefaultRealmError",     "Configuration file does not specify default realm");
        PyKAdminError_krb5_insert(module, KRB5_SAM_UNSUPPORTED,                             "SAMUnsupportedError",           "Bad SAM flags in obtain_sam_padata");
        PyKAdminError_krb5_insert(module, KRB5_SAM_INVALID_ETYPE,                           "SAMInvalidEncryptionTypeError", "Invalid encryption type in SAM challenge");
        PyKAdminError_krb5_insert(module, KRB5_SAM_NO_CHECKSUM,                             "SAMNoChecksumError",            "Missing checksum in SAM challenge");
        PyKAdminError_krb5_insert(module, KRB5_SAM_BAD_CHECKSUM,                            "SAMChecksumError",              "Bad checksum in SAM challenge");
        PyKAdminError_krb5_insert(module, KRB5_KT_NAME_TOOLONG,                             "KTNameTooLongError",            "Keytab name too long");
        PyKAdminError_krb5_insert(module, KRB5_KT_KVNONOTFOUND,                             "KTKVNOError",                   "Key version number for principal in key table is incorrect");
        PyKAdminError_krb5_insert(module, KRB5_APPL_EXPIRED,                                "ApplicationExpiredError",       "This application has expired");
        PyKAdminError_krb5_insert(module, KRB5_LIB_EXPIRED,                                 "LibraryExpiredError",           "This Krb5 library has expired");
        PyKAdminError_krb5_insert(module, KRB5_CHPW_PWDNULL,                                "NullPasswordError",             "New password cannot be zero length");
        PyKAdminError_krb5_insert(module, KRB5_CHPW_FAIL,                                   "PasswordChangeError",           "Password change failed");
        PyKAdminError_krb5_insert(module, KRB5_KT_FORMAT,                                   "KTFormatError",                 "Bad format in keytab");
        PyKAdminError_krb5_insert(module, KRB5_NOPERM_ETYPE,                                "EncryptionTypeError",           "Encryption type not permitted");
        PyKAdminError_krb5_insert(module, KRB5_CONFIG_ETYPE_NOSUPP,                         "ConfigEncryptionTypeError",     "No supported encryption types (config file error?)");
        PyKAdminError_krb5_insert(module, KRB5_OBSOLETE_FN,                                 "ObsoleteFunctionError",         "Program called an obsolete, deleted function");
        
        PyKAdminError_krb5_insert(module, KRB5_EAI_FAIL,                                    "EAIGenericError",         "unknown getaddrinfo failure");
        PyKAdminError_krb5_insert(module, KRB5_EAI_NODATA,                                  "EAINoDataError",          "no data available for host/domain name");
        PyKAdminError_krb5_insert(module, KRB5_EAI_NONAME,                                  "EAINoNameError",          "host/domain name not found");
        PyKAdminError_krb5_insert(module, KRB5_EAI_SERVICE,                                 "EAIServiceUnknownError",  "service name unknown");
        PyKAdminError_krb5_insert(module, KRB5_ERR_NUMERIC_REALM,                           "NumericRealmError",       "Cannot determine realm for numeric host address");
        PyKAdminError_krb5_insert(module, KRB5_ERR_BAD_S2K_PARAMS,                          "KeyParametersError",      "Invalid key generation parameters from KDC");
        PyKAdminError_krb5_insert(module, KRB5_ERR_NO_SERVICE,                              "ServiceUnavailableError", "service not available");

        PyKAdminError_krb5_insert(module, KRB5_CC_READONLY,                                 "CCReadOnlyError",     "Ccache function not supported: read-only ccache type");
        PyKAdminError_krb5_insert(module, KRB5_CC_NOSUPP,                                   "CCNotSupportedError", "Ccache function not supported: not implemented");

        PyKAdminError_krb5_insert(module, KRB5_DELTAT_BADFORMAT,                            "DeltaFormatError",           "Invalid format of Kerberos lifetime or clock skew string");
        PyKAdminError_krb5_insert(module, KRB5_PLUGIN_NO_HANDLE,                            "PluginHandleError",          "Supplied data not handled by this plugin");
        PyKAdminError_krb5_insert(module, KRB5_PLUGIN_OP_NOTSUPP,                           "PluginSupportError",         "Plugin does not support the operation");
        PyKAdminError_krb5_insert(module, KRB5_ERR_INVALID_UTF8,                            "UTF8Error",                  "Invalid UTF-8 string");
        PyKAdminError_krb5_insert(module, KRB5_ERR_FAST_REQUIRED,                           "FASTRequiredError",          "FAST protected pre-authentication required but not supported by KDC");
        PyKAdminError_krb5_insert(module, KRB5_LOCAL_ADDR_REQUIRED,                         "LocalAddressRequiredError",  "Auth context must contain local address");
        PyKAdminError_krb5_insert(module, KRB5_REMOTE_ADDR_REQUIRED,                        "RemoteAddressRequiredError", "Auth context must contain remote address");
        PyKAdminError_krb5_insert(module, KRB5_TRACE_NOSUPP,                                "TraceSupportError",          "Tracing unsupported");
    
        result = 1;   
    }

    return result;

}



int PyKAdminError_init_kadm(PyObject *module) {

    int result = 0;
    _pykadmin_kadm_errors = PyDict_New();

    if (_pykadmin_kadm_errors) {
 
        PyKAdminError_kadm_insert(module, KADM5_FAILURE,                  "FailureError",                 "Operation failed for unspecified reason");
        PyKAdminError_kadm_insert(module, KADM5_AUTH_GET,                 "AuthGetError",                 "Operation requires ``get'' privilege");
        PyKAdminError_kadm_insert(module, KADM5_AUTH_ADD,                 "AuthAddError",                 "Operation requires ``add'' privilege");
        PyKAdminError_kadm_insert(module, KADM5_AUTH_MODIFY,              "AuthModifyError",              "Operation requires ``modify'' privilege");
        PyKAdminError_kadm_insert(module, KADM5_AUTH_DELETE,              "AuthDeleteError",              "Operation requires ``delete'' privilege");
        PyKAdminError_kadm_insert(module, KADM5_AUTH_INSUFFICIENT,        "AuthInsufficientError",        "Insufficient authorization for operation");
        PyKAdminError_kadm_insert(module, KADM5_BAD_DB,                   "BadDadtabaseError",            "Database inconsistency detected");
        PyKAdminError_kadm_insert(module, KADM5_DUP,                      "DuplicateError",               "Principal or policy already exists");
        PyKAdminError_kadm_insert(module, KADM5_RPC_ERROR,                "RPCErrorError",                "Communication failure with server");
        PyKAdminError_kadm_insert(module, KADM5_NO_SRV,                   "NoServerError",                "No administration server found for realm");
        PyKAdminError_kadm_insert(module, KADM5_BAD_HIST_KEY,             "BadHistoryKeyError",           "Password history principal key version mismatch");
        PyKAdminError_kadm_insert(module, KADM5_NOT_INIT,                 "NotInitializedError",          "Connection to server not initialized");
        PyKAdminError_kadm_insert(module, KADM5_UNK_PRINC,                "UnknownPrincipalError",        "Principal does not exist");
        PyKAdminError_kadm_insert(module, KADM5_UNK_POLICY,               "UnknownPolicyError",           "Policy does not exist");
        PyKAdminError_kadm_insert(module, KADM5_BAD_MASK,                 "BadMaskError",                 "Invalid field mask for operation");
        PyKAdminError_kadm_insert(module, KADM5_BAD_CLASS,                "BadClassError",                "Invalid number of character classes");
        PyKAdminError_kadm_insert(module, KADM5_BAD_LENGTH,               "BadLengthError",               "Invalid password length");
        PyKAdminError_kadm_insert(module, KADM5_BAD_POLICY,               "BadPolicyError",               "Illegal policy name");
        PyKAdminError_kadm_insert(module, KADM5_BAD_PRINCIPAL,            "BadPrincipalError",            "Illegal principal name");
        PyKAdminError_kadm_insert(module, KADM5_BAD_AUX_ATTR,             "BadAuxAttrError",              "Invalid auxillary attributes");
        PyKAdminError_kadm_insert(module, KADM5_BAD_HISTORY,              "BadHistoryError",              "Invalid password history count");
        PyKAdminError_kadm_insert(module, KADM5_BAD_MIN_PASS_LIFE,        "BadMinPasswordLifeError",      "Password minimum life is greater then password maximum life");
        PyKAdminError_kadm_insert(module, KADM5_PASS_Q_TOOSHORT,          "PasswordTooShortError",        "Password is too short");
        PyKAdminError_kadm_insert(module, KADM5_PASS_Q_CLASS,             "PasswordClassError",           "Password does not contain enough character classes");
        PyKAdminError_kadm_insert(module, KADM5_PASS_Q_DICT,              "PasswordDictError",            "Password is in the password dictionary");
        PyKAdminError_kadm_insert(module, KADM5_PASS_REUSE,               "PasswordReuseError",           "Cannot resuse password");
        PyKAdminError_kadm_insert(module, KADM5_PASS_TOOSOON,             "PasswordTooSoonError",         "Current password's minimum life has not expired");
        PyKAdminError_kadm_insert(module, KADM5_POLICY_REF,               "PolicyRefError",               "Policy is in use");
        PyKAdminError_kadm_insert(module, KADM5_INIT,                     "InitializedError",             "Connection to server already initialized");
        PyKAdminError_kadm_insert(module, KADM5_BAD_PASSWORD,             "BadPasswordError",             "Incorrect password");
        PyKAdminError_kadm_insert(module, KADM5_PROTECT_PRINCIPAL,        "ProtectedPrincipalError",      "Cannot change protected principal");
        PyKAdminError_kadm_insert(module, KADM5_BAD_SERVER_HANDLE,        "BadServerHandleError",         "Programmer error! Bad Admin server handle");
        PyKAdminError_kadm_insert(module, KADM5_BAD_STRUCT_VERSION,       "BadStructVersionError",        "Programmer error! Bad API structure version");
        PyKAdminError_kadm_insert(module, KADM5_OLD_STRUCT_VERSION,       "OldStructVersionError",        "API structure version specified by application is no longer supported (to fix, recompile application against current Admin API header files and libraries)");
        PyKAdminError_kadm_insert(module, KADM5_NEW_STRUCT_VERSION,       "NewStructVersionError",        "API structure version specified by application is unknown to libraries (to fix, obtain current Admin API header files and libraries and recompile application)");
        PyKAdminError_kadm_insert(module, KADM5_BAD_API_VERSION,          "BadAPIVersionError",           "Programmer error! Bad API version");
        PyKAdminError_kadm_insert(module, KADM5_OLD_LIB_API_VERSION,      "OldLibraryAPIVersionError",    "API version specified by application is no longer supported by libraries (to fix, update application to adhere to current API version and recompile)");
        PyKAdminError_kadm_insert(module, KADM5_OLD_SERVER_API_VERSION,   "OldServerAPIVersionError",     "API version specified by application is no longer supported by server (to fix, update application to adhere to current API version and recompile)");
        PyKAdminError_kadm_insert(module, KADM5_NEW_LIB_API_VERSION,      "NewLibraryAPIVersionError",    "API version specified by application is unknown to libraries (to fix, obtain current Admin API header files and libraries and recompile application)");
        PyKAdminError_kadm_insert(module, KADM5_NEW_SERVER_API_VERSION,   "NewServerAPIVersionError",     "API version specified by application is unknown to server (to fix, obtain and install newest Admin Server)");
        PyKAdminError_kadm_insert(module, KADM5_SECURE_PRINC_MISSING,     "SecurePrincipalMissingError",  "Database error! Required principal missing");
        PyKAdminError_kadm_insert(module, KADM5_NO_RENAME_SALT,           "NoRenameSaltError",            "The salt type of the specified principal does not support renaming");
        PyKAdminError_kadm_insert(module, KADM5_BAD_CLIENT_PARAMS,        "BadClientParamsError",         "Illegal configuration parameter for remote KADM5 client");
        PyKAdminError_kadm_insert(module, KADM5_BAD_SERVER_PARAMS,        "BadServerParamsError",         "Illegal configuration parameter for local KADM5 client.");
        PyKAdminError_kadm_insert(module, KADM5_AUTH_LIST,                "AuthListError",                "Operation requires ``list'' privilege");
        PyKAdminError_kadm_insert(module, KADM5_AUTH_CHANGEPW,            "AuthChangePasswordError",      "Operation requires ``change-password'' privilege");
        PyKAdminError_kadm_insert(module, KADM5_GSS_ERROR,                "GSSAPIErrorError",             "GSS-API (or Kerberos) error");
        PyKAdminError_kadm_insert(module, KADM5_BAD_TL_TYPE,              "BadTypeError",                 "Programmer error! Illegal tagged data list element type");
        PyKAdminError_kadm_insert(module, KADM5_MISSING_CONF_PARAMS,      "MissingConfParamsError",       "Required parameters in kdc.conf missing");
        PyKAdminError_kadm_insert(module, KADM5_BAD_SERVER_NAME,          "BadServerNameError",           "Bad krb5 admin server hostname");
        PyKAdminError_kadm_insert(module, KADM5_AUTH_SETKEY,              "AuthSetKeyError",              "Operation requires ``set-key'' privilege");
        PyKAdminError_kadm_insert(module, KADM5_SETKEY_DUP_ENCTYPES,      "SetKeyDuplicateEnctypesError", "Multiple values for single or folded enctype");
        PyKAdminError_kadm_insert(module, KADM5_SETV4KEY_INVAL_ENCTYPE,   "Setv4KeyInvalEnctypeError",    "Invalid enctype for setv4key");
        PyKAdminError_kadm_insert(module, KADM5_SETKEY3_ETYPE_MISMATCH,   "SetKey3EnctypeMismatchError",  "Mismatched enctypes for setkey3");
        PyKAdminError_kadm_insert(module, KADM5_MISSING_KRB5_CONF_PARAMS, "MissingKrb5ConfParamsError",   "Missing parameters in krb5.conf required for kadmin client");
        PyKAdminError_kadm_insert(module, KADM5_XDR_FAILURE,              "XDRFailureError",              "XDR encoding error");
        #ifdef KADM5_CANT_RESOLVE
        PyKAdminError_kadm_insert(module, KADM5_CANT_RESOLVE,             "CantResolveError",             "");
        #endif
        #ifdef KADM5_PASS_Q_GENERIC
        PyKAdminError_kadm_insert(module, KADM5_PASS_Q_GENERIC,           "PasswordGenericError",         "Database synchronization failed");
        #endif
    
        result = 1;
    }


    return result;
}


