
#include "PyKAdminErrors.h"

#define IS_NULL(ptr) (ptr == NULL)

void PyKAdminError_insert(PyObject *module, kadm5_ret_t retval, char *error_name, char *error_string) {
    
    PyObject *error_number        = PyLong_FromUnsignedLong(retval);
    PyObject *exception     = NULL;
    PyObject *error_tuple   = NULL;
    uint32_t length         = strlen(error_name) + 0xF;
   
    char *real_name         = malloc(length); 

    snprintf(real_name, length, "kadmin.%s", error_name);

    exception = PyErr_NewException(real_name, KAdminError, NULL);
    PyModule_AddObject(module, error_name, exception); 
    
    error_tuple = Py_BuildValue("(Os)", exception, error_string);

    free(real_name);

    Py_XINCREF(error_tuple);
    Py_XINCREF(error_number);

    PyDict_SetItem(KAdminErrorsDict, error_number, error_tuple);

}


void PyKAdminError_init(PyObject *module) {

    KAdminErrorsDict = PyDict_New();
 
    PyKAdminError_insert(module, KADM5_FAILURE,                  "FailureError",                 "Operation failed for unspecified reason");
    PyKAdminError_insert(module, KADM5_AUTH_GET,                 "AuthGetError",                 "Operation requires ``get'' privilege");
    PyKAdminError_insert(module, KADM5_AUTH_ADD,                 "AuthAddError",                 "Operation requires ``add'' privilege");
    PyKAdminError_insert(module, KADM5_AUTH_MODIFY,              "AuthModifyError",              "Operation requires ``modify'' privilege");
    PyKAdminError_insert(module, KADM5_AUTH_DELETE,              "AuthDeleteError",              "Operation requires ``delete'' privilege");
    PyKAdminError_insert(module, KADM5_AUTH_INSUFFICIENT,        "AuthInsufficientError",        "Insufficient authorization for operation");
    PyKAdminError_insert(module, KADM5_BAD_DB,                   "BadDadtabaseError",            "Database inconsistency detected");
    PyKAdminError_insert(module, KADM5_DUP,                      "DuplicateError",               "Principal or policy already exists");
    PyKAdminError_insert(module, KADM5_RPC_ERROR,                "RPCErrorError",                "Communication failure with server");
    PyKAdminError_insert(module, KADM5_NO_SRV,                   "NoServerError",                "No administration server found for realm");
    PyKAdminError_insert(module, KADM5_BAD_HIST_KEY,             "BadHistoryKeyError",           "Password history principal key version mismatch");
    PyKAdminError_insert(module, KADM5_NOT_INIT,                 "NotInitializedError",          "Connection to server not initialized");
    PyKAdminError_insert(module, KADM5_UNK_PRINC,                "UnknownPrincipalError",        "Principal does not exist");
    PyKAdminError_insert(module, KADM5_UNK_POLICY,               "UnknownPolicyError",           "Policy does not exist");
    PyKAdminError_insert(module, KADM5_BAD_MASK,                 "BadMaskError",                 "Invalid field mask for operation");
    PyKAdminError_insert(module, KADM5_BAD_CLASS,                "BadClassError",                "Invalid number of character classes");
    PyKAdminError_insert(module, KADM5_BAD_LENGTH,               "BadLengthError",               "Invalid password length");
    PyKAdminError_insert(module, KADM5_BAD_POLICY,               "BadPolicyError",               "Illegal policy name");
    PyKAdminError_insert(module, KADM5_BAD_PRINCIPAL,            "BadPrincipalError",            "Illegal principal name");
    PyKAdminError_insert(module, KADM5_BAD_AUX_ATTR,             "BadAuxAttrError",              "Invalid auxillary attributes");
    PyKAdminError_insert(module, KADM5_BAD_HISTORY,              "BadHistoryError",              "Invalid password history count");
    PyKAdminError_insert(module, KADM5_BAD_MIN_PASS_LIFE,        "BadMinPasswordLifeError",      "Password minimum life is greater then password maximum life");
    PyKAdminError_insert(module, KADM5_PASS_Q_TOOSHORT,          "PasswordTooShortError",        "Password is too short");
    PyKAdminError_insert(module, KADM5_PASS_Q_CLASS,             "PasswordClassError",           "Password does not contain enough character classes");
    PyKAdminError_insert(module, KADM5_PASS_Q_DICT,              "PasswordDictError",            "Password is in the password dictionary");
    PyKAdminError_insert(module, KADM5_PASS_REUSE,               "PasswordReuseError",           "Cannot resuse password");
    PyKAdminError_insert(module, KADM5_PASS_TOOSOON,             "PasswordTooSoonError",         "Current password's minimum life has not expired");
    PyKAdminError_insert(module, KADM5_POLICY_REF,               "PolicyRefError",               "Policy is in use");
    PyKAdminError_insert(module, KADM5_INIT,                     "InitializedError",             "Connection to server already initialized");
    PyKAdminError_insert(module, KADM5_BAD_PASSWORD,             "BadPasswordError",             "Incorrect password");
    PyKAdminError_insert(module, KADM5_PROTECT_PRINCIPAL,        "ProtectedPrincipalError",      "Cannot change protected principal");
    PyKAdminError_insert(module, KADM5_BAD_SERVER_HANDLE,        "BadServerHandleError",         "Programmer error! Bad Admin server handle");
    PyKAdminError_insert(module, KADM5_BAD_STRUCT_VERSION,       "BadStructVersionError",        "Programmer error! Bad API structure version");
    PyKAdminError_insert(module, KADM5_OLD_STRUCT_VERSION,       "OldStructVersionError",        "API structure version specified by application is no longer supported (to fix, recompile application against current Admin API header files and libraries)");
    PyKAdminError_insert(module, KADM5_NEW_STRUCT_VERSION,       "NewStructVersionError",        "API structure version specified by application is unknown to libraries (to fix, obtain current Admin API header files and libraries and recompile application)");
    PyKAdminError_insert(module, KADM5_BAD_API_VERSION,          "BadAPIVersionError",           "Programmer error! Bad API version");
    PyKAdminError_insert(module, KADM5_OLD_LIB_API_VERSION,      "OldLibraryAPIVersionError",    "API version specified by application is no longer supported by libraries (to fix, update application to adhere to current API version and recompile)");
    PyKAdminError_insert(module, KADM5_OLD_SERVER_API_VERSION,   "OldServerAPIVersionError",     "API version specified by application is no longer supported by server (to fix, update application to adhere to current API version and recompile)");
    PyKAdminError_insert(module, KADM5_NEW_LIB_API_VERSION,      "NewLibraryAPIVersionError",    "API version specified by application is unknown to libraries (to fix, obtain current Admin API header files and libraries and recompile application)");
    PyKAdminError_insert(module, KADM5_NEW_SERVER_API_VERSION,   "NewServerAPIVersionError",     "API version specified by application is unknown to server (to fix, obtain and install newest Admin Server)");
    PyKAdminError_insert(module, KADM5_SECURE_PRINC_MISSING,     "SecurePrincipalMissingError",  "Database error! Required principal missing");
    PyKAdminError_insert(module, KADM5_NO_RENAME_SALT,           "NoRenameSaltError",            "The salt type of the specified principal does not support renaming");
    PyKAdminError_insert(module, KADM5_BAD_CLIENT_PARAMS,        "BadClientParamsError",         "Illegal configuration parameter for remote KADM5 client");
    PyKAdminError_insert(module, KADM5_BAD_SERVER_PARAMS,        "BadServerParamsError",         "Illegal configuration parameter for local KADM5 client.");
    PyKAdminError_insert(module, KADM5_AUTH_LIST,                "AuthListError",                "Operation requires ``list'' privilege");
    PyKAdminError_insert(module, KADM5_AUTH_CHANGEPW,            "AuthChangePasswordError",      "Operation requires ``change-password'' privilege");
    PyKAdminError_insert(module, KADM5_GSS_ERROR,                "GSSAPIErrorError",             "GSS-API (or Kerberos) error");
    PyKAdminError_insert(module, KADM5_BAD_TL_TYPE,              "BadTypeError",                 "Programmer error! Illegal tagged data list element type");
    PyKAdminError_insert(module, KADM5_MISSING_CONF_PARAMS,      "MissingConfParamsError",       "Required parameters in kdc.conf missing");
    PyKAdminError_insert(module, KADM5_BAD_SERVER_NAME,          "BadServerNameError",           "Bad krb5 admin server hostname");
    PyKAdminError_insert(module, KADM5_AUTH_SETKEY,              "AuthSetKeyError",              "Operation requires ``set-key'' privilege");
    PyKAdminError_insert(module, KADM5_SETKEY_DUP_ENCTYPES,      "SetKeyDuplicateEnctypesError", "Multiple values for single or folded enctype");
    PyKAdminError_insert(module, KADM5_SETV4KEY_INVAL_ENCTYPE,   "Setv4KeyInvalEnctypeError",    "Invalid enctype for setv4key");
    PyKAdminError_insert(module, KADM5_SETKEY3_ETYPE_MISMATCH,   "SetKey3EnctypeMismatchError",  "Mismatched enctypes for setkey3");
    PyKAdminError_insert(module, KADM5_MISSING_KRB5_CONF_PARAMS, "MissingKrb5ConfParamsError",   "Missing parameters in krb5.conf required for kadmin client");
    PyKAdminError_insert(module, KADM5_XDR_FAILURE,              "XDRFailureError",              "XDR encoding error");
    #ifdef KADM5_CANT_RESOLVE
    PyKAdminError_insert(module, KADM5_CANT_RESOLVE,             "CantResolveError",             "");
    #endif
    #ifdef KADM5_PASS_Q_GENERIC
    PyKAdminError_insert(module, KADM5_PASS_Q_GENERIC,           "PasswordGenericError",         "Database synchronization failed");
    #endif

}


PyObject *PyKAdmin_RaiseKAdminError(kadm5_ret_t retval, char *caller) {

    static const char *kERROR_NUMBER = "errno";
    static const char *kERROR_STRING = "message";
 
    PyObject *error_number  = PyLong_FromUnsignedLong(retval);
    PyObject *error_object  = NULL;
    PyObject *error_string  = NULL;
    PyObject *error_tuple   = NULL;
    PyObject *error_dict    = PyDict_New();

    PyDict_SetItemString(error_dict, kERROR_NUMBER, error_number);

    if (!IS_NULL(KAdminErrorsDict)) {
        
        error_tuple = PyDict_GetItem(KAdminErrorsDict, error_number);

        if (!IS_NULL(error_tuple) && (PyTuple_GET_SIZE(error_tuple) >= 2)) {
            error_object = PyTuple_GetItem(error_tuple, 0x0); 
            error_string = PyTuple_GetItem(error_tuple, 0x1);
        }
    }

    if (!IS_NULL(error_string)) {
        PyDict_SetItemString(error_dict, kERROR_STRING, error_string);
    } else {
        error_string = PyString_FromString(caller);
        PyDict_SetItemString(error_dict, kERROR_STRING, error_string);
        Py_XDECREF(error_string);
    }


    if (!IS_NULL(error_object)) {
        PyErr_SetObject(error_object, error_dict);
    } else {
        PyErr_SetObject(KAdminError, error_dict);
    }

    Py_XDECREF(error_number);
    Py_XDECREF(error_dict);

    return NULL;

}


