
#include "PyKAdminErrors.h"


inline void PyKAdminError_insert(PyObject *module, kadm5_ret_t retval, char *error_name, char *error_string) {
    
    PyObject *kerrno         = PyLong_FromUnsignedLong(retval);
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
    Py_XINCREF(kerrno);

    PyDict_SetItem(KAdminErrorsDict, kerrno, error_tuple);

}


void PyKAdminError_init(PyObject *module) {

KAdminErrorsDict = PyDict_New();

PyKAdminError_insert(module, 43787520,  "UNSPECIFIED"                       ,"Operation failed for unspecified reason");
PyKAdminError_insert(module, 43787521,  "REQUIRES_GET"                      ,"Operation requires ``get'' privilege");
PyKAdminError_insert(module, 43787522,  "REQUIRES_ADD"                      ,"Operation requires ``add'' privilege");
PyKAdminError_insert(module, 43787523,  "REQUIRES_MODIFY"                   ,"Operation requires ``modify'' privilege");
PyKAdminError_insert(module, 43787524,  "REQUIRES_DELETE"                   ,"Operation requires ``delete'' privilege");
PyKAdminError_insert(module, 43787525,  "INSUFFICIENT_AUTHORIZATION"        ,"Insufficient authorization for operation");
PyKAdminError_insert(module, 43787526,  "DATABASE_INCONSISTENCY"            ,"Database inconsistency detected");
PyKAdminError_insert(module, 43787527,  "PRINCIPAL_POLICY_EXISTS"           ,"Principal or policy already exists");
PyKAdminError_insert(module, 43787528,  "COMMUNICATION_FAILURE"             ,"Communication failure with server");
PyKAdminError_insert(module, 43787529,  "NO_ADMIN_SERVER_FOUND"             ,"No administration server found for realm");
PyKAdminError_insert(module, 43787530,  "HISTORY_KEY_VERSION_MISMATCH"      ,"Password history principal key version mismatch");
PyKAdminError_insert(module, 43787531,  "CONNECTION_NOT_INITIALIZED"        ,"Connection to server not initialized");
PyKAdminError_insert(module, 43787532,  "PRINCIPAL_DOES_NOT_EXIST"          ,"Principal does not exist");
PyKAdminError_insert(module, 43787533,  "POLICY_DOES_NOT_EXIST"             ,"Policy does not exist");
PyKAdminError_insert(module, 43787534,  "INVALID_FIELD_MASK"                , "Invalid field mask for operation");
PyKAdminError_insert(module, 43787535,  "INVALID_NUM_CHAR_CLASSES"          ,"Invalid number of character classes");
PyKAdminError_insert(module, 43787536,  "INVALID_PASSWORD_LENGTH"           ,"Invalid password length");
PyKAdminError_insert(module, 43787537,  "ILLEGAL_POLICY_NAME"               ,"Illegal policy name");
PyKAdminError_insert(module, 43787538,  "ILLEGAL_PRINCIPAL_NAME"            ,"Illegal principal name");
PyKAdminError_insert(module, 43787539,  "INVALID_AUX_ATTRIBUTES"            ,"Invalid auxillary attributes");
PyKAdminError_insert(module, 43787540,  "INVALID_HISTORY_COUNT"             ,"Invalid password history count");
PyKAdminError_insert(module, 43787541,  "PASSWORD_MIN_LIFE_GT_MAX_LIFE"     ,"Password minimum life is greater than password maximum life");
PyKAdminError_insert(module, 43787542,  "PASSWORD_TOO_SHORT"                ,"Password is too short");
PyKAdminError_insert(module, 43787543,  "PASSWORD_NOT_ENOUGH_CHAR_CLASSES"  ,"Password does not contain enough character classes");
PyKAdminError_insert(module, 43787544,  "PASSWORD_IN_DICTIONARY"            ,"Password is in the password dictionary");
PyKAdminError_insert(module, 43787545,  "CANNOT_REUSE_PASSWORD"             ,"Cannot reuse password");
PyKAdminError_insert(module, 43787546,  "PASSWORD_MIN_LIFE_NOT_EXPIRED"     ,"Current password's minimum life has not expired");
PyKAdminError_insert(module, 43787547,  "POLICY_IN_USE"                     ,"Policy is in use");
PyKAdminError_insert(module, 43787548,  "CONNECTION_ALREADY_INITIALIZED"    ,"Connection to server already initialized");
PyKAdminError_insert(module, 43787549,  "INCORRECT_PASSWORD"                ,"Incorrect password");
PyKAdminError_insert(module, 43787550,  "CANNOT_CHANGE_PROTECTED_PRINCIPAL" ,"Cannot change protected principal");
PyKAdminError_insert(module, 43787551,  "BAD_HANDLE"                        ,"Programmer error! Bad Admin server handle");
PyKAdminError_insert(module, 43787552,  "BAD_API_STRUCTURE_VERSION"         ,"Programmer error! Bad API structure version");
PyKAdminError_insert(module, 43787553,  "UNSUPPORTED_API_STRUCTURE_VERSION" ,"API structure version specified by application is no longer supported (to fix, recompile application against current KADM5 API header files and libraries)");
PyKAdminError_insert(module, 43787554,  "UNKNOWN_API_STRUCTURE_VERSION"     ,"API structure version specified by application is unknown to libraries (to fix, obtain current KADM5 API header files and libraries and recompile application)");
PyKAdminError_insert(module, 43787555,  "BAD_API_VERSION"                   ,"Programmer error! Bad API version");
PyKAdminError_insert(module, 43787556,  "UNSUPPORTED_API_VERSION_BY_LIBS"   ,"API version specified by application is no longer supported by libraries (to fix, update application to adhere to current API version and recompile)");
PyKAdminError_insert(module, 43787557,  "UNSUPPORTED_API_VERSION_BY_SERVER" ,"API version specified by application is no longer supported by server (to fix, update application to adhere to current API version and recompile)");
PyKAdminError_insert(module, 43787558,  "UNKNOWN_API_VERSION_BY_LIBS"       ,"API version specified by application is unknown to libraries (to fix, obtain current KADM5 API header files and libraries and recompile application)");
PyKAdminError_insert(module, 43787559,  "UNKWNON_API_VERSION_BY_SERVER"     ,"API version specified by application is unknown to server (to fix, obtain and install newest KADM5 Admin Server) libraries and recompile application)");
PyKAdminError_insert(module, 43787560,  "KADM5_PRINCIPAL_MISSING"           ,"Database error! Required KADM5 principal missing");
PyKAdminError_insert(module, 43787561,  "SALT_TYPE_NOT_SUPPORT_RENAMING"    ,"The salt type of the specified principal does not support renaming");
PyKAdminError_insert(module, 43787562,  "ILLEGAL_CONFIG_PARAM_REMOTE"       ,"Illegal configuration parameter for remote KADM5 client");
PyKAdminError_insert(module, 43787563,  "ILLEGAL_CONFIG_PARAM_LOCAL"        ,"Illegal configuration parameter for local KADM5 client");
PyKAdminError_insert(module, 43787564,  "REQUIRES_LIST"                     ,"Operation requires ``list'' privilege");
PyKAdminError_insert(module, 43787565,  "REQUIRES_CHANGE_PASSWORD"          ,"Operation requires ``change-password'' privilege");
PyKAdminError_insert(module, 43787566,  "GSSAPI"                            ,"GSS-API (or Kerberos) error");
PyKAdminError_insert(module, 43787567,  "ILLEGAL_TAGGED_LIST_TYPE"          ,"Programmer error! Illegal tagged data list type");
PyKAdminError_insert(module, 43787568,  "REQUIRED_KDC_CONF_PARAMS_MISSING"  ,"Required parameters in kdc.conf missing");
PyKAdminError_insert(module, 43787569,  "BAD_ADMIN_SERVER_HOSTNAME"         ,"Bad krb5 admin server hostname");

}

PyObject *PyKAdminError_raise_kadmin_error(kadm5_ret_t retval, char *caller) {

    const char *ERROR_NUMBER = "errno";
    const char *ERROR_STRING = "error";
//    const char *ERROR_DEFAULT = sprintf("Unexpected KAdmin Error in '%s'\n", caller); 

    PyObject *kerrno = PyLong_FromUnsignedLong(retval);
    PyObject *errob = NULL;
    PyObject *error = NULL;

    PyObject *error_tuple   = NULL;
    PyObject *error_info    = PyDict_New();

    PyDict_SetItemString(error_info, ERROR_NUMBER, kerrno);

    if (KAdminErrorsDict) {
        
        error_tuple = PyDict_GetItem(KAdminErrorsDict, kerrno);

        if (error_tuple) {
            errob = PyTuple_GetItem(error_tuple, 0x0); 
            error = PyTuple_GetItem(error_tuple, 0x1);
        }
    }

    if (error) {
        PyDict_SetItemString(error_info, ERROR_STRING, error);
    } else {
        error = PyString_FromString(caller);
        PyDict_SetItemString(error_info, ERROR_STRING, error);
        Py_XDECREF(error);
    }

    if (errob) {
        PyErr_SetObject(errob, error_info);
    } else {
        PyErr_SetObject(KAdminError, error_info);
    }

    Py_XDECREF(kerrno);
    Py_XDECREF(error_info);

    return NULL;
}


