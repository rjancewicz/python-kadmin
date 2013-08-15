

#include <python2.6/Python.h>
#include <kadm5/admin.h>
#include <krb5/krb5.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    PyObject_HEAD

    PyKAdminObject *kadmin;
    kadm5_principal_ent_rec entry;  
} PyKAdminPrincipalObject;


extern time_t get_date(char *);

//static void KAdminPrincipal_dealloc(PyKAdminPrincipalObject *);
void KAdminPrincipal_destroy(PyKAdminPrincipalObject *self); 

PyTypeObject PyKAdminPrincipalObject_Type;
PyKAdminPrincipalObject *PyKAdminPrincipalObject_create(void);


