#ifndef PYKADMIN_H
#define PYKADMIN_H

#include <Python.h>
#include <patchlevel.h>

struct module_state {
    PyObject *error;
};

#ifdef KADMIN_LOCAL
#	define kMODULE_NAME "kadmin_local"
#else
#	define kMODULE_NAME "kadmin"
#endif

#if PY_MAJOR_VERSION >= 3
#	define PYTHON3
#	define Py_TPFLAGS_HAVE_ITER 0
#	define GETSTATE(m) ((struct module_state*)PyModule_GetState(m))
# 	define PyUnifiedLongInt_FromLong(from) PyLong_FromLong((long) from)
#	define PyUnifiedLongInt_AsUnsignedLong(ob) PyLong_AsUnsignedLong((PyObject *)ob)
#else 
#   define GETSTATE(m) (&_state)    
# 	define PyUnifiedLongInt_FromLong(from) PyInt_FromLong((long) from)
#	define PyUnifiedLongInt_AsUnsignedLong(ob) PyInt_AsUnsignedLongMask((PyObject *)ob)
#endif

#ifndef Py_TYPE
#	define Py_TYPE(ob) (((PyObject*)(ob))->ob_type)
#endif

#define PyUnicodeBytes_Check(obj) (PyUnicode_CheckExact(obj) || PyBytes_CheckExact(obj))

#endif