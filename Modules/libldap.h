/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include <Python.h>
#include <ldap.h>
#include <lber.h>
#include <signal.h>


typedef struct {
	PyObject_HEAD
	LDAP *ldap;
} LDAPObject;


#define LDAP_BEGIN_ALLOW_THREADS          \
	{                                     \
		PyGILState_STATE gstate;          \
		gstate = PyGILState_Ensure();
#define LDAP_END_ALLOW_THREADS            \
		PyGILState_Release(gstate);       \
	}

#define XDECREF_MANY(...)                                        \
	_XDECREF_MANY(                                               \
		(PyObject *[]){__VA_ARGS__},                             \
		sizeof((PyObject *[]){__VA_ARGS__}) / sizeof(PyObject *) \
	)

extern PyObject *LDAPError;


/* Functions */
void _XDECREF_MANY(PyObject *objs[], size_t count);
LDAPMod **python2LDAPMods(PyObject *list);

/* Instance methods */
PyObject *LDAPObject_bind(LDAPObject *self, PyObject *args);
PyObject *LDAPObject_unbind(LDAPObject *self, PyObject *args);
PyObject *LDAPObject_search(LDAPObject *self, PyObject *args);
PyObject *LDAPObject_add(LDAPObject *self, PyObject *args);
PyObject *LDAPObject_modify(LDAPObject *self, PyObject *args);
PyObject *LDAPObject_delete(LDAPObject *self, PyObject *args);
PyObject *LDAPObject_rename(LDAPObject *self, PyObject *args);
PyObject *LDAPObject_compare(LDAPObject *self, PyObject *args);
PyObject *LDAPObject_abandon(LDAPObject *self, PyObject *args);
PyObject *LDAPObject_whoami(LDAPObject *self, PyObject *args);
PyObject *LDAPObject_passwd(LDAPObject *self, PyObject *args);
PyObject *LDAPObject_cancel(LDAPObject *self, PyObject *args);
PyObject *LDAPObject_start_tls(LDAPObject *self, PyObject *args);
PyObject *LDAPObject_set_option(LDAPObject *self, PyObject *args);
PyObject *LDAPObject_result(LDAPObject *self, PyObject *args);

/* vi: set noexpandtab : */
