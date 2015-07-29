/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


PyObject *
LDAPObject_abandon(LDAPObject *self, PyObject *args)
{
	int msgid;
	LDAPControl **sctrls = NULL;
	int rc;

	if (self->ldap == NULL) {
		PyErr_SetString(LDAPError, "This instance has already been deallocated.");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "i", &msgid))
		return NULL;

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_abandon_ext(self->ldap, msgid, sctrls, NULL);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}
	Py_RETURN_NONE;
}

/* vi: set noexpandtab : */
