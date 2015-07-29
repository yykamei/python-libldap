/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


PyObject *
LDAPObject_cancel(LDAPObject *self, PyObject *args)
{
	int cancelid;
	LDAPControl **sctrls = NULL;
	int rc;

	if (self->ldap == NULL) {
		PyErr_SetString(LDAPError, "This instance has already been deallocated.");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "i", &cancelid))
		return NULL;

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_cancel_s(self->ldap, cancelid, sctrls, NULL);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}
	Py_RETURN_NONE;
}

/* vi: set noexpandtab : */
