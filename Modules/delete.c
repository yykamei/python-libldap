/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


PyObject *
LDAPObject_delete(LDAPObject *self, PyObject *args)
{
	const char *dn;
	LDAPControl **sctrls = NULL;
	int rc;
	int msgid;

	if (self->ldap == NULL) {
		PyErr_SetString(LDAPError, "This instance has already been deallocated.");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s", &dn))
		return NULL;

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_delete_ext(self->ldap, dn, sctrls, NULL, &msgid);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}
	return PyLong_FromLong(msgid);
}

/* vi: set noexpandtab : */
