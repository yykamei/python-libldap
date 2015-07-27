/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


PyObject *
LDAPObject_rename(LDAPObject *self, PyObject *args)
{
	const char *dn;
    const char *newrdn;
    const char *newparent;
    int deleteoldrdn;
	LDAPControl **sctrls = NULL;
	int rc, msgid;

	if (!PyArg_ParseTuple(args, "sssi", &dn, &newrdn, &newparent, &deleteoldrdn))
		return NULL;

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_rename(self->ldap, dn, newrdn, newparent, deleteoldrdn, sctrls, NULL, &msgid);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}
	return PyLong_FromLong(msgid);
}

/* vi: set noexpandtab : */
