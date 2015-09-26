/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


PyObject *
LDAPObject_unbind(LDAPObject *self, PyObject *args)
{
	LDAPControl **sctrls = NULL;
	int rc;

	if (self->ldap == NULL) {
		PyErr_SetString(LDAPError, "This instance has already been deallocated.");
		return NULL;
	}

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_unbind_ext(self->ldap, sctrls, NULL);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
		return NULL;
	}
	self->ldap = NULL;
	Py_RETURN_NONE;
}

/* vi: set noexpandtab : */
