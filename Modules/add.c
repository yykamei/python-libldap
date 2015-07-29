/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


PyObject *
LDAPObject_add(LDAPObject *self, PyObject *args)
{
	const char *dn;
	PyObject *attributes;
	LDAPMod **attrs;
	LDAPControl **sctrls = NULL;
	int rc, msgid;

	if (self->ldap == NULL) {
		PyErr_SetString(LDAPError, "This instance has already been deallocated.");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "sO", &dn, &attributes))
		return NULL;

	attrs = python2LDAPMods(attributes);
	if (attrs == NULL)
		return NULL;

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_add_ext(self->ldap, dn, attrs, sctrls, NULL, &msgid);
	LDAP_END_ALLOW_THREADS
	free_LDAPMods(attrs);
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}
	return PyLong_FromLong(msgid);
}

/* vi: set noexpandtab : */
