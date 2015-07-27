/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


PyObject *
LDAPObject_modify(LDAPObject *self, PyObject *args)
{
	const char *dn;
	PyObject *attributes;
	LDAPMod **mods;
	LDAPControl **sctrls = NULL;
	int rc, msgid;

	if (!PyArg_ParseTuple(args, "sO", &dn, &attributes))
		return NULL;

	mods = python2LDAPMods(attributes);
	if (mods == NULL)
		return NULL;

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_modify_ext(self->ldap, dn, mods, sctrls, NULL, &msgid);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}
	return PyLong_FromLong(msgid);
}

/* vi: set noexpandtab : */
