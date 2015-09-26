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
	PyObject *controls = NULL;
	LDAPObjectControl *ldapoc = NULL;
	LDAPControl **sctrls = NULL;
	LDAPControl **cctrls = NULL;
	int rc;
	int msgid;

	if (self->ldap == NULL) {
		PyErr_SetString(LDAPError, "This instance has already been deallocated.");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "sO|O!", &dn, &attributes, &LDAPObjectControlType, &controls))
		return NULL;

	attrs = python2LDAPMods(attributes);
	if (attrs == NULL)
		return NULL;

	if (controls) {
		ldapoc = (LDAPObjectControl *)controls;
		sctrls = ldapoc->sctrls;
		cctrls = ldapoc->cctrls;
	}

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_add_ext(self->ldap, dn, attrs, sctrls, cctrls, &msgid);
	LDAP_END_ALLOW_THREADS
	free_LDAPMods(attrs);
	if (rc != LDAP_SUCCESS) {
		PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
		return NULL;
	}
	return PyLong_FromLong(msgid);
}

/* vi: set noexpandtab : */
