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
	PyObject *controls = NULL;
	LDAPObjectControl *ldapoc = NULL;
	LDAPControl **sctrls = NULL;
	LDAPControl **cctrls = NULL;
	int rc;

	if (self->ldap == NULL) {
		PyErr_SetString(LDAPError, "This instance has already been deallocated.");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "i|O!", &msgid, &LDAPObjectControlType, &controls))
		return NULL;

	if (controls) {
		ldapoc = (LDAPObjectControl *)controls;
		sctrls = ldapoc->sctrls;
		cctrls = ldapoc->cctrls;
	}

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_abandon_ext(self->ldap, msgid, sctrls, cctrls);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
		return NULL;
	}
	Py_RETURN_NONE;
}

/* vi: set noexpandtab : */
