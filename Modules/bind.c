/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


PyObject *
LDAPObject_bind(LDAPObject *self, PyObject *args)
{
	char *who;
	char *password;
	struct berval passwd = {0, NULL};
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

	if (!PyArg_ParseTuple(args, "ss|O!", &who, &password, &LDAPObjectControlType, &controls))
		return NULL;

	passwd.bv_val = password;
	passwd.bv_len = strlen(passwd.bv_val);

	if (controls) {
		ldapoc = (LDAPObjectControl *)controls;
		sctrls = ldapoc->sctrls;
		cctrls = ldapoc->cctrls;
	}

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_sasl_bind(self->ldap, who, LDAP_SASL_SIMPLE, &passwd, sctrls, cctrls, &msgid);
	LDAP_END_ALLOW_THREADS
	if (msgid == -1) {
		PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
		return NULL;
	}
	return PyLong_FromLong(msgid);
}

/* vi: set noexpandtab : */
