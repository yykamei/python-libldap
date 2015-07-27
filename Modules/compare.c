/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


PyObject *
LDAPObject_compare(LDAPObject *self, PyObject *args)
{
	const char *dn;
	const char *attribute;
	char *value;
	struct berval bvalue;
	LDAPControl **sctrls = NULL;
	int rc;
	int msgid;

	if (self->ldap == NULL) {
		PyErr_SetString(LDAPError, "This instance has already been deallocated.");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "sss", &dn, &attribute, &value))
		return NULL;

	bvalue.bv_val = value;
	bvalue.bv_len = strlen(value);

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_compare_ext(self->ldap, dn, attribute, &bvalue, sctrls, NULL, &msgid);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}
	return PyLong_FromLong(msgid);
}

/* vi: set noexpandtab : */
