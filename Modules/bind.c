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
	const char *who;
	const char *password;
	struct berval passwd = {0, NULL};
	int rc;
	int msgid;
	
	if (!PyArg_ParseTuple(args, "ss", &who, &password))
		return NULL;

	// ldap_set_option
	// ldap_start_tls_s
	passwd.bv_val = ber_strdup(password);
	passwd.bv_len = strlen(passwd.bv_val);

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_sasl_bind(self->ldap, who, LDAP_SASL_SIMPLE, &passwd, NULL, NULL, &msgid); // CONTROL
	LDAP_END_ALLOW_THREADS
	if (msgid == -1) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}
	return PyLong_FromLong(msgid);
}

/* vi: set noexpandtab : */
