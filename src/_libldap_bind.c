/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "_libldap.h"


PyObject *
LDAPObject_bind(LDAPObject *self, PyObject *args)
{
	const char *who;
	const char *password;
	struct berval passwd = {0, NULL};
	LDAPMessage *result = NULL;
	int rc, msgid, err;
	char *matched = NULL;
	char *info = NULL;
	char **refs = NULL;
	LDAPControl **ctrls = NULL;
	
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

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_result(self->ldap, msgid, LDAP_MSG_ALL, NULL, &result);
	LDAP_END_ALLOW_THREADS
	if (rc == -1) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	} else if (rc == 0) {
		PyErr_SetString(LDAPError, ldap_err2string(LDAP_TIMEOUT));
		return NULL;
	}

	if (result) {
		LDAP_BEGIN_ALLOW_THREADS
		rc = ldap_parse_result(self->ldap, result, &err, &matched, &info, &refs, &ctrls, 1);
		LDAP_END_ALLOW_THREADS
		if (rc != LDAP_SUCCESS) {
			PyErr_SetString(LDAPError, ldap_err2string(rc));
			return NULL;
		}
	}
	if (err != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(err));
		return NULL;
	}
	Py_RETURN_TRUE;
}

/* vi: set noexpandtab : */
