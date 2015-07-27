/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


PyObject *
LDAPObject_set_option(LDAPObject *self, PyObject *args)
{
	int option;
	PyObject *value;
	int is_global;
	LDAP *ctx = NULL;
	int rc;
	int integer = 0;
	char *string;
	void *ptr;

	if (self->ldap == NULL) {
		PyErr_SetString(LDAPError, "This instance has already been deallocated.");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "iO|i", &option, &value, &is_global))
		return NULL;

	if (!is_global)
		ctx = self->ldap;
	switch(option) {
		/* FIXME: SASL options are not included */
		case LDAP_OPT_CONNECT_ASYNC:
		case LDAP_OPT_REFERRALS:
		case LDAP_OPT_RESTART:
			ptr = PyObject_IsTrue(value) == 1 ? LDAP_OPT_ON : LDAP_OPT_OFF;
			break;
		case LDAP_OPT_DEBUG_LEVEL:
		case LDAP_OPT_DEREF:
		case LDAP_OPT_PROTOCOL_VERSION:
		case LDAP_OPT_RESULT_CODE:
		case LDAP_OPT_SIZELIMIT:
		case LDAP_OPT_TIMELIMIT:
		case LDAP_OPT_X_KEEPALIVE_IDLE:
		case LDAP_OPT_X_KEEPALIVE_PROBES:
		case LDAP_OPT_X_KEEPALIVE_INTERVAL:
		case LDAP_OPT_X_TLS_CRLCHECK:
		case LDAP_OPT_X_TLS_PROTOCOL_MIN:
		case LDAP_OPT_X_TLS_REQUIRE_CERT:
			integer = (int)PyLong_AsLong(value);
			ptr = &integer;
			break;
		case LDAP_OPT_DEFBASE:
		case LDAP_OPT_DIAGNOSTIC_MESSAGE:
		case LDAP_OPT_MATCHED_DN:
		case LDAP_OPT_URI:
		case LDAP_OPT_X_TLS_CACERTDIR:
		case LDAP_OPT_X_TLS_CACERTFILE:
		case LDAP_OPT_X_TLS_CERTFILE:
		case LDAP_OPT_X_TLS_CIPHER_SUITE:
		case LDAP_OPT_X_TLS_CRLFILE:
		case LDAP_OPT_X_TLS_DHFILE:
		case LDAP_OPT_X_TLS_KEYFILE:
		case LDAP_OPT_X_TLS_RANDOM_FILE:
			if ((string = PyUnicode_AsUTF8(value)) == NULL)
				return NULL;
			ptr = &string;
			break;
		case LDAP_OPT_CONNECT_CB:
			/* FIXME */
			break;
		case LDAP_OPT_NETWORK_TIMEOUT:
		case LDAP_OPT_TIMEOUT:
			/* FIXME */
			break;
		case LDAP_OPT_REFERRAL_URLS:
			/* FIXME */
			break;
		default:
			PyErr_SetString(LDAPError, "Specified option is not supported or read-only");
			return NULL;
	}

	rc = ldap_set_option(ctx, option, ptr);
	if (rc != LDAP_OPT_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}
	Py_RETURN_NONE;
}

/* vi: set noexpandtab : */
