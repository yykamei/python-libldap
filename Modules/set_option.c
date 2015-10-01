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
	int is_global = 0;
	LDAP *ctx = NULL;
	int rc;
	int integer = 0;
	ber_len_t bv_len;
	char *string = NULL;
	int timeout;
	struct timeval tv;
	struct timeval *tvp = NULL;
	int i;
	Py_ssize_t size;
	char **referral_urls = NULL;
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
		case LDAP_OPT_X_SASL_NOCANON:
			integer = (int)PyLong_AsLong(value);
			ptr = &integer;
			break;
		case LDAP_OPT_X_SASL_MAXBUFSIZE:
		case LDAP_OPT_X_SASL_SSF_EXTERNAL:
		case LDAP_OPT_X_SASL_SSF_MAX:
		case LDAP_OPT_X_SASL_SSF_MIN:
			bv_len = (ber_len_t)PyLong_AsLong(value);
			ptr = &bv_len;
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
		case LDAP_OPT_X_SASL_SECPROPS:
			if ((string = PyUnicode_AsUTF8(value)) == NULL)
				return NULL;
			ptr = string;
			break;
		case LDAP_OPT_NETWORK_TIMEOUT:
		case LDAP_OPT_TIMEOUT:
			if ((timeout = (int)PyLong_AsLong(value)) == -1)
				return NULL;
			if (timeout > 0) {
				tvp = &tv;
				int2timeval(tvp, timeout);
			} else {
				tvp = NULL;
			}
			ptr = tvp;
			break;
		case LDAP_OPT_REFERRAL_URLS:
			if (!PyList_Check(value))
				return NULL;
			size = PyList_GET_SIZE(value);
			referral_urls = (char **)PyMem_RawMalloc(sizeof(char *) * (size + 1));
			if (referral_urls == NULL)
				return NULL;
			for (i = 0; i < size; i++) {
				referral_urls[i] = PyUnicode_AsUTF8(PyList_GET_ITEM(value, i));
				if (referral_urls[i] == NULL) {  /* PyUnicode_AsUTF8 failed */
					PyMem_RawFree(referral_urls);
					return NULL;
				}
			}
			referral_urls[size] = NULL;
			ptr = referral_urls;
			break;
		default:
			PyErr_SetString(LDAPError, "Specified option is not supported or read-only");
			return NULL;
	}

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_set_option(ctx, option, ptr);
	LDAP_END_ALLOW_THREADS

	if (referral_urls)
		PyMem_RawFree(referral_urls);

	if (rc == LDAP_OPT_ERROR) {
		PyErr_SetString(LDAPError, "Invalid value is specified");
		return NULL;
	} else if (rc != LDAP_OPT_SUCCESS) {
		PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
		return NULL;
	}
	Py_RETURN_NONE;
}

/* vi: set noexpandtab : */
