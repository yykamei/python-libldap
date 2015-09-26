/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


PyObject *
LDAPObject_get_option(LDAPObject *self, PyObject *args)
{
	int option;
	int is_global = 0;
	LDAP *ctx = NULL;
	int rc;
	int integer;
	ber_len_t bv_len;
	char *string = NULL;
	struct timeval *tvp = NULL;
	int i;
	char **referral_urls = NULL;
	LDAPAPIInfo api_info;
	PyObject *py_outvalue = NULL;
	PyObject *py_extensions = NULL;

	if (self->ldap == NULL) {
		PyErr_SetString(LDAPError, "This instance has already been deallocated.");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "i|i", &option, &is_global))
		return NULL;

	if (!is_global)
		ctx = self->ldap;

	switch(option) {
		case LDAP_OPT_CONNECT_ASYNC:
		case LDAP_OPT_REFERRALS:
		case LDAP_OPT_RESTART:
			LDAP_BEGIN_ALLOW_THREADS
			rc = ldap_get_option(ctx, option, &integer);
			LDAP_END_ALLOW_THREADS
			if (rc != LDAP_OPT_SUCCESS) {
				PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
				return NULL;
			}
			py_outvalue = PyBool_FromLong(integer);
			break;
		case LDAP_OPT_DEBUG_LEVEL:
		case LDAP_OPT_DEREF:
		case LDAP_OPT_DESC:
		case LDAP_OPT_PROTOCOL_VERSION:
		case LDAP_OPT_RESULT_CODE:
		case LDAP_OPT_SESSION_REFCNT:
		case LDAP_OPT_SIZELIMIT:
		case LDAP_OPT_TIMELIMIT:
		case LDAP_OPT_X_KEEPALIVE_IDLE:
		case LDAP_OPT_X_KEEPALIVE_PROBES:
		case LDAP_OPT_X_KEEPALIVE_INTERVAL:
		case LDAP_OPT_X_TLS_CRLCHECK:
		case LDAP_OPT_X_TLS_NEWCTX:
		case LDAP_OPT_X_TLS_PROTOCOL_MIN:
		case LDAP_OPT_X_TLS_REQUIRE_CERT:
		case LDAP_OPT_X_SASL_NOCANON:
			LDAP_BEGIN_ALLOW_THREADS
			rc = ldap_get_option(ctx, option, &integer);
			LDAP_END_ALLOW_THREADS
			if (rc != LDAP_OPT_SUCCESS) {
				PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
				return NULL;
			}
			py_outvalue = PyLong_FromLong(integer);
			break;
		case LDAP_OPT_X_SASL_MAXBUFSIZE:
		case LDAP_OPT_X_SASL_SSF:
		case LDAP_OPT_X_SASL_SSF_MAX:
		case LDAP_OPT_X_SASL_SSF_MIN:
			LDAP_BEGIN_ALLOW_THREADS
			rc = ldap_get_option(ctx, option, &bv_len);
			LDAP_END_ALLOW_THREADS
			if (rc != LDAP_OPT_SUCCESS) {
				PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
				return NULL;
			}
			py_outvalue = PyLong_FromLong(bv_len);
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
		case LDAP_OPT_X_SASL_AUTHCID:
		case LDAP_OPT_X_SASL_AUTHZID:
		case LDAP_OPT_X_SASL_MECH:
		case LDAP_OPT_X_SASL_MECHLIST:
		case LDAP_OPT_X_SASL_REALM:
		case LDAP_OPT_X_SASL_SECPROPS:
		case LDAP_OPT_X_SASL_USERNAME:
			LDAP_BEGIN_ALLOW_THREADS
			rc = ldap_get_option(ctx, option, &string);
			LDAP_END_ALLOW_THREADS
			if (rc != LDAP_OPT_SUCCESS) {
				PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
				return NULL;
			}
			if (string == NULL) {
				Py_RETURN_NONE;
			}
			py_outvalue = PyUnicode_FromString(string);
			ldap_memfree(string);
			break;
		case LDAP_OPT_NETWORK_TIMEOUT:
		case LDAP_OPT_TIMEOUT:
			LDAP_BEGIN_ALLOW_THREADS
			rc = ldap_get_option(ctx, option, &tvp);
			LDAP_END_ALLOW_THREADS
			if (rc != LDAP_OPT_SUCCESS) {
				PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
				return NULL;
			}
			if (tvp == NULL) {
				Py_RETURN_NONE;
			}
			py_outvalue = PyFloat_FromDouble(
					(double)tvp->tv_sec + ((double)tvp->tv_usec / 1000000.0));
			ldap_memfree(tvp);
			break;
		case LDAP_OPT_REFERRAL_URLS:
			LDAP_BEGIN_ALLOW_THREADS
			rc = ldap_get_option(ctx, option, &referral_urls);
			LDAP_END_ALLOW_THREADS
			if (rc != LDAP_OPT_SUCCESS) {
				PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
				return NULL;
			}
			if (referral_urls == NULL) {
				Py_RETURN_NONE;
			}
			if ((py_outvalue = PyList_New(0)) == NULL)
				return NULL;
			for (i = 0; referral_urls[i] != NULL; i++) {
				if (PyList_Append(py_outvalue, PyUnicode_FromString(referral_urls[i])) == -1) {
					XDECREF_MANY(py_outvalue);
					return NULL;
				}
			}
			ldap_memvfree((void *)referral_urls);
			break;
		case LDAP_OPT_API_INFO:
			api_info.ldapai_info_version = LDAP_API_INFO_VERSION;
			LDAP_BEGIN_ALLOW_THREADS
			rc = ldap_get_option(ctx, option, &api_info);
			LDAP_END_ALLOW_THREADS
			if (rc != LDAP_OPT_SUCCESS) {
				PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
				return NULL;
			}
			if ((py_extensions = PyList_New(0)) == NULL)
				return NULL;
			for (i = 0; api_info.ldapai_extensions[i] != NULL; i++) {
				if (PyList_Append(py_extensions, PyUnicode_FromString(api_info.ldapai_extensions[i])) == -1) {
					XDECREF_MANY(py_extensions);
					return NULL;
				}
			}
			py_outvalue = Py_BuildValue("{s:i, s:i, s:i, s:O, s:s, s:i}",
					"api_info_version", api_info.ldapai_info_version,
					"api_version", api_info.ldapai_api_version,
					"api_protocol_max", api_info.ldapai_protocol_version,
					"api_extensions", py_extensions,
					"api_vendor_name", api_info.ldapai_vendor_name,
					"api_vendor_version", api_info.ldapai_vendor_version);
			if (api_info.ldapai_vendor_name)
				ldap_memfree(api_info.ldapai_vendor_name);
			if (api_info.ldapai_extensions)
				ldap_memvfree((void **)api_info.ldapai_extensions);
			XDECREF_MANY(py_extensions);
			break;
		case LDAP_OPT_CONNECT_CB:
		case LDAP_OPT_SOCKBUF:
		case LDAP_OPT_X_TLS_CONNECT_ARG:
		case LDAP_OPT_X_TLS_CONNECT_CB:
		case LDAP_OPT_X_TLS_CTX:
		case LDAP_OPT_X_TLS_SSL_CTX:
		default:
			PyErr_SetString(LDAPError, "Specified option is not supported");
			return NULL;
	}
	return py_outvalue;
}

/* vi: set noexpandtab : */
