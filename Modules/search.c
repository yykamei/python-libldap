/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


PyObject *
LDAPObject_search(LDAPObject *self, PyObject *args)
{
	char *base;
	int scope;
	char *filter;
	PyObject *attributes = Py_None;
	int attrsonly = 0;
	LDAPControl **sctrls = NULL;
	int timeout = LDAP_NO_LIMIT;
	int sizelimit = LDAP_NO_LIMIT;
	struct timeval tv;
	struct timeval *tvp = NULL;
	char **attrs = NULL;
	int i;
	Py_ssize_t size;
	int rc;
	int msgid;

	if (self->ldap == NULL) {
		PyErr_SetString(LDAPError, "This instance has already been deallocated.");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "sis|Oiii", &base, &scope, &filter,
				&attributes, &attrsonly, &timeout, &sizelimit))
		return NULL;

	if (timeout > 0) {
		tvp = &tv;
		int2timeval(tvp, timeout);
	} else {
		tvp = NULL;
	}

	if (PyList_Check(attributes)) {
		if ((size = PyList_GET_SIZE(attributes)) == -1)
			return NULL;
		attrs = (char **)PyMem_RawMalloc(sizeof(char *) * (size + 1));
		for (i = 0; i < size; i++) {
			attrs[i] = PyUnicode_AsUTF8(PyList_GET_ITEM(attributes, i));
		}
		attrs[size] = NULL;
	} else {
		attrs = NULL;
	}

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_search_ext(self->ldap, base, scope, filter, attrs,
			attrsonly, sctrls, NULL, tvp, sizelimit, &msgid);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		if (attrs)
			PyMem_RawFree(attrs);
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}

	if (attrs)
		PyMem_RawFree(attrs);

	return PyLong_FromLong(msgid);
}

/* vi: set noexpandtab : */
