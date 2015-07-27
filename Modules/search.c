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
	long timeout = -1;
	struct timeval *tv = NULL;
	char **attrs = NULL;
	int i;
	Py_ssize_t size = 0;
	int rc;
	int msgid;

	if (self->ldap == NULL) {
		PyErr_SetString(LDAPError, "This instance has already been deallocated.");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "sis|Oil", &base, &scope, &filter,
				&attributes, &attrsonly, &timeout))
		return NULL;

	if (timeout >= 0) {
		tv->tv_sec = (long)timeout;
		tv->tv_usec = 0;
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
			attrsonly, sctrls, NULL, tv, 0, &msgid);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}

	if (attrs)
		PyMem_RawFree(attrs);

	return PyLong_FromLong(msgid);
}

/* vi: set noexpandtab : */
