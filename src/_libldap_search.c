/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "_libldap.h"


PyObject *
LDAPObject_search(LDAPObject *self, PyObject *args)
{
	char *base;
	int scope;
	char *filter;
	PyObject *attributes = Py_None;
	char **attrs = NULL;
	int rc, msgid;

	if (!PyArg_ParseTuple(args, "sis|O", &base, &scope, &filter, &attributes))
		return NULL;

	if (attributes == Py_None) {
		attrs = NULL;
	} else if (PyUnicode_Check(attributes)) {
		*attrs = PyUnicode_AsUTF8(attributes);
	} else if (PySequence_Check(attributes)) {
		// FIXME
	}

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_search_ext(self->ldap, base, scope, filter, attrs,
			0, NULL, NULL, 0, 0, &msgid);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}

	return PyLong_FromLong(msgid);
}

/* vi: set noexpandtab : */
