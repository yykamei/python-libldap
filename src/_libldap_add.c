/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "_libldap.h"

static LDAPMod **get_attributes(PyObject *dict);
static void dealloc(LDAPMod **attrs);


PyObject *
LDAPObject_add(LDAPObject *self, PyObject *args)
{
	const char *dn;
	PyObject *attributes;
	LDAPMod **attrs;
	LDAPControl *sctrls = NULL;
	int rc, msgid;

	if (!PyArg_ParseTuple(args, "sO", &dn, &attributes))
		return NULL;

	if (!PyDict_Check(attributes)) {
		XDECREF_MANY(&attributes);
		PyErr_SetString(PyExc_ValueError, "'attributes' MUST be dict type");
		return NULL;
	}

	attrs = get_attributes(attributes);
	if (attrs == NULL) {
		XDECREF_MANY(&attributes);
		return NULL;
	}

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_add_ext(self->ldap, dn, attrs, sctrls, NULL, &msgid);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}

	return PyLong_FromLong(msgid);
}


static LDAPMod **
get_attributes(PyObject *dict)
{
	LDAPMod *attr = NULL, **attrs = NULL;
	Py_ssize_t pos, size, i;
	PyObject *key, *value, *val;
	struct berval *bvals;

	pos = PyDict_Size(dict);
	attrs = (LDAPMod **)malloc((LDAPMod *) * pos);
	if (attrs == NULL)
		return PyErr_NoMemory();

	pos = 0;
	while (PyDict_Next(dict, &pos, &key, &value)) {
		if (!PyUnicode_Check(key)) {
			PyErr_SetString(PyExc_ValueError, "Each key MUST be str type");
			return NULL;
		}
		if (!PyList_Check(value)) {
			PyErr_SetString(PyExc_ValueError, "Each value MUST be list type");
			return NULL;
		}

		attr = (LDAPMod *)malloc(sizeof(LDAPMod));
		attr->mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
		attr->mod_bvalues = NULL;

		/* Attribute */
		if ((attr->mod_type = PyUnicode_AsUTF8(key)) == NULL) {
			dealloc(attrs);
			return PyErr_NoMemory();
		}

		/* Values */
		size = PyList_GET_SIZE(value);
		for (i = 0; i < size; i++) {
			val = PyList_GET_ITEM(value, i);
			if (PyUnicode_Check(val)) {
			}
		}
	}
}


static void
dealloc(LDAPMod **attrs)
{
}

/* vi: set noexpandtab : */
