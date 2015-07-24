/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "_libldap.h"


PyObject *
get_entry(LDAP *ldap, LDAPMessage *msg)
{
	PyObject *entry = NULL, *order = NULL, *values = NULL, *val = NULL;
	BerElement *ber = NULL;
	struct berval bv, *bvals, **bvp = &bvals;
	int i, rc;

	/* Initialize container */
	entry = PyDict_New();
	order = PyList_New(0);
	values = PyList_New(0);
	if (entry == NULL || order == NULL || values == NULL)
		goto nomem;

	/* Get DN */
	rc = ldap_get_dn_ber(ldap, msg, &ber, &bv);
	if (rc != LDAP_SUCCESS)
		goto failed;

	/* Set DN and __order__ */
	if ((PyList_Append(order, PyUnicode_FromString("dn"))) == -1)
		goto nomem;
	if ((PyList_Append(values, PyUnicode_FromString(bv.bv_val))) == -1)
		goto nomem;
	if (PyDict_SetItemString(entry, "dn", values) == -1)
		goto nomem;
	if (PyDict_SetItemString(entry, "__order__", order) == -1)
		goto nomem;

	/* Parse attributes */
	for (rc = ldap_get_attribute_ber(ldap, msg, ber, &bv, bvp);
			rc == LDAP_SUCCESS;
			rc = ldap_get_attribute_ber(ldap, msg, ber, &bv, bvp)) {
		if (bv.bv_val == NULL)
			break;

		/* Set attribute container */
		Py_DECREF(values);
		values = PyList_New(0);
		if (values == NULL)
			goto nomem;
		if ((PyList_Append(order, PyUnicode_FromString(bv.bv_val))) == -1)
			goto nomem;
		if ((PyDict_SetItemString(entry, bv.bv_val, values)) == -1)
			goto nomem;

		/* Set values */
		if (bvals) {
			for (i = 0; bvals[i].bv_val != NULL; i++) {
				val = PyUnicode_FromString(bvals[i].bv_val);
				PyList_Append(values, val);
			}
			ber_memfree(bvals);
		}
	}

	if (ber != NULL)
		ber_free(ber, 0);

	return entry;

failed:
	Py_XDECREF(val);
	Py_XDECREF(values);
	Py_XDECREF(order);
	Py_XDECREF(entry);
	PyErr_SetString(LDAPError, ldap_err2string(rc));
	return NULL;

nomem:
	Py_XDECREF(val);
	Py_XDECREF(values);
	Py_XDECREF(order);
	Py_XDECREF(entry);
	return PyErr_NoMemory();
}

/* vi: set noexpandtab : */
