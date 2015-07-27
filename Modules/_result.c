/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "_libldap.h"

static PyObject *get_entry(LDAP *ldap, LDAPMessage *msg);


PyObject *
LDAPObject_result(LDAPObject *self, PyObject *args)
{
	int msgid = LDAP_RES_ANY;
	int all = LDAP_MSG_ALL;
	LDAPMessage *res, *msg;
	int rc;
	PyObject *result = NULL, *message = NULL;

	if (!PyArg_ParseTuple(args, "|ii", &msgid, &all))
		return NULL;

	/* Initialize container */
	result = PyList_New(0);
	if (result == NULL)
		return PyErr_NoMemory();

	/* Get result */
	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_result(self->ldap, msgid, all, NULL, &res);
	LDAP_END_ALLOW_THREADS
	if (rc < 0) {
		XDECREF_MANY(result, message);
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	} else if (rc == 0) {
		XDECREF_MANY(result, message);
		PyErr_SetString(LDAPError, ldap_err2string(LDAP_TIMEOUT));
		return NULL;
	}

	for (msg = ldap_first_message(self->ldap, res);
			msg != NULL;
			msg = ldap_next_message(self->ldap, msg)) {
		switch (ldap_msgtype(msg)) {
			case LDAP_RES_SEARCH_ENTRY:
				message = get_entry(self->ldap, msg);
				if (message == NULL) {
					ldap_msgfree(res);
					XDECREF_MANY(result);
					return PyErr_NoMemory();
				}
				PyList_Append(result, message);
				break;
		}
	}
	ldap_msgfree(res);
	return result;
}


static PyObject *
get_entry(LDAP *ldap, LDAPMessage *msg)
{
	PyObject *entry = NULL, *order = NULL, *values = NULL;
	BerElement *ber = NULL;
	struct berval bv, *bvals, **bvp = &bvals;
	int i, rc;

	/* Initialize container */
	entry = PyDict_New();
	order = PyList_New(0);
	values = PyList_New(0);
	if (entry == NULL || order == NULL || values == NULL) {
		XDECREF_MANY(entry, order, values);
		return PyErr_NoMemory();
	}

	/* Get DN */
	rc = ldap_get_dn_ber(ldap, msg, &ber, &bv);
	if (rc != LDAP_SUCCESS) {
		XDECREF_MANY(entry, order, values);
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}

	/* Set DN and __order__ */
	if ((PyList_Append(order, PyUnicode_FromString("dn"))) == -1) {
		XDECREF_MANY(entry, order, values);
		return PyErr_NoMemory();
	}
	if ((PyList_Append(values, PyUnicode_FromString(bv.bv_val))) == -1) {
		XDECREF_MANY(entry, order, values);
		return PyErr_NoMemory();
	}
	if (PyDict_SetItemString(entry, "dn", values) == -1) {
		XDECREF_MANY(entry, order, values);
		return PyErr_NoMemory();
	}
	if (PyDict_SetItemString(entry, "__order__", order) == -1) {
		XDECREF_MANY(entry, order, values);
		return PyErr_NoMemory();
	}

	/* Parse attributes */
	for (rc = ldap_get_attribute_ber(ldap, msg, ber, &bv, bvp);
			rc == LDAP_SUCCESS;
			rc = ldap_get_attribute_ber(ldap, msg, ber, &bv, bvp)) {
		if (bv.bv_val == NULL)
			break;

		/* Set attribute container */
		Py_DECREF(values);
		values = PyList_New(0);
		if (values == NULL) {
			XDECREF_MANY(entry, order, values);
			return PyErr_NoMemory();
		}
		if ((PyList_Append(order, PyUnicode_FromString(bv.bv_val))) == -1) {
			XDECREF_MANY(entry, order, values);
			return PyErr_NoMemory();
		}
		if ((PyDict_SetItemString(entry, bv.bv_val, values)) == -1) {
			XDECREF_MANY(entry, order, values);
			return PyErr_NoMemory();
		}

		/* Set values */
		if (bvals) {
			for (i = 0; bvals[i].bv_val != NULL; i++) {
				PyList_Append(values, PyUnicode_FromString(bvals[i].bv_val));
			}
			ber_memfree(bvals);
		}
	}

	if (ber != NULL)
		ber_free(ber, 0);

	return entry;
}

/* vi: set noexpandtab : */
