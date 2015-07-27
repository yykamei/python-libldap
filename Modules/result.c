/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


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
		return NULL;
	}
	if ((PyList_Append(values, PyUnicode_FromString(bv.bv_val))) == -1) {
		XDECREF_MANY(entry, order, values);
		return NULL;
	}
	if (PyDict_SetItemString(entry, "dn", values) == -1) {
		XDECREF_MANY(entry, order, values);
		return NULL;
	}
	if (PyDict_SetItemString(entry, "__order__", order) == -1) {
		XDECREF_MANY(entry, order, values);
		return NULL;
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
			return NULL;
		}
		if ((PyDict_SetItemString(entry, bv.bv_val, values)) == -1) {
			XDECREF_MANY(entry, order, values);
			return NULL;
		}

		/* Set values */
		if (bvals) {
			for (i = 0; bvals[i].bv_val != NULL; i++) {
				if ((PyList_Append(values, PyUnicode_FromString(bvals[i].bv_val))) == -1) {
					XDECREF_MANY(entry, order, values);
					return NULL;
				}
			}
			ber_memfree(bvals);
		}
	}

	if (ber != NULL)
		ber_free(ber, 0);

	return entry;
}


static PyObject *
parse_result(LDAP *ldap, LDAPMessage *msg)
{
	int rc;
	int err;
	char *errormsg = NULL;
	char **referrals = NULL;
	LDAPControl **serverctrls = NULL;
	PyObject *result = NULL;
	int set_rc;
	PyObject *refs = NULL;

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_parse_result(ldap, msg, &err, NULL, &errormsg,
			&referrals, &serverctrls, 0);
	LDAP_END_ALLOW_THREADS
	if (rc == LDAP_SUCCESS)
		rc = err;

	if ((result = PyDict_New()) == NULL)
		return NULL;

	set_rc = PyDict_SetItemString(result, "return", PyLong_FromLong(rc));
	if (set_rc == -1) {
		XDECREF_MANY(result);
		return NULL;
	}
	set_rc = PyDict_SetItemString(result, "message",
			PyUnicode_FromString(ldap_err2string(rc)));
	if (set_rc == -1) {
		XDECREF_MANY(result);
		return NULL;
	}
	if (errormsg) {
		set_rc = PyDict_SetItemString(result, "error_message",
				PyUnicode_FromString(errormsg));
		ldap_memfree(errormsg);
		if (set_rc == -1) {
			XDECREF_MANY(result);
			return NULL;
		}
	} else {
		set_rc = PyDict_SetItemString(result, "error_message", Py_None);
		if (set_rc == -1) {
			XDECREF_MANY(result);
			return NULL;
		}
	}
	if (referrals && *referrals) {
		int i;
		if ((refs = PyList_New(0)) == NULL) {
			XDECREF_MANY(result);
			return NULL;
		}
		for (i = 0; referrals[i]; i++) {
			set_rc = PyList_Append(refs, PyUnicode_FromString(referrals[i]));
			if (set_rc == -1) {
				XDECREF_MANY(result, refs);
				return NULL;
			}
		}
		set_rc = PyDict_SetItemString(result, "referrals", refs);
		if (set_rc == -1) {
			XDECREF_MANY(result, refs);
			return NULL;
		}
	} else {
		if ((refs = PyList_New(0)) == NULL) {
			XDECREF_MANY(result);
			return NULL;
		}
		set_rc = PyDict_SetItemString(result, "referrals", refs);
		if (set_rc == -1) {
			XDECREF_MANY(result, refs);
			return NULL;
		}
	}
	return result;
}


PyObject *
LDAPObject_result(LDAPObject *self, PyObject *args)
{
	int msgid = LDAP_RES_ANY;
	int all = LDAP_MSG_ALL;
	PyObject *result = NULL;
	int rc;
	LDAPMessage *res;
	PyObject *message = NULL;
	LDAPMessage *msg;

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
		XDECREF_MANY(result);
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	} else if (rc == 0) {
		XDECREF_MANY(result);
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
					return NULL;
				}
				if (PyList_Append(result, message) == -1) {
					ldap_msgfree(res);
					XDECREF_MANY(result, message);
					return NULL;
				}
				break;
			case LDAP_RES_SEARCH_RESULT:
				/* FIXME */
				break;
			case LDAP_RES_BIND:
			case LDAP_RES_ADD:
			case LDAP_RES_MODIFY:
			case LDAP_RES_DELETE:
			case LDAP_RES_MODDN:
			case LDAP_RES_COMPARE:
				XDECREF_MANY(result);
				result = parse_result(self->ldap, msg);
				if (result == NULL)
					return NULL;
				return result;
		}
	}
	ldap_msgfree(res);
	return result;
}

/* vi: set noexpandtab : */
