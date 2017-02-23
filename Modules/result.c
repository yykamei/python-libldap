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
	PyObject *v = NULL;

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
		PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
		return NULL;
	}

	/* Set DN and __order__ */
	v = PyUnicode_FromString(bv.bv_val);
	if (PyDict_SetItemString(entry, "dn", v) == -1) {
		XDECREF_MANY(entry, order, values);
		return NULL;
	}
	Py_XDECREF(v);

	if (PyDict_SetItemString(entry, "__order__", order) == -1) {
		XDECREF_MANY(entry, order, values);
		return NULL;
	}
	Py_XDECREF(order);

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
		v = PyUnicode_FromString(bv.bv_val);
		if (PyList_Append(order, v) == -1) {
			XDECREF_MANY(entry, order, values);
			return NULL;
		}
		Py_XDECREF(v);

		if ((PyDict_SetItemString(entry, bv.bv_val, values)) == -1) {
			XDECREF_MANY(entry, order, values);
			return NULL;
		}

		/* Set values */
		if (bvals) {
			for (i = 0; bvals[i].bv_val != NULL; i++) {
				v = PyBytes_FromStringAndSize(bvals[i].bv_val, bvals[i].bv_len);
				if (PyList_Append(values, v) == -1) {
					XDECREF_MANY(entry, order, values);
					return NULL;
				}
				Py_XDECREF(v);
			}
			ber_memfree(bvals);
		}
	}

	if (ber != NULL)
		ber_free(ber, 0);

	return entry;
}


static int
parse_ctrls_result(LDAP *ldap, LDAPObjectControl *ldapoc, LDAPControl **sctrls, PyObject *result)
{
	int i;
	int rc;
	int set_rc;
	LDAPControl *ctrl = NULL;

	assert(ldapoc != NULL);
	assert(sctrls != NULL);

	for (i = 0; sctrls[i]; i++) {
		if (strcmp(sctrls[i]->ldctl_oid, LDAP_CONTROL_PAGEDRESULTS) == 0) {
			struct berval value;
			ber_int_t estimate;
			rc = ldap_parse_pageresponse_control(ldap, sctrls[i],
					&estimate, &ldapoc->pr_cookie);
			if (rc != LDAP_SUCCESS) {
				PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
				return -1;
			}
			ctrl = ldap_control_find(LDAP_CONTROL_PAGEDRESULTS, ldapoc->sctrls, NULL);
			rc = ldap_create_page_control_value(ldap, ldapoc->pagesize,
					&ldapoc->pr_cookie, &value);
			if (rc != LDAP_SUCCESS) {
				PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
				return -1;
			}
			ctrl->ldctl_value.bv_val = value.bv_val;
			ctrl->ldctl_value.bv_len = value.bv_len;
		} else if (strcmp(sctrls[i]->ldctl_oid, LDAP_CONTROL_PASSWORDPOLICYRESPONSE) == 0) {
			ber_int_t expire;
			ber_int_t grace;
			LDAPPasswordPolicyError error;
			rc = ldap_parse_passwordpolicy_control(ldap, sctrls[i], &expire, &grace, &error);
			if (rc != LDAP_SUCCESS) {
				PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
				return -1;
			}
			set_rc = PyDict_SetItemString(result, "ppolicy_msg",
					PyUnicode_FromString(ldap_passwordpolicy_err2txt(error)));
			if (set_rc == -1)
				return -1;
			set_rc = PyDict_SetItemString(result, "ppolicy_expire", PyLong_FromLong(expire));
			if (set_rc == -1)
				return -1;
			set_rc = PyDict_SetItemString(result, "ppolicy_grace", PyLong_FromLong(grace));
			if (set_rc == -1)
				return -1;
		}
	}
	return 0;
}


static PyObject *
parse_result(LDAP *ldap, LDAPMessage *msg, int with_extended, LDAPObjectControl *ldapoc)
{
	int rc;
	int err;
	char *errormsg = NULL;
	char **referrals = NULL;
	LDAPControl **sctrls = NULL;
	PyObject *result = NULL;
	int set_rc;
	PyObject *refs = NULL;
	PyObject *v = NULL;

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_parse_result(ldap, msg, &err, NULL, &errormsg,
			&referrals, &sctrls, 0);
	LDAP_END_ALLOW_THREADS
	if (rc == LDAP_SUCCESS)
		rc = err;

	if ((result = PyDict_New()) == NULL)
		return NULL;

	v = PyLong_FromLong(rc);
	set_rc = PyDict_SetItemString(result, "return_code", v);
	if (set_rc == -1) {
		XDECREF_MANY(result, v);
		return NULL;
	}
	Py_XDECREF(v);
	v = PyUnicode_FromString(ldap_err2string(rc));
	set_rc = PyDict_SetItemString(result, "message", v);
	if (set_rc == -1) {
		XDECREF_MANY(result, v);
		return NULL;
	}
	Py_XDECREF(v);
	if (errormsg) {
		v = PyUnicode_FromString(errormsg);
		set_rc = PyDict_SetItemString(result, "error_message", v);
		ldap_memfree(errormsg);
		if (set_rc == -1) {
			XDECREF_MANY(result, v);
			return NULL;
		}
		Py_XDECREF(v);
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
			v = PyUnicode_FromString(referrals[i]);
			set_rc = PyList_Append(refs, v);
			if (set_rc == -1) {
				XDECREF_MANY(result, refs, v);
				return NULL;
			}
			Py_XDECREF(v);
		}
		set_rc = PyDict_SetItemString(result, "referrals", refs);
		if (set_rc == -1) {
			XDECREF_MANY(result, refs);
			return NULL;
		}
		Py_XDECREF(refs);
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
		Py_XDECREF(refs);
	}

	if (sctrls && ldapoc) { /* We handle only server controls */
		if (parse_ctrls_result(ldap, ldapoc, sctrls, result) == -1) {
			XDECREF_MANY(result, refs);
			return NULL;
		}
	}

	if (with_extended) {
		char *oid;
		struct berval *data;

		LDAP_BEGIN_ALLOW_THREADS
		rc = ldap_parse_extended_result(ldap, msg, &oid, &data, 0);
		LDAP_END_ALLOW_THREADS
		if (rc != LDAP_SUCCESS) {
			XDECREF_MANY(result, refs);
			PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
			return NULL;
		}
		if (oid) {
			set_rc = PyDict_SetItemString(result, "oid", PyUnicode_FromString(oid));
			ber_memfree(oid);
		}
		if (data) {
			set_rc = PyDict_SetItemString(result, "data", PyBytes_FromString(data->bv_val));
			set_rc = PyDict_SetItemString(result, "data_length", PyLong_FromLong(data->bv_len));
			ber_bvfree(data);
		}
	}
	return result;
}


PyObject *
LDAPObject_result(LDAPObject *self, PyObject *args)
{
	int msgid = LDAP_RES_ANY;
	int all = LDAP_MSG_ALL;
	int timeout = LDAP_NO_LIMIT;
	PyObject *controls = NULL;
	LDAPObjectControl *ldapoc = NULL;
	struct timeval tv;
	struct timeval *tvp = NULL;
	PyObject *result = NULL;
	int rc;
	LDAPMessage *res;
	PyObject *message = NULL;
	LDAPMessage *msg;

	if (self->ldap == NULL) {
		PyErr_SetString(LDAPError, "This instance has already been deallocated.");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "|iiiO!", &msgid, &all, &timeout,
				&LDAPObjectControlType, &controls))
		return NULL;

	if (timeout > 0) {
		tvp = &tv;
		int2timeval(tvp, timeout);
	} else {
		tvp = NULL;
	}

	if (controls) {
		ldapoc = (LDAPObjectControl *)controls;
	}

	/* Initialize container */
	result = PyList_New(0);
	if (result == NULL)
		return PyErr_NoMemory();

	/* Get result */
	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_result(self->ldap, msgid, all, tvp, &res);
	LDAP_END_ALLOW_THREADS
	if (rc < 0) {
		XDECREF_MANY(result);
		PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
		return NULL;
	} else if (rc == 0) {
		XDECREF_MANY(result);
		PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(LDAP_TIMEOUT), LDAP_TIMEOUT);
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
				Py_DECREF(message);
				break;
			case LDAP_RES_SEARCH_RESULT:
				message = parse_result(self->ldap, msg, 0, ldapoc);
				if (message == NULL){
					ldap_msgfree(res);
					XDECREF_MANY(result);
					return NULL;
				}
				if (PyList_Append(result, message) == -1) {
					ldap_msgfree(res);
					XDECREF_MANY(result, message);
					return NULL;
				}
				Py_DECREF(message);
				break;
			case LDAP_RES_BIND:
			case LDAP_RES_ADD:
			case LDAP_RES_MODIFY:
			case LDAP_RES_DELETE:
			case LDAP_RES_MODDN:
			case LDAP_RES_COMPARE:
				XDECREF_MANY(result);
				result = parse_result(self->ldap, msg, 0, ldapoc);
				goto done;
			case LDAP_RES_EXTENDED:
				XDECREF_MANY(result);
				result = parse_result(self->ldap, msg, 1, ldapoc);
				goto done;
		}
	}
done:
	ldap_msgfree(res);
	return result;
}

/* vi: set noexpandtab : */
