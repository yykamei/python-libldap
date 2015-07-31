/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


static LDAPControl *
create_page_control(LDAPObjectControl *self, struct berval *bv, int iscritical)
{
	LDAPControl *ctrl = NULL;
	int rc;
	ber_int_t pagesize = (ber_int_t)atoi(bv->bv_val);
	LDAP *ldap;

	/* Dummy session */
	rc = ldap_initialize(&ldap, NULL);
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}

	if (pagesize == 0) {
		ldap_unbind_ext_s(ldap, NULL, NULL);
		PyErr_SetString(LDAPError, "Must be integer");
		return NULL;
	}
	rc = ldap_create_page_control(ldap, pagesize, &self->pr_cookie, iscritical, &ctrl);
	if (rc != LDAP_SUCCESS) {
		ldap_unbind_ext_s(ldap, NULL, NULL);
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}
	ldap_unbind_ext_s(ldap, NULL, NULL);
	self->pagesize = pagesize;
	return ctrl;
}


static PyObject *
LDAPObjectControl_add_control(LDAPObjectControl *self, PyObject *args)
{
	char *oid = NULL;
	Py_buffer view = {NULL, NULL};
	int iscritical = 0;
	int is_client_control = 0;
	struct berval *bvp = NULL;
	LDAPControl *ctrl;
	LDAPControl **ctrls;
	LDAPControl ***lctrls;
	int *count;
	int rc;

	if (!PyArg_ParseTuple(args, "s|y*ii", &oid, &view, &iscritical, &is_client_control))
		return NULL;

	if (view.buf != NULL)
		bvp = ber_bvstrdup((const char *)view.buf);

	if (strcmp(oid, LDAP_CONTROL_PAGEDRESULTS) == 0) {
		ctrl = create_page_control(self, bvp, iscritical);
		if (ctrl == NULL) {
			ber_bvfree(bvp);
			return NULL;
		}
	} else {
		rc = ldap_control_create(oid, iscritical, bvp, 0, &ctrl);
		if (rc != LDAP_SUCCESS) {
			PyErr_SetString(LDAPError, ldap_err2string(rc));
			return NULL;
		}
	}

	if (is_client_control) {
		ctrls = self->cctrls;
		lctrls = &self->cctrls;
		count = &self->ccount;
	} else {
		ctrls = self->sctrls;
		lctrls = &self->sctrls;
		count = &self->scount;
	}

	if (ctrls && ldap_control_find(oid, ctrls, NULL)) {
		ldap_control_free(ctrl);
		PyErr_Format(LDAPError, "OID %s is already registered", oid);
		return NULL;
	}
	*count += 1;
	*lctrls = (LDAPControl **)realloc(ctrls, sizeof(LDAPControl *) * (*count + 1));
	if (*lctrls == NULL) {
		ldap_control_free(ctrl);
		return PyErr_NoMemory();
	}
	(*lctrls)[*count-1] = ctrl;
	(*lctrls)[*count] = NULL;

	Py_RETURN_NONE;
}


static PyObject *
LDAPObjectControl_remove_control(LDAPObjectControl *self, PyObject *args)
{
	char *oid;
	int is_client_control = 0;
	LDAPControl *ctrl;
	LDAPControl **ctrls;
	LDAPControl ***lctrls;
	int *count;

	if (!PyArg_ParseTuple(args, "s|i", &oid, &is_client_control))
		return NULL;

	if (is_client_control) {
		ctrls = self->cctrls;
		lctrls = &self->cctrls;
		count = &self->ccount;
	} else {
		ctrls = self->sctrls;
		lctrls = &self->sctrls;
		count = &self->scount;
	}

	if (ctrls == NULL) {
		PyErr_SetString(LDAPError, "No controls are set");
		return NULL;
	}

	ctrl = ldap_control_find(oid, ctrls, NULL);
	if (ctrl == NULL) {
		PyErr_Format(LDAPError, "Specified control %s is not found", oid);
		return NULL;
	}

	if (*count == 1) {
		ldap_controls_free(ctrls);
		*lctrls = NULL;
		*count = 0;
	} else {
		int i;
		for (i = 0; ctrls[i]; i++) {
			if (i != 0 && ctrls[i-1] == NULL){
				ctrls[i-1] = ctrls[i];
				ctrls[i] = NULL;
			}
			if (ctrl == ctrls[i]) {
				ctrls[i] = NULL;
			}
		}
		ctrls[i] = NULL;
		*count -= 1;
		*lctrls = (LDAPControl **)realloc(ctrls, sizeof(LDAPControl *) * (*count + 1));
		if (*lctrls == NULL) {
			return PyErr_NoMemory();
		}
	}
	Py_RETURN_NONE;
}


static PyObject *
LDAPObjectControl_list_controls(LDAPObjectControl *self, PyObject *args)
{
	int is_client_control = 0;
	PyObject *list;
	int i;

	if (!PyArg_ParseTuple(args, "|i", &is_client_control))
		return NULL;

	list = PyList_New(0);

	if (is_client_control) {
		if (self->cctrls == NULL)
			return list;
		for (i = 0; self->cctrls[i]; i++) {
			PyList_Append(list, PyUnicode_FromString(self->cctrls[i]->ldctl_oid));
		}
	} else {
		if (self->sctrls == NULL)
			return list;
		for (i = 0; self->sctrls[i]; i++) {
			PyList_Append(list, PyUnicode_FromString(self->sctrls[i]->ldctl_oid));
		}
	}
	return list;
}


static PyObject *
LDAPObjectControl_get_info(LDAPObjectControl *self, PyObject *args)
{
	char *name = NULL;

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	if (strcmp(name, "pr_cookie") == 0) {
		if (self->pr_cookie.bv_len > 0) {
			return PyBytes_FromStringAndSize(self->pr_cookie.bv_val, self->pr_cookie.bv_len);
		} else {
			Py_RETURN_NONE;
		}
	} else if (strcmp(name, "ppolicy_msg") == 0) {
		if (self->ppolicy_msg) {
			return PyUnicode_FromString(self->ppolicy_msg);
		} else {
			Py_RETURN_NONE;
		}
	} else if (strcmp(name, "ppolicy_expire") == 0) {
		return PyLong_FromLong(self->ppolicy_expire);
	} else if (strcmp(name, "ppolicy_grace") == 0) {
		return PyLong_FromLong(self->ppolicy_grace);
	} else {
		PyErr_SetString(LDAPError, "Unknown");
		return NULL;
	}
}


static void
LDAPObjectControl_dealloc(LDAPObjectControl *self)
{
	if (self->sctrls) {
		LDAP_BEGIN_ALLOW_THREADS
		ldap_controls_free(self->sctrls);
		LDAP_END_ALLOW_THREADS
		self->sctrls = NULL;
	}
	if (self->cctrls) {
		LDAP_BEGIN_ALLOW_THREADS
		ldap_controls_free(self->cctrls);
		LDAP_END_ALLOW_THREADS
		self->cctrls = NULL;
	}
	if (self->pr_cookie.bv_val) {
		ber_memfree(self->pr_cookie.bv_val);
		self->pr_cookie.bv_val = NULL;
		self->pr_cookie.bv_len = 0;
	}
	Py_TYPE(self)->tp_free((PyObject*)self);
}


static PyObject *
LDAPObjectControl_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	LDAPObjectControl *self;
	self = (LDAPObjectControl *)type->tp_alloc(type, 0);
	self->sctrls = NULL;
	self->cctrls = NULL;
	self->scount = 0;
	self->ccount = 0;
	self->pr_cookie.bv_val = NULL;
	self->pr_cookie.bv_len = 0;
	self->pagesize = 0;
	self->ppolicy_msg = NULL;
	self->ppolicy_expire = 0;
	self->ppolicy_grace = 0;
	return (PyObject *)self;
}


/* LDAPObjectControl methods */
static PyMethodDef LDAPObjectControl_methods[] = {
	{"add_control",  (PyCFunction)LDAPObjectControl_add_control,
		METH_VARARGS, "add_control"},
	{"remove_control",  (PyCFunction)LDAPObjectControl_remove_control,
		METH_VARARGS, "remove_control"},
	{"list_controls",  (PyCFunction)LDAPObjectControl_list_controls,
		METH_VARARGS, "list_controls"},
	{"get_info",  (PyCFunction)LDAPObjectControl_get_info,
		METH_VARARGS, "get_info"},
	{NULL, NULL, 0, NULL}        /* Sentinel */
};


/* LDAPObjectControlType definition */
PyTypeObject LDAPObjectControlType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_libldap._LDAPObjectControl",          /* tp_name */
	sizeof(LDAPObjectControl),              /* tp_basicsize */
	0,                                      /* tp_itemsize */
	(destructor)LDAPObjectControl_dealloc,  /* tp_dealloc */
	0,                                      /* tp_print */
	0,                                      /* tp_getattr */
	0,                                      /* tp_setattr */
	0,                                      /* tp_reserved */
	0,                                      /* tp_repr */
	0,                                      /* tp_as_number */
	0,                                      /* tp_as_sequence */
	0,                                      /* tp_as_mapping */
	0,                                      /* tp_hash  */
	0,                                      /* tp_call */
	0,                                      /* tp_str */
	0,                                      /* tp_getattro */
	0,                                      /* tp_setattro */
	0,                                      /* tp_as_buffer */
	Py_TPFLAGS_DEFAULT |
	    Py_TPFLAGS_BASETYPE,                /* tp_flags */
	"LDAPControl object",                   /* tp_doc */
	0,                                      /* tp_traverse */
	0,                                      /* tp_clear */
	0,                                      /* tp_richcompare */
	0,                                      /* tp_weaklistoffset */
	0,                                      /* tp_iter */
	0,                                      /* tp_iternext */
	LDAPObjectControl_methods,              /* tp_methods */
	0,                                      /* tp_members */
	0,                                      /* tp_getset */
	0,                                      /* tp_base */
	0,                                      /* tp_dict */
	0,                                      /* tp_descr_get */
	0,                                      /* tp_descr_set */
	0,                                      /* tp_dictoffset */
	0,                                      /* tp_init */
	0,                                      /* tp_alloc */
	LDAPObjectControl_new,                  /* tp_new */
};

/* vi: set noexpandtab : */
