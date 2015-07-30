/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


static PyObject *
LDAPObjectControl_add_control(LDAPObjectControl *self, PyObject *args)
{
	char *oid = NULL;
	Py_buffer view;
	int iscritical = 0;
	int is_client_control = 0;
	struct berval bv;
	struct berval *bvp;
	LDAPControl *ctrl;
	int rc;

	if (!PyArg_ParseTuple(args, "s|y*ii", &oid, &view, &iscritical, &is_client_control))
		return NULL;

	if (view.len > 0) {
		bv.bv_val = (char *)view.buf;
		bv.bv_len = (ber_len_t)view.len;
		bvp = &bv;
	} else {
		bvp = NULL;
	}

	rc = ldap_control_create(oid, iscritical, bvp, 0, &ctrl);
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}

	if (is_client_control) {
		self->cctrls = (LDAPControl **)realloc(self->cctrls, ++self->ccount + 1);
		if (self->cctrls == NULL)
			return PyErr_NoMemory();
		self->cctrls[self->ccount - 1] = ctrl;
		self->cctrls[self->ccount] = NULL;
	} else {
		self->sctrls = (LDAPControl **)realloc(self->sctrls, ++self->scount + 1);
		if (self->sctrls == NULL)
			return PyErr_NoMemory();
		self->sctrls[self->scount - 1] = ctrl;
		self->sctrls[self->scount] = NULL;
	}
	Py_RETURN_NONE;
}


static PyObject *
LDAPObjectControl_add_page_control(LDAPObjectControl *self, PyObject *args)
{
	int pagesize;
	int iscritical = 0;
	int is_client_control = 0;
	int rc;
	BerElement *ber;
	ber_tag_t tag;
	struct berval value;
	LDAPControl *ctrl;

	if (!PyArg_ParseTuple(args, "i|ii", &pagesize, &iscritical, &is_client_control))
		return NULL;

	ber = ber_alloc_t(LBER_USE_DER);
	if (ber == NULL)
		return PyErr_NoMemory();

	tag = ber_printf(ber, "{iO}", pagesize, &self->pr_cookie);
	if (tag == LBER_ERROR) {
		if (ber != NULL)
			ber_free(ber, 1);
		PyErr_SetString(LDAPError, ldap_err2string(LDAP_ENCODING_ERROR));
		return NULL;
	}

	if (ber_flatten2(ber, &value, 1) == -1) {
		if (ber != NULL)
			ber_free(ber, 1);
		return PyErr_NoMemory();
	}

	rc = ldap_control_create(LDAP_CONTROL_PAGEDRESULTS, iscritical, &value, 0, &ctrl);
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}

	if (is_client_control) {
		self->cctrls = (LDAPControl **)realloc(self->cctrls, ++self->ccount + 1);
		if (self->cctrls == NULL)
			return PyErr_NoMemory();
		self->cctrls[self->ccount - 1] = ctrl;
		self->cctrls[self->ccount] = NULL;
	} else {
		self->sctrls = (LDAPControl **)realloc(self->sctrls, ++self->scount + 1);
		if (self->sctrls == NULL)
			return PyErr_NoMemory();
		self->sctrls[self->scount - 1] = ctrl;
		self->sctrls[self->scount] = NULL;
	}
	Py_RETURN_NONE;
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
	return (PyObject *)self;
}


/* LDAPObjectControl methods */
static PyMethodDef LDAPObjectControl_methods[] = {
	{"add_control",  (PyCFunction)LDAPObjectControl_add_control, METH_VARARGS, "add_control"},
	{"add_page_control",  (PyCFunction)LDAPObjectControl_add_page_control, METH_VARARGS, "add_page_control"},
	{NULL, NULL, 0, NULL}        /* Sentinel */
};


/* LDAPObjectControlType definition */
PyTypeObject LDAPObjectControlType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_libldap._LDAPObjectControl",         /* tp_name */
	sizeof(LDAPObjectControl),             /* tp_basicsize */
	0,                                     /* tp_itemsize */
	(destructor)LDAPObjectControl_dealloc, /* tp_dealloc */
	0,                                     /* tp_print */
	0,                                     /* tp_getattr */
	0,                                     /* tp_setattr */
	0,                                     /* tp_reserved */
	0,                                     /* tp_repr */
	0,                                     /* tp_as_number */
	0,                                     /* tp_as_sequence */
	0,                                     /* tp_as_mapping */
	0,                                     /* tp_hash  */
	0,                                     /* tp_call */
	0,                                     /* tp_str */
	0,                                     /* tp_getattro */
	0,                                     /* tp_setattro */
	0,                                     /* tp_as_buffer */
	Py_TPFLAGS_DEFAULT |
	    Py_TPFLAGS_BASETYPE,               /* tp_flags */
	"LDAPControl object",                  /* tp_doc */
	0,                                     /* tp_traverse */
	0,                                     /* tp_clear */
	0,                                     /* tp_richcompare */
	0,                                     /* tp_weaklistoffset */
	0,                                     /* tp_iter */
	0,                                     /* tp_iternext */
	LDAPObjectControl_methods,            /* tp_methods */
	0,                                     /* tp_members */
	0,                                     /* tp_getset */
	0,                                     /* tp_base */
	0,                                     /* tp_dict */
	0,                                     /* tp_descr_get */
	0,                                     /* tp_descr_set */
	0,                                     /* tp_dictoffset */
	0,                                     /* tp_init */
	0,                                     /* tp_alloc */
	LDAPObjectControl_new,                 /* tp_new */
};

/* vi: set noexpandtab : */
