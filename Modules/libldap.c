/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


static char ldap_doc[] =
	"A Python binding for ldap"
	"\n"
;

PyObject *LDAPError;


static struct PyModuleDef module = {
	PyModuleDef_HEAD_INIT,
	"_libldap",   /* name of module */
	ldap_doc,     /* module documentation, may be NULL */
	-1,           /* module keeps state in global variables */
	NULL, NULL, NULL, NULL, NULL
};


static void
LDAPObject_dealloc(LDAPObject *self)
{
	if (self->ldap) {
		LDAP_BEGIN_ALLOW_THREADS
		ldap_unbind_ext(self->ldap, NULL, NULL);
		LDAP_END_ALLOW_THREADS
		self->ldap = NULL;
	}
	Py_TYPE(self)->tp_free((PyObject*)self);
}


static PyObject *
LDAPObject_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	LDAPObject *self;
	self = (LDAPObject *)type->tp_alloc(type, 0);
	self->ldap = NULL;
	return (PyObject *)self;
}


static int
LDAPObject_init(LDAPObject *self, PyObject *args, PyObject *kwargs)
{
	const char *uri;
	LDAP *ld;
	int protocol = 3;
	int rc;

	if (!PyArg_ParseTuple(args, "s", &uri))
		return -1;

	rc = ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, &protocol);
	if (rc != LDAP_OPT_SUCCESS) {
		PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
		return -1;
	}

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_initialize(&ld, uri);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		PyErr_Format(LDAPError, "%s (%d)", ldap_err2string(rc), rc);
		return -1;
	}

	/* Create new instance */
	self->ldap = ld;
	return 0;
}


/* LDAPObject methods */
static PyMethodDef LDAPObject_methods[] = {
	{"bind",  (PyCFunction)LDAPObject_bind, METH_VARARGS, "bind"},
	{"unbind",  (PyCFunction)LDAPObject_unbind, METH_VARARGS, "unbind"},
	{"search",  (PyCFunction)LDAPObject_search, METH_VARARGS, "search"},
	{"add",  (PyCFunction)LDAPObject_add, METH_VARARGS, "add"},
	{"modify",  (PyCFunction)LDAPObject_modify, METH_VARARGS, "modify"},
	{"delete",  (PyCFunction)LDAPObject_delete, METH_VARARGS, "delete"},
	{"rename",  (PyCFunction)LDAPObject_rename, METH_VARARGS, "rename"},
	{"compare",  (PyCFunction)LDAPObject_compare, METH_VARARGS, "compare"},
	{"abandon",  (PyCFunction)LDAPObject_abandon, METH_VARARGS, "abandon"},
	{"whoami",  (PyCFunction)LDAPObject_whoami, METH_VARARGS, "whoami"},
	{"passwd",  (PyCFunction)LDAPObject_passwd, METH_VARARGS, "passwd"},
	{"cancel",  (PyCFunction)LDAPObject_cancel, METH_VARARGS, "cancel"},
	{"start_tls",  (PyCFunction)LDAPObject_start_tls, METH_VARARGS, "start_tls"},
	{"set_option",  (PyCFunction)LDAPObject_set_option, METH_VARARGS, "set_option"},
	{"get_option",  (PyCFunction)LDAPObject_get_option, METH_VARARGS, "get_option"},
	{"result",  (PyCFunction)LDAPObject_result, METH_VARARGS, "result"},
	{NULL, NULL, 0, NULL}        /* Sentinel */
};


/* LDAPObjectType definition */
PyTypeObject LDAPObjectType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_libldap._LDAPObject",         /* tp_name */
	sizeof(LDAPObject),             /* tp_basicsize */
	0,                              /* tp_itemsize */
	(destructor)LDAPObject_dealloc, /* tp_dealloc */
	0,                              /* tp_print */
	0,                              /* tp_getattr */
	0,                              /* tp_setattr */
	0,                              /* tp_reserved */
	0,                              /* tp_repr */
	0,                              /* tp_as_number */
	0,                              /* tp_as_sequence */
	0,                              /* tp_as_mapping */
	0,                              /* tp_hash  */
	0,                              /* tp_call */
	0,                              /* tp_str */
	0,                              /* tp_getattro */
	0,                              /* tp_setattro */
	0,                              /* tp_as_buffer */
	Py_TPFLAGS_DEFAULT |
	    Py_TPFLAGS_BASETYPE,        /* tp_flags */
	"LDAP object",                  /* tp_doc */
	0,                              /* tp_traverse */
	0,                              /* tp_clear */
	0,                              /* tp_richcompare */
	0,                              /* tp_weaklistoffset */
	0,                              /* tp_iter */
	0,                              /* tp_iternext */
	LDAPObject_methods,             /* tp_methods */
	0,                              /* tp_members */
	0,                              /* tp_getset */
	0,                              /* tp_base */
	0,                              /* tp_dict */
	0,                              /* tp_descr_get */
	0,                              /* tp_descr_set */
	0,                              /* tp_dictoffset */
	(initproc)LDAPObject_init,      /* tp_init */
	0,                              /* tp_alloc */
	LDAPObject_new,                 /* tp_new */
};


/* Python module initialization */
PyMODINIT_FUNC
PyInit__libldap(void)
{
	PyObject *m;

	if (PyType_Ready(&LDAPObjectType) < 0)
		return NULL;

	if (PyType_Ready(&LDAPObjectControlType) < 0)
		return NULL;

	m = PyModule_Create(&module);
	if (m == NULL)
		return NULL;

	LDAPError = PyErr_NewException("_libldap._LDAPError", NULL, NULL);
	Py_INCREF(LDAPError);
	PyModule_AddObject(m, "_LDAPError", LDAPError);

	Py_INCREF(&LDAPObjectType);
	PyModule_AddObject(m, "_LDAPObject", (PyObject *)&LDAPObjectType);

	Py_INCREF(&LDAPObjectControlType);
	PyModule_AddObject(m, "_LDAPObjectControl", (PyObject *)&LDAPObjectControlType);

	return m;
}

/* vi: set noexpandtab : */
