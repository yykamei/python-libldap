/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "_libldap.h"


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

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_initialize(&ld, uri);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return -1;
	}

	ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &protocol);

	/* Create new instance */
	self->ldap = ld;
	return 0;
}


static PyObject *
LDAPObject_bind(LDAPObject *self, PyObject *args)
{
	const char *who;
	const char *password;
	struct berval passwd = {0, NULL};
	LDAPMessage *result = NULL;
	int rc, msgid, err;
	char *matched = NULL;
	char *info = NULL;
	char **refs = NULL;
	LDAPControl **ctrls = NULL;
	
	if (!PyArg_ParseTuple(args, "ss", &who, &password))
		return NULL;

	// ldap_set_option
	// ldap_start_tls_s
	passwd.bv_val = ber_strdup(password);
	passwd.bv_len = strlen(passwd.bv_val);

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_sasl_bind(self->ldap, who, LDAP_SASL_SIMPLE, &passwd, NULL, NULL, &msgid); // CONTROL
	LDAP_END_ALLOW_THREADS
	if (msgid == -1) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_result(self->ldap, msgid, LDAP_MSG_ALL, NULL, &result);
	LDAP_END_ALLOW_THREADS
	if (rc == -1) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	} else if (rc == 0) {
		PyErr_SetString(LDAPError, ldap_err2string(LDAP_TIMEOUT));
		return NULL;
	}

	if (result) {
		LDAP_BEGIN_ALLOW_THREADS
		rc = ldap_parse_result(self->ldap, result, &err, &matched, &info, &refs, &ctrls, 1);
		LDAP_END_ALLOW_THREADS
		if (rc != LDAP_SUCCESS) {
			PyErr_SetString(LDAPError, ldap_err2string(rc));
			return NULL;
		}
	}
	if (err != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(err));
		return NULL;
	}
	Py_RETURN_TRUE;
}

static PyObject *
LDAPObject_search(LDAPObject *self, PyObject *args)
{
	char *base;
	int scope;
	char *filter;
	PyObject *py_attributes = Py_None;
	char **attributes = NULL;
	int rc, msgid;

	if (!PyArg_ParseTuple(args, "sis|O", &base, &scope, &filter, &py_attributes))
		return NULL;

	if (py_attributes == Py_None) {
		attributes = NULL;
	} else if (PyUnicode_Check(py_attributes)) {
		*attributes = PyUnicode_AsUTF8(py_attributes);
	} else if (PySequence_Check(py_attributes)) {
		// FIXME
	}

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_search_ext(self->ldap, base, scope, filter, attributes,
			0, NULL, NULL, 0, 0, &msgid);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}

	return PyLong_FromLong(msgid);
}


static PyObject *
LDAPObject_result(LDAPObject *self, PyObject *args)
{
	int msgid = LDAP_RES_ANY;
	int all = LDAP_MSG_ONE;
	LDAPMessage *res, *msg;
	int rc, err;
	char *matched = NULL;
	char *info = NULL;
	char **refs = NULL;
	LDAPControl **ctrls = NULL;
	PyObject *result = NULL, *entry = NULL;

	if (!PyArg_ParseTuple(args, "|ii", &msgid, &all))
		return NULL;

	/* Initialize container */
	result = PyList_New(0);
	if (result == NULL)
		return PyErr_NoMemory();

	LDAP_BEGIN_ALLOW_THREADS
	while ((rc = ldap_result(self->ldap, msgid, all, NULL, &res)) > 0) {
		for (msg = ldap_first_message(self->ldap, res);
				msg != NULL;
				msg = ldap_next_message(self->ldap, msg)) {
			switch(ldap_msgtype(msg)) {
				case LDAP_RES_SEARCH_ENTRY:
					entry = get_entry(self->ldap, msg);
					if (entry == NULL)
						goto failed;
					PyList_Append(result, entry);
					break;
				case LDAP_RES_SEARCH_RESULT:
					rc = ldap_parse_result(self->ldap, res, &err, &matched, &info, &refs, &ctrls, 0);
					if (rc != LDAP_SUCCESS) {
						err = rc;
						goto done;
					}
					goto done;
			}
		}
		ldap_msgfree(res);
	}
done:
	LDAP_END_ALLOW_THREADS
	ldap_msgfree(res);
	if (err != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(err));
		return NULL;
	}
	return result;

failed:
	Py_XDECREF(result);
	Py_XDECREF(entry);
	return NULL;
}


/* operations definition */
static PyMethodDef LDAPObject_methods[] = {
	{"bind",  (PyCFunction)LDAPObject_bind, METH_VARARGS, "bind"},
	{"search",  (PyCFunction)LDAPObject_search, METH_VARARGS, "search"},
	{"result",  (PyCFunction)LDAPObject_result, METH_VARARGS, "result"},
	{NULL, NULL, 0, NULL}        /* Sentinel */
};


/* Type definition */
static PyTypeObject LDAPType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_libldap.LDAPObject",             /* tp_name */
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

	if (PyType_Ready(&LDAPType) < 0)
		return NULL;

	m = PyModule_Create(&module);
	if (m == NULL)
		return NULL;

	LDAPError = PyErr_NewException("_libldap.LDAPError", NULL, NULL);
	Py_INCREF(LDAPError);
	PyModule_AddObject(m, "LDAPError", LDAPError);

	Py_INCREF(&LDAPType);
	PyModule_AddObject(m, "LDAPObject", (PyObject *)&LDAPType);

	return m;
}

/* vi: set noexpandtab : */
