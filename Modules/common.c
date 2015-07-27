/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


void
_XDECREF_MANY(PyObject *objs[], size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		Py_XDECREF(objs[i]);
	}
}


static struct berval *
str2berval(PyObject *str)
{
	struct berval *bv;

	bv = (struct berval *)PyMem_RawMalloc(sizeof(struct berval));
	if (bv == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (!PyUnicode_Check(str)) {
		PyMem_RawFree(bv);
		PyErr_SetString(LDAPError, "Each Item of value MUST be str type");
		return NULL;
	}
	bv->bv_val = PyUnicode_AsUTF8(str);
	if (bv->bv_val == NULL) {
		PyMem_RawFree(bv);
		return NULL;
	}
	bv->bv_len = (ber_len_t)strlen(bv->bv_val);
	return bv;
}


static LDAPMod *
attribute_spec2LDAPMod(PyObject *attribute, PyObject *value, int mod_op)
{
	LDAPMod *mod;
	int len;
	Py_ssize_t i;
	PyObject *val;

	if (!PyUnicode_Check(attribute)) {
		PyErr_SetString(PyExc_ValueError, "Attribute MUST be str type");
		return NULL;
	}

	if (!PyList_Check(value)) {
		PyErr_SetString(PyExc_ValueError, "Value MUST be list type");
		return NULL;
	}

	mod = (LDAPMod *)PyMem_RawMalloc(sizeof(LDAPMod));
	if (mod == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	len = PyList_GET_SIZE(value);
	mod->mod_op = mod_op;
	mod->mod_type = PyUnicode_AsUTF8(attribute);
	if (mod->mod_type == NULL) {
		PyMem_RawFree(mod);
		return NULL;
	}
	mod->mod_bvalues = (struct berval **)PyMem_RawMalloc(sizeof(struct berval *) * (len + 1));
	if (mod ->mod_bvalues == NULL) {
		PyMem_RawFree(mod);
		PyErr_NoMemory();
		return NULL;
	}
	for (i = 0; i < len; i++) {
		val = PyList_GET_ITEM(value, i);
		mod->mod_bvalues[i] = str2berval(val);
		if (mod->mod_bvalues[i] == NULL) {
			PyMem_RawFree(mod->mod_bvalues);
			PyMem_RawFree(mod);
			return NULL;
		}
	}
	mod->mod_bvalues[len] = NULL;
	return mod;
}


LDAPMod **
python2LDAPMods(PyObject *list)
{
	Py_ssize_t len;
	LDAPMod **mods;
	Py_ssize_t i;
	PyObject *attribute_spec;
	Py_ssize_t tuple_size;
	PyObject *attribute = NULL;
	PyObject *value = NULL;
	int mod_op;

	if (!PyList_Check(list)) {
		PyErr_SetString(PyExc_ValueError, "Object MUST be list type");
		return NULL;
	}

	len = PyList_GET_SIZE(list);
	mods = (LDAPMod **)PyMem_RawMalloc(sizeof(LDAPMod *) * (len + 1));
	if (mods == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	for (i = 0; i < len; i++) {
		attribute_spec = PyList_GET_ITEM(list, i);
		if (!PyTuple_Check(attribute_spec)) {
			PyMem_RawFree(mods);
			PyErr_SetString(LDAPError, "Each Item of list MUST be tuple type");
			return NULL;
		}
		tuple_size = PyTuple_GET_SIZE(attribute_spec);
		if (tuple_size == 2) {
			attribute = PyTuple_GET_ITEM(attribute_spec, 0);
			value = PyTuple_GET_ITEM(attribute_spec, 1);
			mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
		} else if (tuple_size == 3) {
			attribute = PyTuple_GET_ITEM(attribute_spec, 0);
			value = PyTuple_GET_ITEM(attribute_spec, 1);
			mod_op = (int)PyLong_AsLong(PyTuple_GET_ITEM(attribute_spec, 2)) | LDAP_MOD_BVALUES;
		} else {
			PyMem_RawFree(mods);
			PyErr_SetString(LDAPError, "Each tuple item MUST have two or three items");
			return NULL;
		}
		mods[i] = attribute_spec2LDAPMod(attribute, value, mod_op);
		if (mods[i] == NULL) {
			return NULL;
		}
	}
	mods[len] = NULL;
	return mods;
}


/* vi: set noexpandtab : */
