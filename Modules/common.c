/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"

#define TUPLE_SIZE_ADD 2
#define TUPLE_SIZE_MOD 3


void
_XDECREF_MANY(PyObject *objs[], size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		Py_XDECREF(objs[i]);
	}
}


void
int2timeval(struct timeval *tv, int i)
{
	tv->tv_usec = 0;
	tv->tv_sec = (long)i;
}

void
free_LDAPMods(LDAPMod **mods)
{
	LDAPMod **init_mods = mods;
	struct berval **bv = NULL;
	struct berval **init_bv = NULL;

	if (init_mods == NULL)
		return;
	for (; *mods; mods++) {
		if ((*mods)->mod_bvalues) {
			bv = (*mods)->mod_bvalues;
			init_bv = bv;
			for (; *bv; bv++) {
				/* Fill the free space with poison */
				memset(*bv, 0xFF, sizeof(struct berval));
				PyMem_RawFree(*bv);
			}
			PyMem_RawFree(init_bv);
		}
		PyMem_RawFree(*mods);
	}
	PyMem_RawFree(init_mods);
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

	if (PyUnicode_Check(str)) {  /* str -> (char *) */
		bv->bv_val = PyUnicode_AsUTF8(str);
		if (bv->bv_val == NULL)
			return NULL;
		bv->bv_len = (ber_len_t)strlen(bv->bv_val);
	} else if (PyBytes_Check(str)) {  /* bytes -> (char *) */
		bv->bv_val = PyBytes_AsString(str);
		bv->bv_len = (ber_len_t)PyBytes_GET_SIZE(str);
		if (bv->bv_val == NULL)
			return NULL;
	} else {
		PyErr_SetString(LDAPError, "Each Item of value MUST be str or bytes type");
		return NULL;
	}
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
		return NULL;
	}
	mod->mod_bvalues = (struct berval **)PyMem_RawMalloc(sizeof(struct berval *) * (len + 1));
	memset(mod->mod_bvalues, 0, sizeof(struct berval *) * (len + 1));
	if (mod ->mod_bvalues == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	for (i = 0; i < len; i++) {
		val = PyList_GET_ITEM(value, i);
		mod->mod_bvalues[i] = str2berval(val);
		if (mod->mod_bvalues[i] == NULL) {
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
	memset(mods, 0, sizeof(LDAPMod *) * (len + 1));

	for (i = 0; i < len; i++) {
		attribute_spec = PyList_GET_ITEM(list, i);
		if (!PyTuple_Check(attribute_spec)) {
			free_LDAPMods(mods);
			PyErr_SetString(LDAPError, "Each Item of list MUST be tuple type");
			return NULL;
		}
		tuple_size = PyTuple_GET_SIZE(attribute_spec);
		if (tuple_size == TUPLE_SIZE_ADD) {
			attribute = PyTuple_GET_ITEM(attribute_spec, 0);
			value = PyTuple_GET_ITEM(attribute_spec, 1);
			mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
		} else if (tuple_size == TUPLE_SIZE_MOD) {
			attribute = PyTuple_GET_ITEM(attribute_spec, 0);
			value = PyTuple_GET_ITEM(attribute_spec, 1);
			mod_op = (int)PyLong_AsLong(PyTuple_GET_ITEM(attribute_spec, 2)) | LDAP_MOD_BVALUES;
		} else {
			free_LDAPMods(mods);
			PyErr_SetString(LDAPError, "Each tuple item MUST have two or three items");
			return NULL;
		}
		mods[i] = attribute_spec2LDAPMod(attribute, value, mod_op);
		if (mods[i] == NULL) {
			free_LDAPMods(mods);
			return NULL;
		}
	}
	mods[len] = NULL;
	return mods;
}


/* vi: set noexpandtab : */
