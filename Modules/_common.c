/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "_libldap.h"


void
_XDECREF_MANY(PyObject **objs[], size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		printf("%p\n", *objs[i]);
		Py_XDECREF(*objs[i]);
	}
}

static LDAPMod *pair2LDAPMod(PyObject *key, PyObject *value, int mod_op);
static struct berval *str2berval(PyObject *str);
static void freeLDAPMods(LDAPMod **mods);
static void freeLDAPMod(LDAPMod *mod);


LDAPMod **
dict2LDAPMods(PyObject *dict)
{
	LDAPMod **mods;
	Py_ssize_t pos = 0, len;
	PyObject *key = NULL, *value = NULL, *mod_value = NULL;
	int mod_op;

	if (!PyDict_Check(dict)) {
		XDECREF_MANY(&dict);
		PyErr_SetString(PyExc_ValueError, "Object MUST be dict type");
		return NULL;
	}

	len = PyDict_Size(dict);
	mods = (LDAPMod **)PyMem_RawMalloc(sizeof(LDAPMod *) * len);
	if (mods == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	while (PyDict_Next(dict, &pos, &key, &value)) {
		if (!PyUnicode_Check(key)) {
			PyErr_SetString(PyExc_ValueError, "Each key MUST be str type");
			return NULL;
		}
		if (PyList_Check(value)) {
			mods[pos] = pair2LDAPMod(key, value, LDAP_MOD_ADD | LDAP_MOD_BVALUES);
			if (mods[pos] == NULL) {
				freeLDAPMods(mods);
				return NULL;
			}
		} else if (PyTuple_Check(value)) {
			if (PyTuple_GET_SIZE(value) != 2) {
				PyErr_SetString(PyExc_ValueError, "Size of tuple MUST be two");
				return NULL;
			}
			mod_op = (int)PyLong_AsLong(PyTuple_GET_ITEM(value, 1));
			mod_value = PyTuple_GET_ITEM(value, 2);
			mods[pos] = pair2LDAPMod(key, mod_value, mod_op | LDAP_MOD_BVALUES);
			if (mods[pos] == NULL) {
				freeLDAPMods(mods);
				return NULL;
			}
		} else {
			PyErr_SetString(PyExc_ValueError, "Each value MUST be list or tuple type");
			return NULL;
		}
	}
	return mods;
}


static LDAPMod *
pair2LDAPMod(PyObject *key, PyObject *value, int mod_op)
{
	LDAPMod *mod;
	int len;
	Py_ssize_t i;
	PyObject *val;

	mod = (LDAPMod *)PyMem_RawMalloc(sizeof(LDAPMod));
	if (mod == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	len = PyList_GET_SIZE(value);
	mod->mod_op = mod_op;
	mod->mod_type = PyUnicode_AsUTF8(key);
	if (mod->mod_type == NULL) {
		freeLDAPMod(mod);
		PyErr_NoMemory();
		return NULL;
	}
	mod->mod_bvalues = (struct berval **)PyMem_RawMalloc(sizeof(struct berval *) * len);
	if (mod ->mod_bvalues == NULL) {
		freeLDAPMod(mod);
		PyErr_NoMemory();
		return NULL;
	}
	for (i = 0; i < len; i++) {
		val = PyList_GET_ITEM(value, i);
		mod->mod_bvalues[i] = str2berval(val);
		if (mod->mod_bvalues[i] == NULL) {
			freeLDAPMod(mod);
			return NULL;
		}
	}
	return mod;
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
		PyErr_NoMemory();
		return NULL;
	}
	bv->bv_len = (ber_len_t)strlen(bv->bv_val);
	return bv;
}


static void
freeLDAPMods(LDAPMod **mods)
{
	LDAPMod **l;
	for (l = mods; *l; l++) {
		freeLDAPMod(*l);
	}
	PyMem_RawFree(mods);
}


static void
freeLDAPMod(LDAPMod *mod)
{
	int i;
	if (mod == NULL)
		return;

	if (mod->mod_bvalues == NULL) {
		PyMem_RawFree(mod);
		return;
	}

	for (i = 0; mod->mod_bvalues[i]; i++) {
		if (mod->mod_bvalues[i] != NULL)
			PyMem_RawFree(mod->mod_bvalues[i]);
	}
	PyMem_RawFree(mod->mod_bvalues);
	PyMem_RawFree(mod);
}

/* vi: set noexpandtab : */
