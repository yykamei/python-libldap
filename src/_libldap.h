/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include <Python.h>
#include <ldap.h>
#include <lber.h>
#include <signal.h>


typedef struct {
	PyObject_HEAD
	LDAP *ldap;
} LDAPObject;


#define LDAP_BEGIN_ALLOW_THREADS          \
	{                                     \
		PyGILState_STATE gstate;          \
		gstate = PyGILState_Ensure();
#define LDAP_END_ALLOW_THREADS            \
		PyGILState_Release(gstate);       \
	}

extern PyObject *LDAPError;

PyObject *
get_entry(LDAP *ldap, LDAPMessage *msg);

/* vi: set noexpandtab : */
