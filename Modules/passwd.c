/*
 * A Python binding for libldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "libldap.h"


PyObject *
LDAPObject_passwd(LDAPObject *self, PyObject *args)
{
	char *user;
	char *oldpw;
	char *newpw;
	struct berval bv_user = {0, NULL};
	struct berval bv_oldpw = {0, NULL};
	struct berval *bv_oldpwp = NULL;
	struct berval bv_newpw = {0, NULL};
	struct berval *bv_newpwp = NULL;
	LDAPControl **sctrls = NULL;
	int rc;
	int msgid;

	if (self->ldap == NULL) {
		PyErr_SetString(LDAPError, "This instance has already been deallocated.");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "szz", &user, &oldpw, &newpw))
		return NULL;

	bv_user.bv_val = user;
	bv_user.bv_len = strlen(user);
	if (oldpw) {
		bv_oldpw.bv_val = oldpw;
		bv_oldpw.bv_len = strlen(oldpw);
		bv_oldpwp = &bv_oldpw;
	}
	if (newpw) {
		bv_newpw.bv_val = newpw;
		bv_newpw.bv_len = strlen(newpw);
		bv_newpwp = &bv_newpw;
	}

	LDAP_BEGIN_ALLOW_THREADS
	rc = ldap_passwd(self->ldap, &bv_user, bv_oldpwp, bv_newpwp, sctrls, NULL, &msgid);
	LDAP_END_ALLOW_THREADS
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		return NULL;
	}
	return PyLong_FromLong(msgid);
}

/* vi: set noexpandtab : */
