/*
 * A Python binding for ldap.
 *
 * Copyright (C) 2015 Yutaka Kamei
 *
 */

#include "_libldap.h"


PyObject *
get_entry(LDAP *ldap, LDAPMessage *msg)
{
	PyObject *entry = NULL;
	BerElement *ber = NULL;
	LDAPMessage *attribute;
	struct berval bv, *bvals, **bvp = &bvals;
	int i, rc;

	entry = PyDict_New();
	if (entry == NULL)
		return PyErr_NoMemory();

	rc = ldap_get_dn_ber(ldap, entry, &ber, &bv);
	if (PyDict_SetItemString(entry, "dn", PyUnicode_FromString(bv.bv_val)) == -1)
		return PyErr_NoMemory();

	for (rc = ldap_get_attribute_ber(ldap, msg, ber, &bv, bvp);
			rc == LDAP_SUCCESS;
			rc = ldap_get_attribute_ber(ldap, msg, ber, &bv, bvp)) {
		if (bv.bv_val == NULL)
			break;

		if (bvals) {
			for (i = 0; bvals[i].bv_val != NULL; i++) {
			}
			ber_memfree(bvals);
		}
	}

	if (ber != NULL)
		ber_free(ber, 0);
}

/* vi: set noexpandtab : */
