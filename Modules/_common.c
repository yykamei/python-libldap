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


/* vi: set noexpandtab : */
