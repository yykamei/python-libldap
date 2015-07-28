# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei

# NOTE: Argument 'filter' conflicts with built-in 'filter' function
_filter = filter

from _libldap import _LDAPError, _LDAPObject
from collections import OrderedDict as _OrderedDict

__all__ = (
    'LDAP',
    'LDAPError',
)

LDAP_SUCCESS = 0x00
LDAP_ERROR = -1


class LDAPError(Exception):
    def __init__(self, message, return_code, *args, **kwargs):
        self.message = message
        self.return_code = return_code

    def __str__(self):
        return '%s (%d)' % (self.message, self.return_code)


class _OrderedEntry(_OrderedDict):
    def __repr__(self):
        content = ', '.join(['%s: %s' % (x, y) for x, y in self.items()])
        return '{%s}' % (content,)


class LDAP(_LDAPObject):
    def search(self, base, scope, filter, ordered_attributes=False):
        msg = super().search(base, scope, filter)
        for entry in super().result(msg):
            if ordered_attributes:
                obj = _OrderedEntry()
                for key in entry['__order__']:
                    obj[key] = entry[key]
                yield obj
            else:
                entry.pop('__order__')
                yield entry
