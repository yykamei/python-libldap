# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei

# NOTE: Argument 'filter' conflicts with built-in 'filter' function
_filter = filter

from _libldap import LDAPObject
from collections import OrderedDict


class OrderedEntry(OrderedDict):
    def __repr__(self):
        content = ', '.join(['%s: %s' % (x, y) for x, y in self.items()])
        return '{%s}' % (content,)


class LDAPObject(LDAPObject):
    def search(self, base, scope, filter, ordered_attributes=False, *args, **kwargs):
        msg = super().search(base, scope, filter)
        for entry in super().result(msg):
            if ordered_attributes:
                obj = OrderedEntry()
                for key in entry['__order__']:
                    obj[key] = entry[key]
                yield obj
            else:
                entry.pop('__order__')
                yield entry
