# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei
"""libldap package

*libldap* is libldap Python binding.
Following objects are exposed.

LDAP
====

This class has following LDAP operation methods.

* bind
* unbind
* search
* paged_search
* add
* modify
* delete
* rename
* compare
* whoami
* passwd
* start_tls
* set_option
* get_option
* abandon
* cancel
* result
* search_result

bind
-----

Method for LDAP bind operation. If you do not use this method,
the relative instance will operate anonymously.
For example:

    >>> from libldap import LDAP
    >>> ld = LDAP('ldap://localhost')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')

This method supports asynchronous operation by passing asyn=True parameter.
Asynchronous operation returns message ID. You can use it like this:

    >>> from pprint import pprint
    >>> from libldap import LDAP
    >>> ld = LDAP('ldap://localhost')
    >>> msgid = ld.bind('cn=master,dc=example,dc=com', 'secret', async=True)
    >>> result = ld.result(msgid)
    {'error_message': None,
     'message': 'Invalid credentials',
     'referrals': [],
     'return_code': 49}

If LDAP server has ppolicy overlay, you can set LDAP_CONTROL_PASSWORDPOLICYREQUEST
control like this:

    >>> from pprint import pprint
    >>> from libldap import LDAP, LDAPControl, LDAP_CONTROL_PASSWORDPOLICYREQUEST
    >>> c = LDAPControl()
    >>> c.add_control(LDAP_CONTROL_PASSWORDPOLICYREQUEST)
    >>> ld = LDAP('ldap://localhost')
    >>> msgid = ld.bind('cn=master,dc=example,dc=com', 'secret', controls=c, async=True)
    >>> result = ld.result(msgid, controls=c)
    >>> pprint(result)
    {'error_message': None,
     'message': 'Invalid credentials',
     'ppolicy_expire': -1,
     'ppolicy_grace': -1,
     'ppolicy_msg': 'Account locked',
     'referrals': [],
     'return_code': 49}

LDAPControl
===========

You can LDAP control extension by using this class.

For example:

    >>> from libldap import LDAP, LDAPControl, LDAP_CONTROL_RELAX
    >>> c = LDAPControl()
    >>> c.add_control(LDAP_CONTROL_RELAX)
    >>> ld = LDAP('ldap://localhost')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')
    >>> ld.modify('cn=test,dc=example,dc=com',
    ...           [('pwdAccountLockedTime', [], LDAP_MOD_DELETE)], controls=c)
    >>> 
"""

from .core import *
from .constants import *
