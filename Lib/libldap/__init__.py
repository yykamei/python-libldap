# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei
"""libldap package

**libldap** is libldap Python binding.
Following objects are exposed.

LDAP
====

This class has following LDAP operation methods.

* bind_
* unbind_
* search_
* paged_search_
* add_
* modify_
* delete_
* rename_
* compare_
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

This is the method for LDAP bind operation. If you do not use this method,
the relative LDAP_ instance will operate anonymously.

For example:

.. code-block:: python

    >>> from libldap import LDAP
    >>> ld = LDAP('ldap://localhost')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')

This method supports asynchronous operation by passing async=True parameter.
Asynchronous operation returns message ID. You can use it like this:

.. code-block:: python

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

.. code-block:: python

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

unbind
------

This is the method for LDAP unbind operation. This terminates the current association,
and free the resources.

.. code-block:: python

    >>> from libldap import LDAP
    >>> ld = LDAP('ldap://localhost')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')
    >>> ld.unbind()

search
------

This is the method for LDAP search operation. Required parameter is *base*.

For example:

.. code-block:: python

    >>> from pprint import pprint
    >>> from libldap import LDAP, LDAP_SCOPE_SUB
    >>> ld = LDAP('ldap://localhost')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')
    >>> entries = ld.search('dc=example,dc=com', LDAP_SCOPE_SUB, '(|(uid=user1)(uid=user2))')
    >>> pprint(entries)
    [{'cn': ['user1'],
      'dn': ['uid=user1,ou=Users,dc=example,dc=com'],
      'gidNumber': ['100'],
      'givenName': ['ONE'],
      'homeDirectory': ['/home/user1'],
      'loginShell': ['/bin/bash'],
      'objectClass': ['inetOrgPerson', 'posixAccount', 'pwdPolicy'],
      'pwdAttribute': ['userPassword'],
      'sn': ['USER'],
      'uid': ['user1'],
      'uidNumber': ['1001'],
      'userPassword': ['secret']},
     {'cn': ['user2'],
      'dn': ['uid=user2,ou=Users,dc=example,dc=com'],
      'gidNumber': ['100'],
      'givenName': ['TWO'],
      'homeDirectory': ['/home/user2'],
      'loginShell': ['/bin/bash'],
      'mail': ['user2@example.com'],
      'objectClass': ['top', 'person', 'posixAccount', 'inetOrgPerson'],
      'sn': ['User'],
      'uid': ['user2'],
      'uidNumber': ['1000'],
      'userPassword': ['{SSHA}6ggrZqsOKRkj3wbBp/GB4tMpbgi+l2JLs3oWCA==']}]

Each entry is dict type and value type is list. **dn** attribute is also included
in entry object.

You can only specified attributes by **attributes** parameter. If `*` or None are
specified, all attributes are fetched. **attrsonly** parameter fetchs attribute names
only (value is empty list).

You can specify **timeout** and **sizelimit** parameter. See ldap.conf(5).

**controls** parameter can be set. Following is LDAP_CONTROL_SORTREQUEST example:

Although LDAP client MUST NOT expect attributes order will be fixed,
you can get ordered attributes by **ordered_attributes** parameter.

search() method support LDAP_CONTROL_SORTREQUEST. You can use like this:

.. code-block:: python

    >>> from pprint import pprint
    >>> from libldap import LDAP, LDAPControl, LDAP_CONTROL_SORTREQUEST
    >>> c = LDAPControl()
    >>> c.add_control(LDAP_CONTROL_SORTREQUEST, b'uidNumber')
    >>> ld = LDAP('ldap://localhost')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')
    >>> entries = ld.search('dc=example,dc=com', LDAP_SCOPE_SUB,
    ...                     '(|(uid=user1)(uid=user2))', attributes=['uidNumber'],
    ...                     controls=c)
    >>> pprint(entries)
    [{'dn': ['uid=user2,ou=Users,dc=example,dc=com'], 'uidNumber': ['1000']},
     {'dn': ['uid=user1,ou=Users,dc=example,dc=com'], 'uidNumber': ['1001']}]

paged_search
-------------

This is the method for LDAP search operation with LDAP_CONTROL_PAGEDRESULTS.
Of course, you can use LDAP_CONTROL_PAGEDRESULTS with search_() method, but
paged_search() is generator.

.. code-block:: python

    >>> from libldap import LDAP, LDAP_SCOPE_SUB
    >>> ld = LDAP('ldap://localhost')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')
    >>> entries = ld.paged_search('dc=example,dc=com', LDAP_SCOPE_SUB)
    >>> entries
    <generator object paged_search at 0x7f8d8714fa20>

add
---

This is the method for LDAP add operation. Add method requires dn and
LDAP attributes parameters. LDAP attributes type is [(str, [str])].

Following is LDIF entry that we want to add.

::

    dn: cn=group1,ou=Groups,dc=example,dc=com
    objectClass: top
    objectClass: posixGroup
    cn: group1
    gidNumber: 100
    description Test Group 1


If you add above entry, convert into following Python code.

.. code-block:: python

    [
        ('objectClass', ['top', 'posixGroup']),
        ('cn', ['group1']),
        ('gidNumber', ['100']),
        ('description', ['Test Group 1']),
    ]


Example.

.. code-block:: python

    >>> from libldap import LDAP, LDAP_SCOPE_SUB
    >>> ld = LDAP('ldap://localhost')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')
    >>> ld.add('cn=group1,ou=Groups,dc=example,dc=com', [
    ...     ('objectClass', ['top', 'posixGroup']),
    ...     ('cn', ['group1']),
    ...     ('gidNumber', ['100']),
    ...     ('description', ['Test Group 1']),
    ... ])


modify
------

This is the method for LDAP modify operation. Modify method requires dn and
changes parameters. Changes type is [(str, [str], int)].

Following is LDIF entry that we want to modify.

::

    dn: cn=group1,ou=Groups,dc=example,dc=com
    changetype: modify
    add: memberUid
    memberUid: user1
    -
    replace: description
    description: Test Group One

If you modify above entry, convert into following Python code.

.. code-block:: python

    [
        ('memberUid', ['user1'], LDAP_MOD_ADD),
        ('description', ['Test Group One'], LDAP_MOD_REPLACE),
    ]

Example.

.. code-block:: python

    >>> from libldap import LDAP, LDAP_MOD_ADD, LDAP_MOD_REPLACE
    >>> ld = LDAP('ldap://localhost')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')
    >>> ld.modify('cn=group1,ou=Groups,dc=example,dc=com', [
    ...     ('memberUid', ['user1'], LDAP_MOD_ADD),
    ...     ('description', ['Test Group One'], LDAP_MOD_REPLACE),
    ... ])

delete
-------

This is the method for LDAP delete operation. Delete method requires dn parameter.

Example.

.. code-block:: python

    >>> from libldap import LDAP
    >>> ld = LDAP('ldap://localhost')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')
    >>> ld.delete('cn=group1,ou=Groups,dc=example,dc=com')

rename
------

This is the method for LDAP rename operation. Rename method requires dn and
newrdn parameters. newparent and deleteoldrdn are optional parameters. if
newparent parameter is None, newparent is same suffix with dn parameter.

Example.

.. code-block:: python

    >>> from libldap import LDAP
    >>> ld = LDAP('ldap://localhost')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')
    >>> ld.rename('uid=test-user,ou=Users,dc=example,dc=com', 'cn=test-user')

.. note::

    If deleteoldrdn is True, old RDN attribute will be deleted. This may cause
    'Object class violation (65)' Exception. Default deleteoldrdn value is False.


compare
--------

This is the method for LDAP compare operation. Compare method requires dn, attribute
and value parameters. It returns boolean, specified attribute description and value
to compare to those found in the entry or not.

Example.

.. code-block:: python

    >>> from libldap import LDAP
    >>> ld = LDAP('ldap://localhost')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')
    >>> ld.compare('cn=group1,ou=Groups,dc=example,dc=com', 'description', 'Test Group 1')
    True

LDAPControl
===========

You can LDAP control extension by using this class.

For example:

.. code-block:: python

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

# vi: set filetype=rst :
