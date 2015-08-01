python-libldap
==============

python-libldap is a Python binding for libldap which is provided by OpenLDAP.

This project requires Python version 3.4 or later (not Python 2).
If you want to use libldap wrapper library with Python 3, please try it.

Requirements
============

* `Python >= 3.4`
* `libldap`
* `libssl`
* `libsasl2`

Install
=======

Install with **pip install python-libldap**

License
=======

Under the MIT license.

Bug tracker
===========

If you have any suggestions or bug reports please report them to the issue tracker at https://github.com/yykamei/python-libldap/issues .

Quick start
===========

Simple search operation
-----------------------

After installing, you can use this library like this:

    >>> from libldap import LDAP, LDAP_SCOPE_SUB
    >>> ld = LDAP('ldap://localhost/')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')
    >>> ld.search('dc=example,dc=com', LDAP_SCOPE_SUB, '(objectClass=*)')
    [...]

Add operation
-------------

    >>> from libldap import LDAP
    >>> ld = LDAP('ldap://localhost/')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')
    >>> ld.add('cn=group1,ou=Groups,dc=example,dc=com', [
    ...     ('objectClass', ['top', 'posixGroup']),
    ...     ('cn', ['group1']),
    ...     ('gidNumber', ['100']),
    ...     ('description', ['Test Group 1']),
    ... ])
    >>>

Modify operation
----------------

    >>> from libldap import LDAP, LDAP_MOD_REPLACE
    >>> ld = LDAP('ldap://localhost/')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')
    >>> ld.modify('cn=group1,ou=Groups,dc=example,dc=com', [
    ...     ('gidNumber', ['101'], LDAP_MOD_REPLACE),
    ... ])
    >>>

Delete operation
----------------

    >>> from libldap import LDAP
    >>> ld = LDAP('ldap://localhost/')
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')
    >>> ld.delete('cn=group1,ou=Groups,dc=example,dc=com')
    >>>
