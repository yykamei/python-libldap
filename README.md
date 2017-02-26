[![PyPI version](https://badge.fury.io/py/python-libldap.svg)](https://badge.fury.io/py/python-libldap)
[![Build Status](https://travis-ci.org/yykamei/python-libldap.svg?branch=master)](https://travis-ci.org/yykamei/python-libldap)
[![Coverage Status](https://coveralls.io/repos/github/yykamei/python-libldap/badge.svg?branch=HEAD)](https://coveralls.io/github/yykamei/python-libldap?branch=HEAD)

python-libldap
==============

python-libldap is a Python binding for *libldap* (LDAP client library).
*libldap* is provided by OpenLDAP.

This project requires Python version 3.4 or later (not Python 2).
If you want to use libldap wrapper library with Python 3, please try it.

Documentation
=============

https://yykamei.github.io/python-libldap/

Requirements
============

* `Python >= 3.4`
* `libldap`
* `libsasl2`

Build Requirements
==================

* `Python developer package >= 3.4`
* `libldap developer package`
* `libsasl2 developer package`

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

Changes
=======

0.8.16 release
--------------

* Fix: Fix memleak
    - HAMANO Tsukasa <hamano@osstech.co.jp>
* Fix: fix for binary attribute
    - HAMANO Tsukasa <hamano@osstech.co.jp>

0.8.15 release
--------------

* Add: Travis CI testing

0.8.14 release
--------------

* Fix: LDAP.rename() description

0.8.13 release
--------------

* Fix: Encoding error and getting size of characters

0.8.12 release
--------------

* Fix: Get LDAP value length by using Pychon/C API in str2berval()
* LDAP constructor receives start_tls parameter
* LDAP_OPT_REFERRALS is False by default

0.8.11 release
--------------

* LDAP constructor receives options parameter

0.8.10 release
--------------

* Fix: We raise LDAPAPIError

0.8.9 release
-------------

* Add LDAP Exceptions which inherit LDAPError

0.8.8 release
-------------

* LDAP class constructor receives list of uri

0.8.7 release
-------------

* LDAP class supports context manager

0.8.6 release
-------------

* Change LDAP entries value type from str to bytes in LDAP.search_result()
* Change LDAP entry object (object has 'dn' attribute) in LDAP.search_result()

0.8.5 release
--------------

* Change deleteoldrdn default value from True to False in LDAP.rename()

