# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei

from uuid import uuid4


Environment = {
    'localhost': {  # Require ppolicy overlay
        'uri_389': 'ldap://localhost/',
        'uri_636': 'ldaps://localhost/',
        'suffix': 'dc=example,dc=com',
        'root_dn': 'cn=master,dc=example,dc=com',
        'root_pw': 'secret',
        'auth_user': 'cn=auth,ou=Users,dc=example,dc=com',
        'auth_pw': 'secret',
    }
}


def create_user_entry(name=None, test_target_host='localhost', relax=False):
    if name is None:
        name = 'test-%s' % (uuid4().hex,)
    env = Environment[test_target_host]
    dn = 'uid=%s,%s' % (name, env['suffix'])
    attributes = [
        ('objectClass', ['top', 'person', 'inetOrgPerson', 'pwdPolicy']),
        ('uid', [name]),
        ('cn', [name]),
        ('givenName', [name]),
        ('sn', [name]),
        ('userPassword', ['secret']),
        ('description', ['Test entry']),
        ('mail', ['a@example.com', 'b@example.com']),
        ('pwdPolicySubentry', [dn]),
        ('pwdAttribute', ['userPassword']),
        ('pwdLockout', ['TRUE']),
    ]
    if relax:
        # Relax control is required for this attribute.
        attributes.append(('pwdAccountLockedTime', ['20001231123030.000000Z']))
    return (dn, attributes)
