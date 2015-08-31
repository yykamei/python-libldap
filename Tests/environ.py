# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei

from uuid import uuid4
from pathlib import Path


Environment = {
    'ldap-server': {  # Require ppolicy overlay
        'uri_389': 'ldap://ldap-server/',
        'uri_636': 'ldaps://ldap-server/',
        'suffix': 'dc=example,dc=com',
        'root_dn': 'cn=master,dc=example,dc=com',
        'root_pw': 'secret',
        'auth_user': 'cn=auth,ou=Users,dc=example,dc=com',
        'auth_pw': 'secret',
        'modify_user': 'uid=modify,ou=Users,dc=example,dc=com',
    }
}
cacert_file = (Path(__file__).parent / 'cacert.pem').absolute()


def create_user_entry(name=None, test_target_host='ldap-server', relax=False):
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
