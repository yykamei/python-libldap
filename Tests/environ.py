# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei

server_info = {
    'localhost': {
        'uri_389': 'ldap://localhost/',
        'uri_636': 'ldaps://localhost/',
        'suffix': 'dc=example,dc=com',
        'root_dn': 'cn=master,dc=example,dc=com',
        'root_pw': 'secret',
        'auth_user': 'cn=auth,ou=Users,dc=example,dc=com',
        'auth_pw': 'secret',
        'user': {
            'dn': ['uid=test1,ou=Users,dc=example,dc=com'],
            'objectClass': ['top', 'person', 'inetOrgPerson', 'pwdPolicy'],
            'uid': ['test1'],
            'cn': ['test1'],
            'givenName': ['One'],
            'sn': ['Test'],
            'uidNumber': ['9999'],
            'gidNumber': ['100'],
            'loginShell': ['/bin/sh'],
            'homeDirectory': ['/home/test1'],
            'userPassword': ['secret'],
            'description': ['Test entry'],
            'mail': ['a@example.com', 'b@example.com'],
        }
    }
}
