# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei

import os
import unittest

from .environ import server_info
from libldap import LDAP, LDAPControl, LDAPError
from libldap.constants import *


class LDAPBindTests(unittest.TestCase):
    def setUp(self):
        server = os.environ.get('TEST_SERVER', 'localhost')
        self.info = server_info[server]

    def test_bind(self):
        ld = LDAP(self.info['uri_389'])
        ld.bind(self.info['auth_user'], self.info['auth_pw'])

    def test_bind_async(self):
        ld = LDAP(self.info['uri_389'])
        msgid = ld.bind(self.info['auth_user'], self.info['auth_pw'], async=True)
        result = ld.result(msgid)
        self.assertEqual(result['return_code'], 0)

    def test_bind_error(self):
        with self.assertRaises(LDAPError) as cm:
            ld = LDAP(self.info['uri_389'])
            ld.bind(self.info['auth_user'], 'bad password')

    def test_bind_error_async(self):
        ld = LDAP(self.info['uri_389'])
        msgid = ld.bind(self.info['auth_user'], 'bad password', async=True)
        result = ld.result(msgid)
        self.assertEqual(result['return_code'], 49)


class LDAPSearchTests(unittest.TestCase):
    def setUp(self):
        server = os.environ.get('TEST_SERVER', 'localhost')
        self.info = server_info[server]

    def tearDown(self):
        pass

    def test_search_base(self):
        ld = LDAP(self.info['uri_389'])
        ld.bind(self.info['root_dn'], self.info['root_pw'])
        self.assertEqual(len(ld.search(self.info['suffix'])), 1)

    def test_search_filter(self):
        ld = LDAP(self.info['uri_389'])
        ld.bind(self.info['root_dn'], self.info['root_pw'])
        r = ld.search(self.info['suffix'], LDAP_SCOPE_SUB, filter='cn=auth')
        self.assertEqual(len(r), 1)
