# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei

import os
import unittest

from .environ import Environment
from libldap import LDAP, LDAPControl, LDAPError
from libldap.constants import *


class LDAPBindTests(unittest.TestCase):
    def setUp(self):
        server = os.environ.get('TEST_SERVER', 'localhost')
        self.env = Environment[server]

    def test_bind(self):
        ld = LDAP(self.env['uri_389'])
        ld.bind(self.env['auth_user'], self.env['auth_pw'])

    def test_bind_async(self):
        ld = LDAP(self.env['uri_389'])
        msgid = ld.bind(self.env['auth_user'], self.env['auth_pw'], async=True)
        result = ld.result(msgid)
        self.assertEqual(result['return_code'], 0)

    def test_bind_controls(self):
        ld = LDAP(self.env['uri_389'])
        c = LDAPControl()
        c.add_control(LDAP_CONTROL_PASSWORDPOLICYREQUEST)
        msgid = ld.bind(self.env['auth_user'],
                        self.env['auth_pw'],
                        controls=c,
                        async=True)
        result = ld.result(msgid, controls=c)
        self.assertIn('ppolicy_msg', result)

    def test_bind_error(self):
        with self.assertRaises(LDAPError) as cm:
            ld = LDAP(self.env['uri_389'])
            ld.bind(self.env['auth_user'], 'bad password')

    def test_bind_error_async(self):
        ld = LDAP(self.env['uri_389'])
        msgid = ld.bind(self.env['auth_user'], 'bad password', async=True)
        result = ld.result(msgid)
        self.assertEqual(result['return_code'], 49)


class LDAPSearchTests(unittest.TestCase):
    def setUp(self):
        server = os.environ.get('TEST_SERVER', 'localhost')
        self.env = Environment[server]

    def tearDown(self):
        pass

    def test_search_base(self):
        ld = LDAP(self.env['uri_389'])
        ld.bind(self.env['root_dn'], self.env['root_pw'])
        self.assertEqual(len(ld.search(self.env['suffix'])), 1)

    def test_search_filter(self):
        ld = LDAP(self.env['uri_389'])
        ld.bind(self.env['root_dn'], self.env['root_pw'])
        r = ld.search(self.env['suffix'], LDAP_SCOPE_SUB, filter='cn=auth')
        self.assertEqual(len(r), 1)
