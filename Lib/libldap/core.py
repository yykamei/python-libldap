# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei

# NOTE: Argument 'filter' conflicts with built-in 'filter' function
_filter = filter

from _libldap import _LDAPError, _LDAPObject
from collections import OrderedDict as _OrderedDict

__all__ = (
    'LDAP',
    'LDAPAsync',
    'LDAPError',
)

LDAP_SUCCESS = 0x00
LDAP_ERROR = -1


class LDAPError(Exception):
    def __init__(self, message, return_code, *args, **kwargs):
        self.message = message
        self.return_code = return_code

    def __str__(self):
        return '%s (%d)' % (self.message, self.return_code)


class _OrderedEntry(_OrderedDict):
    def __repr__(self):
        content = ', '.join(['%s: %s' % (x, y) for x, y in self.items()])
        return '{%s}' % (content,)


class LDAP(_LDAPObject):
    """LDAP is libldap wrapper class

    You can use this like this:

    >>> ld = LDAP('ldap://localhost/')
    >>> ld.bind_user
    'anonymous'
    >>> ld.bind('cn=master,dc=example,dc=com', 'secret')
    >>> ld.bind_user
    'cn=master,dc=example,dc=com'
    >>> from .constants import LDAP_SCOPE_SUB
    >>> ld.search('dc=example,dc=com', LDAP_SCOPE_SUB)
    [...]
    """

    def __init__(self, uri):
        self.uri = uri
        self.bind_user = 'anonymous'
        try:
            super().__init__(uri)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None

    def bind(self, who, password):
        """
        Parameters
        ----------
        who : str
        password : str

        Returns
        -------
        None
            If operation is succeeded, None object is returned.

        Raises
        ------
        LDAPError
        """
        try:
            msgid = super().bind(who, password)
            result = super().result(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)
        self.bind_user = who

    def unbind(self):
        """
        Returns
        -------
        None
            If operation is succeeded, None object is returned.
        """
        try:
            super().unbind()
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        try:
            super().__init__(self.uri)  # Re-use this instance
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None

    def search(self,
               base,
               scope=0x0000,
               filter='(objectClass=*)',
               attributes=None,
               attrsonly=False,
               timeout=0,
               ordered_attributes=False):
        """
        Parameters
        ----------
        base : str
            DN of the entry at which to start the search.
        scope : int, optional
            Scope of the search.
            it must be LDAP_SCOPE_BASE, LDAP_SCOPE_ONE, LDAP_SCOPE_SUB or
            LDAP_SCOPE_CHILDREN (the default is LDAP_SCOPE_BASE).
        filter : str, optional
             (the default is '(objectClass=*)')
        attributes : [str] or None, optional
            (the default is None, which implies '*')
        attrsonly : bool, optional
            (the default is False)
        timeout : int or float, optional
            (the default is 0, which implies No timeout)
        ordered_attributes : bool, optional
            If ordered_attributes is True, the order of the attributes in entry
            are remembered (the default is False).

        Returns
        -------
        list
            List of entries.

        Raises
        ------
        LDAPError
        """
        msgid = super().search(base, scope, filter, attributes,
                               int(attrsonly), timeout)
        try:
            if ordered_attributes:
                return [_OrderedEntry([(key, entry[key])
                                       for key in entry['__order__']])
                        for entry in super().result(msgid)]
            else:
                return [dict([(key, value) for key, value in entry.items()
                              if key != '__order__'])
                        for entry in super().result(msgid)]
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None

    def add(self, dn, attributes):
        """
        Parameters
        ----------
        dn : str
        attributes : [(str, [str])]
            List of tuple. tuple has two items:
                attr   - Attribute name
                values - List of value

        Returns
        -------
        None
            If operation is succeeded, None object is returned.

        Raises
        ------
        LDAPError
        """
        try:
            msgid = super().add(dn, attributes)
            result = super().result(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)

    def modify(self, dn, changes):
        """
        Parameters
        ----------
        dn : str
        changes : [(str, int, [str])]
            List of tuple. tuple has three items:
                attr   - Attribute name
                mod_op - Modify operation (e.g.: LDAP_MOD_REPLACE)
                values - List of value

        Returns
        -------
        None
            If operation is succeeded, None object is returned.

        Raises
        ------
        LDAPError
        """
        try:
            msgid = super().modify(dn, changes)
            result = super().result(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)

    def delete(self, dn):
        """
        Parameters
        ----------
        dn : str

        Returns
        -------
        None
            If operation is succeeded, None object is returned.

        Raises
        ------
        LDAPError
        """
        try:
            msgid = super().delete(dn)
            result = super().result(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)

    def rename(self, dn, newrdn, newparent, deleteoldrdn=False):
        """
        Parameters
        ----------
        dn : str
        newrdn : str
        newparent : str
        deleteoldrdn : bool

        Returns
        -------
        None
            If operation is succeeded, None object is returned.

        Raises
        ------
        LDAPError
        """
        try:
            msgid = super().rename(dn, newrdn, newparent, int(deleteoldrdn))
            result = super().result(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)

    def compare(self, dn, attribute, value):
        """
        Parameters
        ----------
        dn : str
        attribute : str
        value : str

        Returns
        -------
        None
            If operation is succeeded, None object is returned.

        Raises
        ------
        LDAPError
        """
        try:
            msgid = super().compare(dn, attribute, value)
            result = super().result(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)

    def whoami(self):
        """
        Returns
        -------
        str
            If operation is succeeded, DN is returned.

        Raises
        ------
        LDAPError
        """
        try:
            msgid = super().whoami()
            result = super().result(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)
        if 'data' in result and result['data']:
            return result['data'].decode('utf-8')
        else:
            return 'anonymous'

    def passwd(self, user, oldpw=None, newpw=None):
        """
        Parameters
        ----------
        user : str
        oldpw : str, optional
        newpw : str, optional

        Returns
        -------
        str
            If operation is succeeded, New password is returned.

        Raises
        ------
        LDAPError
        """
        try:
            msgid = super().passwd(user, oldpw, newpw)
            result = super().result(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)
        if 'data' in result:
            # We use lstrip instead of `ber_scanf( ber, "{a}", &s);`
            return result['data'].lstrip(b'0\n\x80\x08').decode('utf-8')
        else:
            return newpw

    def start_tls(self):
        """
        Returns
        -------
        None
            If operation is succeeded, None object is returned.

        Raises
        ------
        LDAPError
        """
        try:
            super().start_tls()
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None

    def set_option(self, option, value, is_global=False):
        # FIXME: Not enough description
        """
        Parameters
        ----------
        option : int
            Available options are located in libldap.constants
        value : some object
        is_global : bool, optional

        Returns
        -------
        None
            If operation is succeeded, None object is returned.

        Raises
        ------
        LDAPError
        """
        try:
            super().set_option(option, value, int(is_global))
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None

    def abandon(self, *args, **kwargs):
        """Not supported because methods of this class are synchronous"""
        raise NotImplementedError('Not supported')

    def cancel(self, *args, **kwargs):
        """Not supported because methods of this class are synchronous"""
        raise NotImplementedError('Not supported')


class LDAPAsync(_LDAPObject):
    pass  # FIXME
