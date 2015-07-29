# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei

# NOTE: Argument 'filter' conflicts with built-in 'filter' function
_filter = filter

from _libldap import _LDAPError, _LDAPObject
from collections import OrderedDict as _OrderedDict

__all__ = (
    'LDAP',
    'LDAPError',
)

LDAP_SUCCESS = 0x00
LDAP_COMPARE_FALSE = 0x05
LDAP_COMPARE_TRUE = 0x06
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

    def bind(self, who, password, async=False):
        """
        Parameters
        ----------
        who : str
        password : str
        async : bool
            If True, return result immediately
            (the default is False, which means operation will
            done synchronously).

        Returns
        -------
        None or int
            If operation is succeeded, None object is returned.
            If async is True, return msgid.

        Raises
        ------
        LDAPError
        """
        try:
            msgid = super().bind(who, password)
            if async:
                # Not set bind_user
                return msgid
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
               sizelimit=0,
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
            (the default is 0, which implies unlimited)
        sizelimit : int, optional
            (the default is 0, which implies unlimited)
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

        Note
        ----
        This method operates synchronously.
        """
        try:
            msgid = super().search(base, scope, filter, attributes,
                                   int(attrsonly), timeout, sizelimit)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
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

    def add(self, dn, attributes, async=False):
        """
        Parameters
        ----------
        dn : str
        attributes : [(str, [str])]
            List of tuple. tuple has two items:
                attr   - Attribute name
                values - List of value
        async : bool
            If True, return result immediately
            (the default is False, which means operation will
            done synchronously).

        Returns
        -------
        None or int
            If operation is succeeded, None object is returned.
            If async is True, return msgid.

        Raises
        ------
        LDAPError
        """
        try:
            msgid = super().add(dn, attributes)
            if async:
                return msgid
            result = super().result(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)

    def modify(self, dn, changes, async=False):
        """
        Parameters
        ----------
        dn : str
        changes : [(str, [str], int)]
            List of tuple. tuple has three items:
                attr   - Attribute name
                values - List of value
                mod_op - Modify operation (e.g.: LDAP_MOD_REPLACE)
        async : bool
            If True, return result immediately
            (the default is False, which means operation will
            done synchronously).

        Returns
        -------
        None or int
            If operation is succeeded, None object is returned.
            If async is True, return msgid.

        Raises
        ------
        LDAPError
        """
        try:
            msgid = super().modify(dn, changes)
            if async:
                return msgid
            result = super().result(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)

    def delete(self, dn, async=False):
        """
        Parameters
        ----------
        dn : str
        async : bool
            If True, return result immediately
            (the default is False, which means operation will
            done synchronously).

        Returns
        -------
        None or int
            If operation is succeeded, None object is returned.
            If async is True, return msgid.

        Raises
        ------
        LDAPError
        """
        try:
            msgid = super().delete(dn)
            if async:
                return msgid
            result = super().result(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)

    def rename(self, dn, newrdn, newparent, deleteoldrdn=True, async=False):
        """
        Parameters
        ----------
        dn : str
        newrdn : str
        newparent : str
        deleteoldrdn : bool
            (the default is True, which means oldrdn is deleted after renamed)
        async : bool
            If True, return result immediately
            (the default is False, which means operation will
            done synchronously).

        Returns
        -------
        None or int
            If operation is succeeded, None object is returned.
            If async is True, return msgid.

        Raises
        ------
        LDAPError
        """
        try:
            msgid = super().rename(dn, newrdn, newparent, int(deleteoldrdn))
            if async:
                return msgid
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
        bool

        Raises
        ------
        LDAPError

        Note
        ----
        This method operates synchronously.
        """
        try:
            msgid = super().compare(dn, attribute, value)
            result = super().result(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] == LDAP_COMPARE_TRUE:
            return True
        elif result['return_code'] == LDAP_COMPARE_FALSE:
            return False
        else:
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

        Note
        ----
        This method operates synchronously.
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

        Note
        ----
        This method operates synchronously.
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
        """
        Parameters
        ----------
        option : int
            Available options are located in libldap.constants
        value : object
        is_global : bool, optional

        Returns
        -------
        None
            If operation is succeeded, None object is returned.

        Raises
        ------
        LDAPError

        Detail
        ------
        If option is following, value MUST be boolean.

        * LDAP_OPT_CONNECT_ASYNC
        * LDAP_OPT_REFERRALS
        * LDAP_OPT_RESTART

        If option is following, value MUST be int.

        * LDAP_OPT_DEBUG_LEVEL
        * LDAP_OPT_DEREF
        * LDAP_OPT_PROTOCOL_VERSION
        * LDAP_OPT_RESULT_CODE
        * LDAP_OPT_SIZELIMIT
        * LDAP_OPT_TIMELIMIT
        * LDAP_OPT_X_KEEPALIVE_IDLE
        * LDAP_OPT_X_KEEPALIVE_PROBES
        * LDAP_OPT_X_KEEPALIVE_INTERVAL
        * LDAP_OPT_X_TLS_CRLCHECK
        * LDAP_OPT_X_TLS_PROTOCOL_MIN
        * LDAP_OPT_X_TLS_REQUIRE_CERT
        * LDAP_OPT_X_SASL_NOCANON
        * LDAP_OPT_X_SASL_MAXBUFSIZE
        * LDAP_OPT_X_SASL_SSF_EXTERNAL
        * LDAP_OPT_X_SASL_SSF_MAX
        * LDAP_OPT_X_SASL_SSF_MIN

        If option is following, value MUST be float or int.

        * LDAP_OPT_NETWORK_TIMEOUT
        * LDAP_OPT_TIMEOUT

        If option is following, value MUST be str.

        * LDAP_OPT_DEFBASE
        * LDAP_OPT_DIAGNOSTIC_MESSAGE
        * LDAP_OPT_MATCHED_DN
        * LDAP_OPT_URI
        * LDAP_OPT_X_TLS_CACERTDIR
        * LDAP_OPT_X_TLS_CACERTFILE
        * LDAP_OPT_X_TLS_CERTFILE
        * LDAP_OPT_X_TLS_CIPHER_SUITE
        * LDAP_OPT_X_TLS_CRLFILE
        * LDAP_OPT_X_TLS_DHFILE
        * LDAP_OPT_X_TLS_KEYFILE
        * LDAP_OPT_X_TLS_RANDOM_FILE
        * LDAP_OPT_X_SASL_SECPROPS

        If option is LDAP_OPT_REFERRAL_URLS, value MUST be [str].

        Other options are not supported.
        """
        try:
            super().set_option(option, value, int(is_global))
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None

    def abandon(self, msgid):
        """
        Parameters
        ----------
        msgid : int

        Returns
        -------
        None
            If operation is succeeded, None object is returned.

        Raises
        ------
        LDAPError
        """
        try:
            return super().abandon(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None

    def cancel(self, msgid):
        """
        Parameters
        ----------
        msgid : int

        Returns
        -------
        None
            If operation is succeeded, None object is returned.

        Raises
        ------
        LDAPError
        """
        try:
            return super().cancel(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None

    def result(self, msgid, all=True, timeout=3):
        """
        Parameters
        ----------
        msgid : int
        all : bool
        timeout : int

        Returns
        -------
        dict or list
            Return result for specified message ID.

        Raises
        ------
        LDAPError
        """
        try:
            return super().result(msgid, int(all), timeout)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
