# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei
"""libldap.core module

This module provides LDAP core operations.
"""

from _libldap import _LDAPError, _LDAPObject, _LDAPObjectControl
from .constants import LDAP_CONTROL_PAGEDRESULTS
from collections import OrderedDict as _OrderedDict

__all__ = (
    'LDAP',
    'LDAPControl',
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
        self.args = args
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __repr__(self):
        additional_info = ' %s' % (getattr(self, 'ppolicy_msg', ''),)
        return 'LDAPError(%s (%d)%s)' % (self.message, self.return_code, additional_info)

    def __str__(self):
        additional_info = ' %s' % (getattr(self, 'ppolicy_msg', ''),)
        return '%s (%d)%s' % (self.message, self.return_code, additional_info)


class _OrderedEntry(_OrderedDict):
    def __repr__(self):
        content = ', '.join(['%s: %s' % (x, y) for x, y in self.items()])
        return '{%s}' % (content,)


class LDAP(_LDAPObject):
    """LDAP is libldap wrapper class

    Parameters:
        uri : str
            LDAP URI (e.g. `'ldap://localhost'`, `'ldaps://localhost'`, `'ldapi://localhost'`)

    Raises:
        LDAPError
    """

    def __init__(self, uri):
        self.uri = uri
        self.bind_user = 'anonymous'
        try:
            super().__init__(uri)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None

    def bind(self, who, password, controls=None, async=False):
        """
        Parameters:
            who : str
                Who bind to
            password : str
                Password
            controls : LDAPControl, optional
                LDAP Controls (the default is None, which implies no controls are set)
            async : bool, optional
                Flag for asynchronous or not (the default is False,
                which implies operation will done synchronously)

        Returns:
            None or int

        Raises:
            LDAPError
        """
        try:
            if controls is not None:
                msgid = super().bind(who, password, controls)
            else:
                msgid = super().bind(who, password)
            if async:
                # Not set bind_user
                return msgid
            result = self.result(msgid, controls=controls)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)
        self.bind_user = who

    def unbind(self):
        """
        Returns:
            None

        Raises:
            LDAPError
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
               controls=None,
               ordered_attributes=False,
               async=False):
        """
        Parameters:
            base: str
                DN of the entry at which to start the search.
            scope: int, optional
                Scope of the search.
                it must be LDAP_SCOPE_BASE, LDAP_SCOPE_ONE, LDAP_SCOPE_SUB or
                LDAP_SCOPE_CHILDREN (the default is LDAP_SCOPE_BASE).
            filter : str, optional
                 LDAP filter (the default is '(objectClass=*)')
            attributes : [str] or None, optional
                Attributes for fetching from LDAP server (the default is None,
                which implies '*')
            attrsonly : bool, optional
                Flag for gettting value or not (the default is False)
            timeout : int or float, optional
                Timeout for search operation (the default is 0, which implies unlimited)
            sizelimit : int, optional
                Sizelimit for search operation (the default is 0, which implies unlimited)
            controls : LDAPControl, optional
                LDAP Controls (the default is None, which implies no controls are set)
            ordered_attributes : bool, optional
                Flag for attributes order is fixed or not
                (the default is False, which implies attributes order in entry is
                not remembered)
            async : bool
                Flag for asynchronous or not (the default is False,
                which implies operation will done synchronously)
                Synchronous operation returns LDAP responses immediately

        Returns:
            list or int
                List of entries or message ID (async=True)

        Raises:
            LDAPError
        """
        try:
            if controls is not None:
                msgid = super().search(base, scope, filter, attributes,
                                       int(attrsonly), timeout, sizelimit, controls)
            else:
                msgid = super().search(base, scope, filter, attributes,
                                       int(attrsonly), timeout, sizelimit)
            if async:
                return msgid
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        return self.search_result(msgid, timeout=timeout, controls=controls,
                                  ordered_attributes=ordered_attributes)

    def paged_search(self,
               base,
               scope=0x0000,
               filter='(objectClass=*)',
               attributes=None,
               attrsonly=False,
               timeout=0,
               sizelimit=0,
               pagesize=100,
               ordered_attributes=False):
        """
        Parameters:
            base: str
                DN of the entry at which to start the search.
            scope: int, optional
                Scope of the search.
                it must be LDAP_SCOPE_BASE, LDAP_SCOPE_ONE, LDAP_SCOPE_SUB or
                LDAP_SCOPE_CHILDREN (the default is LDAP_SCOPE_BASE).
            filter : str, optional
                 LDAP filter (the default is '(objectClass=*)')
            attributes : [str] or None, optional
                Attributes for fetching from LDAP server (the default is None,
                which implies '*')
            attrsonly : bool, optional
                Flag for gettting value or not (the default is False)
            timeout : int or float, optional
                Timeout for search operation (the default is 0, which implies unlimited)
            sizelimit : int, optional
                Sizelimit for search operation (the default is 0, which implies unlimited)
            pagesize : int, optional
                LDAP page size (the default is 100, which implies LDAP search request
                is done by 100 LDAP entries)
            ordered_attributes : bool, optional
                Flag for attributes order is fixed or not
                (the default is False, which implies attributes order in entry is
                not remembered)
            async : bool
                Flag for asynchronous or not (the default is False,
                which implies operation will done synchronously)
                Synchronous operation returns LDAP responses immediately

        Yield:
            dict
                LDAP entries

        Raises:
            LDAPError
        """

        _pagesize = ('%d' % (pagesize,)).encode('utf-8')
        controls = _LDAPObjectControl()
        controls.add_control(LDAP_CONTROL_PAGEDRESULTS, _pagesize, False)
        initial = True
        while initial or controls.get_pr_cookie() is not None:
            initial = False
            try:
                msgid = super().search(base, scope, filter, attributes,
                                       int(attrsonly), timeout, sizelimit, controls)
            except _LDAPError as e:
                raise LDAPError(str(e), LDAP_ERROR) from None
            yield from self.search_result(msgid, timeout=timeout, controls=controls,
                                          ordered_attributes=ordered_attributes)

    def add(self, dn, attributes, controls=None, async=False):
        """
        Parameters:
            dn : str
                DN
            attributes : [(str, [str])]
                List of tuple. tuple has two items:
                    attr   - Attribute name
                    values - List of value
            controls : LDAPControl, optional
                LDAP Controls (the default is None, which implies no controls are set)
            async : bool
                Flag for asynchronous or not (the default is False,
                which implies operation will done synchronously)

        Returns:
            None or int
                If operation is succeeded, None object is returned.
                If async is True, return message ID.

        Raises:
            LDAPError
        """
        try:
            if controls is not None:
                msgid = super().add(dn, attributes, controls)
            else:
                msgid = super().add(dn, attributes)
            if async:
                return msgid
            result = self.result(msgid, controls=controls)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)

    def modify(self, dn, changes, controls=None, async=False):
        """
        Parameters:
            dn : str
                DN
            changes : [(str, [str], int)]
                List of tuple. tuple has three items:
                    attr   - Attribute name
                    values - List of value
                    mod_op - Modify operation (e.g.: LDAP_MOD_REPLACE)
            controls : LDAPControl, optional
                LDAP Controls (the default is None, which implies no controls are set)
            async : bool
                Flag for asynchronous or not (the default is False,
                which implies operation will done synchronously)

        Returns:
            None or int
                If operation is succeeded, None object is returned.
                If async is True, return message ID.

        Raises:
            LDAPError
        """
        try:
            if controls is not None:
                msgid = super().modify(dn, changes, controls)
            else:
                msgid = super().modify(dn, changes)
            if async:
                return msgid
            result = self.result(msgid, controls=controls)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)

    def delete(self, dn, controls=None, async=False):
        """
        Parameters:
            dn : str
                DN
            controls : LDAPControl, optional
                LDAP Controls (the default is None, which implies no controls are set)
            async : bool
                Flag for asynchronous or not (the default is False,
                which implies operation will done synchronously)

        Returns:
            None or int
                If operation is succeeded, None object is returned.
                If async is True, return message ID.

        Raises:
            LDAPError
        """
        try:
            if controls is not None:
                msgid = super().delete(dn, controls)
            else:
                msgid = super().delete(dn)
            if async:
                return msgid
            result = self.result(msgid, controls=controls)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)

    def rename(self, dn, newrdn, newparent=None, deleteoldrdn=True, controls=None, async=False):
        """
        Parameters:
            dn : str
                DN
            newrdn : str
                New RDN
            newparent : str, optional
                New Parent DN (ths default is None, which implies same parent
                with old dn is set)
            deleteoldrdn : bool
                Flag for deleting old rdn attribute or not (the default is True,
                which implies oldrdn is deleted after renamed)
            controls : LDAPControl, optional
                LDAP Controls (the default is None, which implies no controls are set)
            async : bool
                Flag for asynchronous or not (the default is False,
                which implies operation will done synchronously)

        Returns:
            None or int
                If operation is succeeded, None object is returned.
                If async is True, return message ID.

        Raises:
            LDAPError
        """
        if newparent is None:
            try:
                newparent = dn.split(',', 1)[1]
            except IndexError:
                raise LDAPError('Invalid DN syntax', 34)
        try:
            if controls is not None:
                msgid = super().rename(dn, newrdn, newparent, int(deleteoldrdn), controls)
            else:
                msgid = super().rename(dn, newrdn, newparent, int(deleteoldrdn))
            if async:
                return msgid
            result = self.result(msgid, controls=controls)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)

    def compare(self, dn, attribute, value, controls=None):
        """
        Parameters:
            dn : str
                DN
            attribute : str
                Attribute for comparing
            value : str
                Value for comparing
            controls : LDAPControl, optional
                LDAP Controls (the default is None, which implies no controls are set)

        Returns:
            bool

        Raises:
            LDAPError

        .. note::

            This method operates synchronously.
        """
        try:
            if controls is not None:
                msgid = super().compare(dn, attribute, value, controls)
            else:
                msgid = super().compare(dn, attribute, value)
            result = self.result(msgid, controls=controls)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] == LDAP_COMPARE_TRUE:
            return True
        elif result['return_code'] == LDAP_COMPARE_FALSE:
            return False
        else:
            raise LDAPError(**result)

    def whoami(self, controls=None):
        """
        Parameters:
            controls : LDAPControl, optional
                LDAP Controls (the default is None, which implies no controls are set)

        Returns:
            str
                If operation is succeeded, DN is returned.

        Raises:
            LDAPError

        .. note::

            This method operates synchronously.
        """
        try:
            if controls is not None:
                msgid = super().whoami(controls)
            else:
                msgid = super().whoami()
            result = self.result(msgid, controls=controls)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)
        if 'data' in result and result['data']:
            return result['data'].decode('utf-8')
        else:
            return 'anonymous'

    def passwd(self, user, oldpw=None, newpw=None, controls=None):
        """
        Parameters:
            user : str
                DN of user
            oldpw : str, optional
                Old password of *user* (the default is None, which implies
                authentication will be skipped)
            newpw : str, optional
                New password of *user* (the default is None, which implies
                password will be created by randomly)
            controls : LDAPControl, optional
                LDAP Controls (the default is None, which implies no controls are set)

        Returns:
            str
                If operation is succeeded, New password is returned.

        Raises:
            LDAPError

        .. note::

            This method operates synchronously.
        """
        try:
            if controls is not None:
                msgid = super().passwd(user, oldpw, newpw, controls)
            else:
                msgid = super().passwd(user, oldpw, newpw)
            result = self.result(msgid, controls=controls)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise LDAPError(**result)
        if 'data' in result:
            # We use lstrip instead of `ber_scanf( ber, "{a}", &s);`
            return result['data'].lstrip(b'0\n\x80\x08').decode('utf-8')
        else:
            return newpw

    def start_tls(self, controls=None):
        """
        Parameters:
            controls : LDAPControl, optional
                LDAP Controls (the default is None, which implies no controls are set)

        Returns:
            None
                If operation is succeeded, None object is returned.

        Raises:
            LDAPError
        """
        try:
            if controls is not None:
                super().start_tls(controls)
            else:
                super().start_tls()
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None

    def set_option(self, option, value, is_global=False):
        """
        Parameters:
            option : int
                LDAP option. Available options are located in libldap.constants
            value : object
                LDAP option value
            is_global : bool, optional
                Flag for LDAP option is set globally or not (the default is False,
                which implies LDAP option is set in this context)

        Returns:
            None
                If operation is succeeded, None object is returned.

        Raises:
            LDAPError

        .. tip::

            These option parameters expect value parameter to be bool.

            * LDAP_OPT_CONNECT_ASYNC
            * LDAP_OPT_REFERRALS
            * LDAP_OPT_RESTART

            These option parameters expect value parameter to be int.

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

            These option parameters expect value parameter to be float or int.

            * LDAP_OPT_NETWORK_TIMEOUT
            * LDAP_OPT_TIMEOUT

            These option parameters expect value parameter to be str.

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

            LDAP_OPT_REFERRAL_URLS option expects value parameter to be [str].

            Other options are not supported.
        """
        try:
            super().set_option(option, value, int(is_global))
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None

    def get_option(self, option, is_global=False):
        """
        Parameters:
            option : int
                LDAP option. Available options are located in libldap.constants
            is_global : bool, optional
                Flag for LDAP option is set globally or not (the default is False,
                which implies LDAP option is set in this context)

        Returns:
            int, str, [str] or None
                Return value varies by option parameter of get_option().

        Raises:
            LDAPError

        .. tip::

            These option parameters return bool value.

            * LDAP_OPT_CONNECT_ASYNC
            * LDAP_OPT_REFERRALS
            * LDAP_OPT_RESTART

            These option parameters return int value.

            * LDAP_OPT_DEBUG_LEVEL
            * LDAP_OPT_DEREF
            * LDAP_OPT_DESC
            * LDAP_OPT_PROTOCOL_VERSION
            * LDAP_OPT_RESULT_CODE
            * LDAP_OPT_SESSION_REFCNT
            * LDAP_OPT_SIZELIMIT
            * LDAP_OPT_TIMELIMIT
            * LDAP_OPT_X_KEEPALIVE_IDLE
            * LDAP_OPT_X_KEEPALIVE_PROBES
            * LDAP_OPT_X_KEEPALIVE_INTERVAL
            * LDAP_OPT_X_TLS_CRLCHECK
            * LDAP_OPT_X_TLS_NEWCTX
            * LDAP_OPT_X_TLS_PROTOCOL_MIN
            * LDAP_OPT_X_TLS_REQUIRE_CERT
            * LDAP_OPT_X_SASL_NOCANON

            These option parameters return float value.

            * LDAP_OPT_NETWORK_TIMEOUT
            * LDAP_OPT_TIMEOUT

            These option parameters return str value.

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
            * LDAP_OPT_X_SASL_AUTHCID
            * LDAP_OPT_X_SASL_AUTHZID
            * LDAP_OPT_X_SASL_MECH
            * LDAP_OPT_X_SASL_MECHLIST
            * LDAP_OPT_X_SASL_REALM
            * LDAP_OPT_X_SASL_SECPROPS
            * LDAP_OPT_X_SASL_USERNAME

            LDAP_OPT_REFERRAL_URLS option parameter returns [str] value.

            LDAP_OPT_API_INFO option parameter returns dict value.
            Return value has following key-value:

                + api_info_version: API Info Version
                + api_version: API Version
                + api_protocol_max: Protocol Max
                + api_extensions:  Extensions
                + api_vendor_name: Vendor Name
                + api_vendor_version: Vendor Version

            Other options are not supported.
        """
        try:
            return super().get_option(option, int(is_global))
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None

    def abandon(self, msgid, controls=None):
        """
        Parameters:
            msgid : int
                Message ID
            controls : LDAPControl, optional
                LDAP Controls (the default is None, which implies no controls are set)

        Returns:
            None
                If operation is succeeded, None object is returned.

        Raises:
            LDAPError
        """
        try:
            if controls is not None:
                return super().abandon(msgid, controls)
            else:
                return super().abandon(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None

    def cancel(self, msgid, controls=None):
        """
        Parameters:
            msgid : int
                Message ID
            controls : LDAPControl, optional
                LDAP Controls (the default is None, which implies no controls are set)

        Returns:
            None
                If operation is succeeded, None object is returned.

        Raises:
            LDAPError
        """
        try:
            if controls is not None:
                return super().cancel(msgid, controls)
            else:
                return super().cancel(msgid)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None

    def result(self, msgid, all=True, timeout=3, controls=None):
        """
        Parameters:
            msgid : int
                Message ID
            all : bool, optional
                Flag for responsing all responses with msgid or not (the default
                is True, which implies all responses with msgid is returned)
            timeout : int
                Timeout for result() method. Zero means wait foreve
                (the default is 3, which implies wait 3 seconds)

        Returns:
            dict or list
                Return result for specified message ID.

        Raises:
            LDAPError
        """
        try:
            if controls is not None:
                return super().result(msgid, int(all), timeout, controls)
            else:
                return super().result(msgid, int(all), timeout)
        except _LDAPError as e:
            raise LDAPError(str(e), LDAP_ERROR) from None

    def search_result(self, *args, **kwargs):
        """
        Return search result by result()

        Parameters:
            `*args` : tuple
                Arguments for result()
            `**kwargs` : dict
                kwargs can contain following key:
                    ordered_attributes : bool
                        (the default is False)

        Returns:
            list
                Return result for specified message ID.

        Raises:
            LDAPError
        """
        if 'ordered_attributes' in kwargs:
            ordered_attributes = kwargs.pop('ordered_attributes')
        else:
            ordered_attributes = False
        results = self.result(*args, **kwargs)
        if results:
            if results[-1]['return_code'] != LDAP_SUCCESS:
                raise LDAPError(**results[-1])
        if ordered_attributes:
            return [_OrderedEntry([(key, entry[key])
                                   for key in entry['__order__']])
                    for entry in results if '__order__' in entry]
        else:
            return [dict([(key, value) for key, value in entry.items()
                          if key != '__order__'])
                    for entry in results if '__order__' in entry]


class LDAPControl(_LDAPObjectControl):
    # FIXME
    pass
