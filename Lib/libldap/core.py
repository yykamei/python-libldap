# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei
"""libldap.core module

This module provides LDAP core operations.
"""

from collections import OrderedDict as _OrderedDict

from _libldap import _LDAPError, _LDAPObject, _LDAPObjectControl
from .constants import LDAP_CONTROL_PAGEDRESULTS
from .exceptions import _generate_exception

__all__ = (
    'LDAP',
    'LDAPControl',
)

LDAP_SUCCESS = 0x00
LDAP_COMPARE_FALSE = 0x05
LDAP_COMPARE_TRUE = 0x06
LDAP_ERROR = -1


class _DictEntry(dict):
    def __init__(self, dn, *args, **kwargs):
        self.dn = dn
        super().__init__(*args, **kwargs)

    def __repr__(self):
        content = ', '.join(['%s: %s' % (x, y) for x, y in self.items()])
        return '{%s}' % (content,)


class _OrderedEntry(_OrderedDict):
    def __init__(self, dn, *args, **kwargs):
        self.dn = dn
        super().__init__(*args, **kwargs)

    def __repr__(self):
        content = ', '.join(['%s: %s' % (x, y) for x, y in self.items()])
        return '{%s}' % (content,)


class LDAP(_LDAPObject):
    """LDAP is libldap wrapper class

    :param uri:
        LDAP URI (e.g. `'ldap://localhost'`, `'ldaps://localhost'`, `'ldapi:///'`)
    :param bind_user:
        LDAP BIND user. This parameter is used only context manager
        (the default is None, which implies BIND operation is not done)
    :param bind_password:
        LDAP BIND password. This parameter is used only context manager
        (the default is None, which implies BIND operation is not done)
    :param options:
        LDAP options. If this is set, set_option() method is called.
        (the default is [], which implies no options are set)

    :type uri:
        str, list or tuple
    :type bind_user:
        str
    :type bind_password:
        str
    :type options:
        [(option, value, is_global)]

    :raises:
        LDAPError
    """

    def __init__(self, uri, bind_user=None, bind_password=None, options=[]):
        self.bind_user = 'anonymous'
        self.__bind_password = None
        if bind_user and bind_password:
            self.bind_user = bind_user
            self.__bind_password = bind_password
        try:
            if isinstance(uri, (list, tuple)):
                super().__init__(','.join(uri))
            else:
                super().__init__(uri)
        except _LDAPError as e:
            raise _generate_exception(e) from None
        try:
            for option, value, is_global in options:
                self.set_option(option, value, is_global)
        except ValueError:
            raise ValueError("Invalid parameter: 'options' parameter type is [(option, value, is_global)]") from None


    def __enter__(self):
        if self.bind_user and self.__bind_password:
            self.bind(self.bind_user, self.__bind_password)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.unbind()

    def bind(self, who, password, controls=None, async=False):
        """
        :param who:
            Who bind to
        :param password:
            Password
        :param controls:
            LDAP Controls (the default is None, which implies no controls are set)
        :param async:
            Flag for asynchronous or not (the default is False,
            which implies operation will done synchronously)

        :type who:
            str
        :type password:
            str
        :type controls:
            LDAPControl or None
        :type async:
            bool

        :returns:
            Nothing or message ID
        :rtype:
            None or int

        :raises:
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
            raise _generate_exception(e) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise _generate_exception(**result)
        self.bind_user = who

    def unbind(self):
        """
        :returns:
            Nothing
        :rtype:
            None

        :raises:
            LDAPError
        """
        try:
            super().unbind()
        except _LDAPError as e:
            raise _generate_exception(e) from None

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
        :param base:
            DN of the entry at which to start the search.
        :param scope:
            Scope of the search.
            it must be LDAP_SCOPE_BASE, LDAP_SCOPE_ONE, LDAP_SCOPE_SUB or
            LDAP_SCOPE_CHILDREN (the default is LDAP_SCOPE_BASE).
        :param filter:
             LDAP filter (the default is '(objectClass=*)')
        :param attributes:
            Attributes for fetching from LDAP server (the default is None,
            which implies '*')
        :param attrsonly:
            Flag for gettting value or not (the default is False)
        :param timeout:
            Timeout for search operation (the default is 0, which implies unlimited)
        :param sizelimit:
            Sizelimit for search operation (the default is 0, which implies unlimited)
        :param controls:
            LDAP Controls (the default is None, which implies no controls are set)
        :param ordered_attributes:
            Flag for attributes order is fixed or not
            (the default is False, which implies attributes order in entry is
            not remembered)
        :param async:
            Flag for asynchronous or not (the default is False,
            which implies operation will done synchronously)
            Synchronous operation returns LDAP responses immediately

        :type base:
            str
        :type scope:
            int
        :type filter:
            str
        :type attributes:
             [str] or None
        :type attrsonly:
            bool
        :type timeout:
            int
        :type sizelimit:
            int
        :type controls:
            LDAPControl or None
        :type ordered_attributes:
            bool
        :type async:
            bool


        :returns:
            List of entries or message ID
        :rtype:
            list or int

        :raises:
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
            raise _generate_exception(e) from None
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
        :param base:
            DN of the entry at which to start the search.
        :param scope:
            Scope of the search.
            it must be LDAP_SCOPE_BASE, LDAP_SCOPE_ONE, LDAP_SCOPE_SUB or
            LDAP_SCOPE_CHILDREN (the default is LDAP_SCOPE_BASE).
        :param filter:
             LDAP filter (the default is '(objectClass=*)')
        :param attributes:
            Attributes for fetching from LDAP server (the default is None,
            which implies '*')
        :param attrsonly:
            Flag for gettting value or not (the default is False)
        :param timeout:
            Timeout for search operation (the default is 0, which implies unlimited)
        :param sizelimit:
            Sizelimit for search operation (the default is 0, which implies unlimited)
        :param pagesize:
            LDAP page size (the default is 100, which implies LDAP search request
            is done by 100 LDAP entries)
        :param ordered_attributes:
            Flag for attributes order is fixed or not
            (the default is False, which implies attributes order in entry is
            not remembered)

        :type base:
            str
        :type scope:
            int
        :type filter:
            str
        :type attributes:
             [str] or None
        :type attrsonly:
            bool
        :type timeout:
            int
        :type sizelimit:
            int
        :type pagesize:
            int
        :type ordered_attributes:
            bool

        :yield:
            LDAP entries (each item is dict)

        :raises:
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
                raise _generate_exception(e) from None
            yield from self.search_result(msgid, timeout=timeout, controls=controls,
                                          ordered_attributes=ordered_attributes)

    def add(self, dn, attributes, controls=None, async=False):
        """
        :param dn:
            DN
        :param attributes:
            List of tuple. tuple has two items:

            * attr   - Attribute name
            * values - List of value
        :param controls:
            LDAP Controls (the default is None, which implies no controls are set)
        :param async:
            Flag for asynchronous or not (the default is False,
            which implies operation will done synchronously)

        :type dn:
            str
        :type attributes:
            [(str, [str])] or [(str, [bytes])]
        :type controls:
            LDAPControl or None
        :type async:
            bool

        :returns:
            If operation is succeeded, None object is returned.
            If async is True, return message ID.
        :rtype:
            None or int

        :raises:
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
            raise _generate_exception(e) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise _generate_exception(**result)

    def modify(self, dn, changes, controls=None, async=False):
        """
        :param dn:
            DN
        :param changes:
            List of tuple. tuple has three items:

            * attr   - Attribute name
            * values - List of value
            * mod_op - Modify operation (e.g.: LDAP_MOD_REPLACE)
        :param controls:
            LDAP Controls (the default is None, which implies no controls are set)
        :param async:
            Flag for asynchronous or not (the default is False,
            which implies operation will done synchronously)

        :type dn:
            str
        :type changes:
            [(str, [str], int)] or [(str, [bytes], int)]
        :type controls:
            LDAPControl or None
        :type async:
            bool

        :returns:
            If operation is succeeded, None object is returned.
            If async is True, return message ID.
        :rtype:
            None or int

        :raises:
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
            raise _generate_exception(e) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise _generate_exception(**result)

    def delete(self, dn, controls=None, async=False):
        """
        :param dn:
            DN
        :param controls:
            LDAP Controls (the default is None, which implies no controls are set)
        :param async:
            Flag for asynchronous or not (the default is False,
            which implies operation will done synchronously)

        :type dn:
            str
        :type controls:
            LDAPControl or None
        :type async:
            bool

        :returns:
            If operation is succeeded, None object is returned.
            If async is True, return message ID.
        :rtype:
            None or int

        :raises:
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
            raise _generate_exception(e) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise _generate_exception(**result)

    def rename(self, dn, newrdn, newparent=None, deleteoldrdn=False, controls=None, async=False):
        """
        :param dn:
            DN
        :param newrdn:
            New RDN
        :param newparent:
            New Parent DN (ths default is None, which implies same parent
            with old dn is set)
        :param deleteoldrdn:
            Flag for deleting old rdn attribute or not (the default is True,
            which implies oldrdn is not deleted after renaming)
        :param controls:
            LDAP Controls (the default is None, which implies no controls are set)
        :param async:
            Flag for asynchronous or not (the default is False,
            which implies operation will done synchronously)

        :type dn:
            str
        :type newrdn:
            str
        :type newparent:
            str or None
        :type deleteoldrdn:
            bool
        :type controls:
            LDAPControl or None
        :type async:
            bool

        :returns:
            If operation is succeeded, None object is returned.
            If async is True, return message ID.
        :rtype:
            None or int

        :raises:
            LDAPError
        """
        if newparent is None:
            try:
                newparent = dn.split(',', 1)[1]
            except IndexError:
                raise _generate_exception('Invalid DN syntax', 0x22)
        try:
            if controls is not None:
                msgid = super().rename(dn, newrdn, newparent, int(deleteoldrdn), controls)
            else:
                msgid = super().rename(dn, newrdn, newparent, int(deleteoldrdn))
            if async:
                return msgid
            result = self.result(msgid, controls=controls)
        except _LDAPError as e:
            raise _generate_exception(e) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise _generate_exception(**result)

    def compare(self, dn, attribute, value, controls=None):
        """
        :param dn:
            DN
        :param attribute:
            Attribute for comparing
        :param value:
            Value for comparing
        :param controls:
            LDAP Controls (the default is None, which implies no controls are set)

        :type dn:
            str
        :type attribute:
            str
        :type value:
            str
        :type controls:
            LDAPControl or None

        :returns:
            Attribute and value found in specified DN or not
        :rtype:
            bool

        :raises:
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
            raise _generate_exception(e) from None
        if result['return_code'] == LDAP_COMPARE_TRUE:
            return True
        elif result['return_code'] == LDAP_COMPARE_FALSE:
            return False
        else:
            raise _generate_exception(**result)

    def whoami(self, controls=None):
        """
        :param controls:
            LDAP Controls (the default is None, which implies no controls are set)

        :type controls:
            LDAPControl or None

        :returns:
            If operation is succeeded, DN is returned.
        :rtype:
            str

        :raises:
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
            raise _generate_exception(e) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise _generate_exception(**result)
        if 'data' in result and result['data']:
            return result['data'].decode('utf-8')
        else:
            return 'anonymous'

    def passwd(self, user, oldpw=None, newpw=None, controls=None):
        """
        :param user:
            DN of user
        :param oldpw:
            Old password of *user* (the default is None, which implies
            authentication will be skipped)
        :param newpw:
            New password of *user* (the default is None, which implies
            password will be created by randomly)
        :param controls:
            LDAP Controls (the default is None, which implies no controls are set)

        :type user:
            str
        :type oldpw:
            str or None
        :type newpw:
            str or None
        :type controls:
            LDAPControl or None

        :returns:
            If operation is succeeded, New password is returned.
        :rtype:
            str

        :raises:
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
            raise _generate_exception(e) from None
        if result['return_code'] != LDAP_SUCCESS:
            raise _generate_exception(**result)
        if 'data' in result:
            # We use lstrip instead of `ber_scanf( ber, "{a}", &s);`
            return result['data'].lstrip(b'0\n\x80\x08').decode('utf-8')
        else:
            return newpw

    def start_tls(self, controls=None):
        """
        :param controls:
            LDAP Controls (the default is None, which implies no controls are set)

        :type controls:
            LDAPControl or None

        :returns:
            If operation is succeeded, None object is returned.
        :rtype:
            None

        :raises:
            LDAPError
        """
        try:
            if controls is not None:
                super().start_tls(controls)
            else:
                super().start_tls()
        except _LDAPError as e:
            raise _generate_exception(e) from None

    def set_option(self, option, value, is_global=False):
        """
        :param option:
            LDAP option. Available options are located in libldap.constants
        :param value:
            LDAP option value
        :param is_global:
            Flag for LDAP option is set globally or not (the default is False,
            which implies LDAP option is set in this context)

        :type option:
            int
        :type value:
            object
        :type is_global:
            bool

        :returns:
            If operation is succeeded, None object is returned.
        :rtype:
            None

        :raises:
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
            raise _generate_exception(e) from None

    def get_option(self, option, is_global=False):
        """
        :param option:
            LDAP option. Available options are located in libldap.constants
        :param is_global:
            Flag for LDAP option is set globally or not (the default is False,
            which implies LDAP option is set in this context)

        :type option:
            int
        :type is_global:
            bool

        :returns:
            Return value varies by option parameter of get_option().
        :rtype:
            int, str, [str] or None

        :raises:
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
            raise _generate_exception(e) from None

    def abandon(self, msgid, controls=None):
        """
        :param msgid:
            Message ID
        :param controls:
            LDAP Controls (the default is None, which implies no controls are set)

        :type msgid:
            int
        :type controls:
            LDAPControl or None

        :returns:
            If operation is succeeded, None object is returned.
        :rtype:
            None

        :raises:
            LDAPError
        """
        try:
            if controls is not None:
                return super().abandon(msgid, controls)
            else:
                return super().abandon(msgid)
        except _LDAPError as e:
            raise _generate_exception(e) from None

    def cancel(self, msgid, controls=None):
        """
        :param msgid:
            Message ID
        :param controls:
            LDAP Controls (the default is None, which implies no controls are set)

        :type msgid:
            int
        :type controls:
            LDAPControl or None

        :returns:
            If operation is succeeded, None object is returned.
        :rtype:
            None

        :raises:
            LDAPError
        """
        try:
            if controls is not None:
                return super().cancel(msgid, controls)
            else:
                return super().cancel(msgid)
        except _LDAPError as e:
            raise _generate_exception(e) from None

    def result(self, msgid, all=True, timeout=3, controls=None):
        """
        :param msgid:
            Message ID
        :param all:
            Flag for responsing all responses with msgid or not (the default
            is True, which implies all responses with msgid is returned)
        :param timeout:
            Timeout for result() method. Zero means wait foreve
            (the default is 3, which implies wait 3 seconds)
        :param controls:
            LDAP Controls (the default is None, which implies no controls are set).
            If controls is set and LDAP response has control message, return value
            has control key-value.

        :type msgid:
            int
        :type all:
            int
        :type timeout:
            int
        :type controls:
            LDAPControl or None

        :returns:
            Return result for specified message ID.
        :rtype:
            dict or list

        :raises:
            LDAPError

        .. note::

            If you have done search() asynchronously, you should use search_result()
            instead of result(). result() get raw data, raw data has __order__ key,
            which has attribute order.
        """
        try:
            if controls is not None:
                return super().result(msgid, int(all), timeout, controls)
            else:
                return super().result(msgid, int(all), timeout)
        except _LDAPError as e:
            raise _generate_exception(e) from None

    def search_result(self, *args, **kwargs):
        """
        :param `*args`:
            Arguments for result()
        :param `**kwargs`:
            kwargs can contain following key:

                * ordered_attributes : bool (the default is False)

        :type `*args`:
            tuple
        :type `**kwargs`:
            dict

        :returns:
            Return LDAP entries for specified message ID.
        :rtype:
            [_DictEntry] or [_OrderedEntry]

            _OrderedEntry and _DictEntry are classes which inherit
            dict or OrderedDict. They have 'dn' attribute.

        :raises:
            LDAPError
        """
        if 'ordered_attributes' in kwargs:
            ordered_attributes = kwargs.pop('ordered_attributes')
        else:
            ordered_attributes = False
        results = self.result(*args, **kwargs)
        if results:
            if results[-1]['return_code'] != LDAP_SUCCESS:
                raise _generate_exception(**results[-1])
        if ordered_attributes:
            return [_OrderedEntry(entry.pop('dn'), [(key, entry[key]) for key in entry['__order__']])
                    for entry in results if '__order__' in entry]
        else:
            return [_DictEntry(entry.pop('dn'), [(key, value) for key, value in entry.items() if key != '__order__'])
                    for entry in results if '__order__' in entry]


class LDAPControl(_LDAPObjectControl):
    """
    .. todo::

        Hide _LDAPObjectControl methods.
    """
    pass
