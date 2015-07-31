# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei

# NOTE: Argument 'filter' conflicts with built-in 'filter' function
_filter = filter

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

    def bind(self, who, password, controls=None, async=False):
        """
        Parameters
        ----------
        who : str
        password : str
        controls : LDAPControl, optional
            (the default is None, which implies no controls are set)
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
            if controls is not None:
                kwargs = {}
                ppolicy_msg = controls.get_info('ppolicy_msg')
                if ppolicy_msg:
                    kwargs['ppolicy_msg'] = ppolicy_msg
                result.update(kwargs)
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
               controls=None,
               ordered_attributes=False,
               async=False):
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
        controls : LDAPControl, optional
            (the default is None, which implies no controls are set)
        ordered_attributes : bool, optional
            If ordered_attributes is True, the order of the attributes in entry
            are remembered (the default is False).
        async : bool
            If True, return result immediately
            (the default is False, which means operation will
            done synchronously).

        Returns
        -------
        list
            List of entries.

        Raises
        ------
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
        _pagesize = ('%d' % (pagesize,)).encode('utf-8')
        controls = _LDAPObjectControl()
        controls.add_control(LDAP_CONTROL_PAGEDRESULTS, _pagesize, False)
        initial = True
        while initial or controls.get_info('pr_cookie') is not None:
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
        Parameters
        ----------
        dn : str
        attributes : [(str, [str])]
            List of tuple. tuple has two items:
                attr   - Attribute name
                values - List of value
        controls : LDAPControl, optional
            (the default is None, which implies no controls are set)
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
        Parameters
        ----------
        dn : str
        changes : [(str, [str], int)]
            List of tuple. tuple has three items:
                attr   - Attribute name
                values - List of value
                mod_op - Modify operation (e.g.: LDAP_MOD_REPLACE)
        controls : LDAPControl, optional
            (the default is None, which implies no controls are set)
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
        Parameters
        ----------
        dn : str
        controls : LDAPControl, optional
            (the default is None, which implies no controls are set)
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

    def rename(self, dn, newrdn, newparent, deleteoldrdn=True, controls=None, async=False):
        """
        Parameters
        ----------
        dn : str
        newrdn : str
        newparent : str
        deleteoldrdn : bool
            (the default is True, which means oldrdn is deleted after renamed)
        controls : LDAPControl, optional
            (the default is None, which implies no controls are set)
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
        Parameters
        ----------
        dn : str
        attribute : str
        value : str
        controls : LDAPControl, optional
            (the default is None, which implies no controls are set)

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
        Parameters
        ----------
        controls : LDAPControl, optional
            (the default is None, which implies no controls are set)

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
        Parameters
        ----------
        user : str
        oldpw : str, optional
        newpw : str, optional
        controls : LDAPControl, optional
            (the default is None, which implies no controls are set)

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
        Parameters
        ----------
        controls : LDAPControl, optional
            (the default is None, which implies no controls are set)

        Returns
        -------
        None
            If operation is succeeded, None object is returned.

        Raises
        ------
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

    def abandon(self, msgid, controls=None):
        """
        Parameters
        ----------
        msgid : int
        controls : LDAPControl, optional
            (the default is None, which implies no controls are set)

        Returns
        -------
        None
            If operation is succeeded, None object is returned.

        Raises
        ------
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
        Parameters
        ----------
        msgid : int
        controls : LDAPControl, optional
            (the default is None, which implies no controls are set)

        Returns
        -------
        None
            If operation is succeeded, None object is returned.

        Raises
        ------
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
        Parameters
        ----------
        msgid : int
        all : bool
        timeout : int
            Zero means unlimited (the default is 3)

        Returns
        -------
        dict or list
            Return result for specified message ID.

        Raises
        ------
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

        Parameters
        ----------
        *args : tuple
        **kwargs : dict
            kwargs can contain following key:
                ordered_attributes : bool
                    (the default is False)

        Returns
        -------
        list
            Return result for specified message ID.

        Raises
        ------
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
    pass
