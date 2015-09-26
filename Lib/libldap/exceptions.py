# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei
"""libldap.exceptions module

This module provides LDAP exceptions classes.


libldap exceptions hierarchy::

    LDAPError
    ├── LDAPAPIError
    │   ├── LDAPAuthUnknown
    │   ├── LDAPClientLoop
    │   ├── LDAPConnectError
    │   ├── LDAPControlNotFound
    │   ├── LDAPDecodingError
    │   ├── LDAPEncodingError
    │   ├── LDAPFilterError
    │   ├── LDAPLocalError
    │   ├── LDAPMoreResultsToReturn
    │   ├── LDAPNoMemory
    │   ├── LDAPNoResultsReturned
    │   ├── LDAPNotSupported
    │   ├── LDAPParamError
    │   ├── LDAPReferralLimitExceeded
    │   ├── LDAPServerDown
    │   ├── LDAPTimeout
    │   ├── LDAPUserCancelled
    │   └── LDAPXConnecting
    └── LDAPFailedResult
        ├── LDAPAdminlimitExceeded
        ├── LDAPAffectsMultipleDsas
        ├── LDAPAliasDerefProblem
        ├── LDAPAliasProblem
        ├── LDAPAlreadyExists
        ├── LDAPAuthMethodNotSupported
        ├── LDAPBusy
        ├── LDAPCompareFalse
        ├── LDAPCompareTrue
        ├── LDAPConfidentialityRequired
        ├── LDAPConstraintViolation
        ├── LDAPInappropriateAuth
        ├── LDAPInappropriateMatching
        ├── LDAPInsufficientAccess
        ├── LDAPInvalidCredentials
        ├── LDAPInvalidDnSyntax
        ├── LDAPInvalidSyntax
        ├── LDAPIsLeaf
        ├── LDAPLoopDetect
        ├── LDAPNamingViolation
        ├── LDAPNoObjectClassMods
        ├── LDAPNoSuchAttribute
        ├── LDAPNoSuchObject
        ├── LDAPNotAllowedOnNonleaf
        ├── LDAPNotAllowedOnRdn
        ├── LDAPObjectClassViolation
        ├── LDAPOperationsError
        ├── LDAPOther
        ├── LDAPPartialResults
        ├── LDAPProtocolError
        ├── LDAPReferral
        ├── LDAPResultsTooLarge
        ├── LDAPSaslBindInProgress
        ├── LDAPSizelimitExceeded
        ├── LDAPStrongAuthRequired
        ├── LDAPTimelimitExceeded
        ├── LDAPTypeOrValueExists
        ├── LDAPUnavailable
        ├── LDAPUnavailableCriticalExtension
        ├── LDAPUndefinedType
        ├── LDAPUnwillingToPerform
        └── LDAPVlvError
"""

import re


class LDAPError(Exception):
    def __init__(self, message, return_code, *args, **kwargs):
        self.message = message
        self.return_code = return_code
        self.args = args
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __repr__(self):
        additional_info = ' %s' % (getattr(self, 'ppolicy_msg', ''),)
        if self.return_code is not None:
            return 'LDAPError(%s, %s)' % (repr(self.message), repr(self.return_code))
        else:
            return 'LDAPError(%s)' % (repr(self.message),)

    def __str__(self):
        additional_info = ' %s' % (getattr(self, 'ppolicy_msg', ''),)
        if self.return_code is not None and self.return_code > 0:
            return '%s (%s)%s' % (self.message, self.return_code, additional_info)
        else:
            return '%s%s' % (self.message, additional_info)


# Main Exceptions

LDAPAPIError = type('LDAPAPIError', (LDAPError,), {})
LDAPFailedResult = type('LDAPFailedResult', (LDAPError,), {})

# Sub classes of LDAPAPIError

LDAPServerDown = type('LDAPServerDown', (LDAPAPIError,), {})
LDAPLocalError = type('LDAPLocalError', (LDAPAPIError,), {})
LDAPEncodingError = type('LDAPEncodingError', (LDAPAPIError,), {})
LDAPDecodingError = type('LDAPDecodingError', (LDAPAPIError,), {})
LDAPTimeout = type('LDAPTimeout', (LDAPAPIError,), {})
LDAPAuthUnknown = type('LDAPAuthUnknown', (LDAPAPIError,), {})
LDAPFilterError = type('LDAPFilterError', (LDAPAPIError,), {})
LDAPUserCancelled = type('LDAPUserCancelled', (LDAPAPIError,), {})
LDAPParamError = type('LDAPParamError', (LDAPAPIError,), {})
LDAPNoMemory = type('LDAPNoMemory', (LDAPAPIError,), {})
LDAPConnectError = type('LDAPConnectError', (LDAPAPIError,), {})
LDAPNotSupported = type('LDAPNotSupported', (LDAPAPIError,), {})
LDAPControlNotFound = type('LDAPControlNotFound', (LDAPAPIError,), {})
LDAPNoResultsReturned = type('LDAPNoResultsReturned', (LDAPAPIError,), {})
LDAPMoreResultsToReturn = type('LDAPMoreResultsToReturn', (LDAPAPIError,), {})
LDAPClientLoop = type('LDAPClientLoop', (LDAPAPIError,), {})
LDAPReferralLimitExceeded = type('LDAPReferralLimitExceeded', (LDAPAPIError,), {})
LDAPXConnecting = type('LDAPXConnecting', (LDAPAPIError,), {})

# Sub classes of LDAPFailedResult

LDAPOperationsError = type('LDAPOperationsError', (LDAPFailedResult,), {})
LDAPProtocolError = type('LDAPProtocolError', (LDAPFailedResult,), {})
LDAPTimelimitExceeded = type('LDAPTimelimitExceeded', (LDAPFailedResult,), {})
LDAPSizelimitExceeded = type('LDAPSizelimitExceeded', (LDAPFailedResult,), {})
LDAPCompareFalse = type('LDAPCompareFalse', (LDAPFailedResult,), {})
LDAPCompareTrue = type('LDAPCompareTrue', (LDAPFailedResult,), {})
LDAPAuthMethodNotSupported = type('LDAPAuthMethodNotSupported', (LDAPFailedResult,), {})
LDAPStrongAuthRequired = type('LDAPStrongAuthRequired', (LDAPFailedResult,), {})
LDAPPartialResults = type('LDAPPartialResults', (LDAPFailedResult,), {})
LDAPReferral = type('LDAPReferral', (LDAPFailedResult,), {})
LDAPAdminlimitExceeded = type('LDAPAdminlimitExceeded', (LDAPFailedResult,), {})
LDAPUnavailableCriticalExtension = type('LDAPUnavailableCriticalExtension', (LDAPFailedResult,), {})
LDAPConfidentialityRequired = type('LDAPConfidentialityRequired', (LDAPFailedResult,), {})
LDAPSaslBindInProgress = type('LDAPSaslBindInProgress', (LDAPFailedResult,), {})
LDAPNoSuchAttribute = type('LDAPNoSuchAttribute', (LDAPFailedResult,), {})
LDAPUndefinedType = type('LDAPUndefinedType', (LDAPFailedResult,), {})
LDAPInappropriateMatching = type('LDAPInappropriateMatching', (LDAPFailedResult,), {})
LDAPConstraintViolation = type('LDAPConstraintViolation', (LDAPFailedResult,), {})
LDAPTypeOrValueExists = type('LDAPTypeOrValueExists', (LDAPFailedResult,), {})
LDAPInvalidSyntax = type('LDAPInvalidSyntax', (LDAPFailedResult,), {})
LDAPNoSuchObject = type('LDAPNoSuchObject', (LDAPFailedResult,), {})
LDAPAliasProblem = type('LDAPAliasProblem', (LDAPFailedResult,), {})
LDAPInvalidDnSyntax = type('LDAPInvalidDnSyntax', (LDAPFailedResult,), {})
LDAPIsLeaf = type('LDAPIsLeaf', (LDAPFailedResult,), {})
LDAPAliasDerefProblem = type('LDAPAliasDerefProblem', (LDAPFailedResult,), {})
LDAPInappropriateAuth = type('LDAPInappropriateAuth', (LDAPFailedResult,), {})
LDAPInvalidCredentials = type('LDAPInvalidCredentials', (LDAPFailedResult,), {})
LDAPInsufficientAccess = type('LDAPInsufficientAccess', (LDAPFailedResult,), {})
LDAPBusy = type('LDAPBusy', (LDAPFailedResult,), {})
LDAPUnavailable = type('LDAPUnavailable', (LDAPFailedResult,), {})
LDAPUnwillingToPerform = type('LDAPUnwillingToPerform', (LDAPFailedResult,), {})
LDAPLoopDetect = type('LDAPLoopDetect', (LDAPFailedResult,), {})
LDAPNamingViolation = type('LDAPNamingViolation', (LDAPFailedResult,), {})
LDAPObjectClassViolation = type('LDAPObjectClassViolation', (LDAPFailedResult,), {})
LDAPNotAllowedOnNonleaf = type('LDAPNotAllowedOnNonleaf', (LDAPFailedResult,), {})
LDAPNotAllowedOnRdn = type('LDAPNotAllowedOnRdn', (LDAPFailedResult,), {})
LDAPAlreadyExists = type('LDAPAlreadyExists', (LDAPFailedResult,), {})
LDAPNoObjectClassMods = type('LDAPNoObjectClassMods', (LDAPFailedResult,), {})
LDAPResultsTooLarge = type('LDAPResultsTooLarge', (LDAPFailedResult,), {})
LDAPAffectsMultipleDsas = type('LDAPAffectsMultipleDsas', (LDAPFailedResult,), {})
LDAPVlvError = type('LDAPVlvError', (LDAPFailedResult,), {})
LDAPOther = type('LDAPOther', (LDAPFailedResult,), {})


def _generate_exception(message, return_code=None, *args, **kwargs):
    if return_code is None:
        matched = re.search(r'\((-?\d+)\)', str(message))
        if matched:
            return_code = int(matched.group(1))
    try:
        return {
            -1: LDAPServerDown,
            -2: LDAPLocalError,
            -3: LDAPEncodingError,
            -4: LDAPDecodingError,
            -5: LDAPTimeout,
            -6: LDAPAuthUnknown,
            -7: LDAPFilterError,
            -8: LDAPUserCancelled,
            -9: LDAPParamError,
            -10: LDAPNoMemory,
            -11: LDAPConnectError,
            -12: LDAPNotSupported,
            -13: LDAPControlNotFound,
            -14: LDAPNoResultsReturned,
            -15: LDAPMoreResultsToReturn,
            -16: LDAPClientLoop,
            -17: LDAPReferralLimitExceeded,
            -18: LDAPXConnecting,
            0x01: LDAPOperationsError,
            0x02: LDAPProtocolError,
            0x03: LDAPTimelimitExceeded,
            0x04: LDAPSizelimitExceeded,
            0x05: LDAPCompareFalse,
            0x06: LDAPCompareTrue,
            0x07: LDAPAuthMethodNotSupported,
            0x08: LDAPStrongAuthRequired,
            0x09: LDAPPartialResults,
            0x0a: LDAPReferral,
            0x0b: LDAPAdminlimitExceeded,
            0x0c: LDAPUnavailableCriticalExtension,
            0x0d: LDAPConfidentialityRequired,
            0x0e: LDAPSaslBindInProgress,
            0x10: LDAPNoSuchAttribute,
            0x11: LDAPUndefinedType,
            0x12: LDAPInappropriateMatching,
            0x13: LDAPConstraintViolation,
            0x14: LDAPTypeOrValueExists,
            0x15: LDAPInvalidSyntax,
            0x20: LDAPNoSuchObject,
            0x21: LDAPAliasProblem,
            0x22: LDAPInvalidDnSyntax,
            0x23: LDAPIsLeaf,
            0x24: LDAPAliasDerefProblem,
            0x30: LDAPInappropriateAuth,
            0x31: LDAPInvalidCredentials,
            0x32: LDAPInsufficientAccess,
            0x33: LDAPBusy,
            0x34: LDAPUnavailable,
            0x35: LDAPUnwillingToPerform,
            0x36: LDAPLoopDetect,
            0x40: LDAPNamingViolation,
            0x41: LDAPObjectClassViolation,
            0x42: LDAPNotAllowedOnNonleaf,
            0x43: LDAPNotAllowedOnRdn,
            0x44: LDAPAlreadyExists,
            0x45: LDAPNoObjectClassMods,
            0x46: LDAPResultsTooLarge,
            0x47: LDAPAffectsMultipleDsas,
            0x4c: LDAPVlvError,
            0x50: LDAPOther,
        }[return_code](str(message), return_code, *args, **kwargs)
    except KeyError:
        return LDAPError(str(message), None, *args, **kwargs)
