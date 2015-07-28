# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei

# LDAP Scopes
LDAP_SCOPE_BASE = 0x0000
LDAP_SCOPE_ONE = 0x0001
LDAP_SCOPE_SUB = 0x0002
LDAP_SCOPE_CHILDREN = 0x0003

# LDAP Modify Operation
LDAP_MOD_ADD = 0x0000
LDAP_MOD_DELETE = 0x0001
LDAP_MOD_REPLACE = 0x0002
LDAP_MOD_INCREMENT = 0x0003

# LDAP Options
LDAP_OPT_API_INFO = 0x0000
LDAP_OPT_DESC = 0x0001
LDAP_OPT_DEREF = 0x0002
LDAP_OPT_SIZELIMIT = 0x0003
LDAP_OPT_TIMELIMIT = 0x0004
LDAP_OPT_REFERRALS = 0x0008
LDAP_OPT_RESTART = 0x0009
LDAP_OPT_PROTOCOL_VERSION = 0x0011
LDAP_OPT_SERVER_CONTROLS = 0x0012
LDAP_OPT_CLIENT_CONTROLS = 0x0013
LDAP_OPT_API_FEATURE_INFO = 0x0015
LDAP_OPT_HOST_NAME = 0x0030
LDAP_OPT_RESULT_CODE = 0x0031
LDAP_OPT_DIAGNOSTIC_MESSAGE = 0x0032
LDAP_OPT_MATCHED_DN = 0x0033
LDAP_OPT_DEBUG_LEVEL = 0x5001
LDAP_OPT_TIMEOUT = 0x5002
LDAP_OPT_NETWORK_TIMEOUT = 0x5005
LDAP_OPT_URI = 0x5006
LDAP_OPT_REFERRAL_URLS = 0x5007
LDAP_OPT_SOCKBUF = 0x5008
LDAP_OPT_DEFBASE = 0x5009
LDAP_OPT_CONNECT_ASYNC = 0x5010
LDAP_OPT_CONNECT_CB = 0x5011
LDAP_OPT_SESSION_REFCNT = 0x5012
LDAP_OPT_X_TLS_CTX = 0x6001
LDAP_OPT_X_TLS_CACERTFILE = 0x6002
LDAP_OPT_X_TLS_CACERTDIR = 0x6003
LDAP_OPT_X_TLS_CERTFILE = 0x6004
LDAP_OPT_X_TLS_KEYFILE = 0x6005
LDAP_OPT_X_TLS_REQUIRE_CERT = 0x6006
LDAP_OPT_X_TLS_PROTOCOL_MIN = 0x6007
LDAP_OPT_X_TLS_CIPHER_SUITE = 0x6008
LDAP_OPT_X_TLS_RANDOM_FILE = 0x6009
LDAP_OPT_X_TLS_CRLCHECK = 0x600b
LDAP_OPT_X_TLS_CONNECT_CB = 0x600c
LDAP_OPT_X_TLS_CONNECT_ARG = 0x600d
LDAP_OPT_X_TLS_DHFILE = 0x600e
LDAP_OPT_X_TLS_NEWCTX = 0x600f
LDAP_OPT_X_TLS_CRLFILE = 0x6010
LDAP_OPT_X_SASL_MECH = 0x6100
LDAP_OPT_X_SASL_REALM = 0x6101
LDAP_OPT_X_SASL_AUTHCID = 0x6102
LDAP_OPT_X_SASL_AUTHZID = 0x6103
LDAP_OPT_X_SASL_SSF = 0x6104
LDAP_OPT_X_SASL_SSF_EXTERNAL = 0x6105
LDAP_OPT_X_SASL_SECPROPS = 0x6106
LDAP_OPT_X_SASL_SSF_MIN = 0x6107
LDAP_OPT_X_SASL_SSF_MAX = 0x6108
LDAP_OPT_X_SASL_MAXBUFSIZE = 0x6109
LDAP_OPT_X_SASL_MECHLIST = 0x610a
LDAP_OPT_X_SASL_NOCANON = 0x610b
LDAP_OPT_X_SASL_USERNAME = 0x610c
LDAP_OPT_X_KEEPALIVE_IDLE = 0x6300
LDAP_OPT_X_KEEPALIVE_PROBES = 0x6301
LDAP_OPT_X_KEEPALIVE_INTERVAL = 0x6302

# For LDAP_OPT_X_TLS_REQUIRE_CERT
LDAP_OPT_X_TLS_NEVER = 0
LDAP_OPT_X_TLS_HARD = 1
LDAP_OPT_X_TLS_DEMAND = 2
LDAP_OPT_X_TLS_ALLOW = 3
LDAP_OPT_X_TLS_TRY = 4

# For LDAP_OPT_X_TLS_CRLCHECK
LDAP_OPT_X_TLS_CRL_NONE = 0
LDAP_OPT_X_TLS_CRL_PEER = 1
LDAP_OPT_X_TLS_CRL_ALL = 2

# FOR LDAP_OPT_X_TLS_PROTOCOL_MIN
LDAP_OPT_X_TLS_PROTOCOL_SSL2 = (2 << 8)
LDAP_OPT_X_TLS_PROTOCOL_SSL3 = (3 << 8)
LDAP_OPT_X_TLS_PROTOCOL_TLS1_0 = ((3 << 8) + 1)
LDAP_OPT_X_TLS_PROTOCOL_TLS1_1 = ((3 << 8) + 2)
LDAP_OPT_X_TLS_PROTOCOL_TLS1_2 = ((3 << 8) + 3)
