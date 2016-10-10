#!/usr/bin/env python
# coding=utf-8
# Created at 16/9/28

YOP_BASE_URL = 'https://open.yeepay.com/yop-center'
YOP_MERCHANT_NO = '#'
YOP_APP_KEY = '#'
YOP_SECRET_KEY = '#'
YOP_SIGN_ALG = "sha256"
YOP_API_VERSION = "v1.0"
YOP_VERBOSE_LOG = True

try:
    from local_settings.yp2const import *
except:
    pass
