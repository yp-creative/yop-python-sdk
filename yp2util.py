#!/usr/bin/env python
# coding=utf-8
# Created at 16/9/28

import yp2const
import hashlib
import time
import hmac
import base64
import hashlib
import urllib
import urllib2
import logging
import time
from poster.encode import multipart_encode, MultipartParam
from poster.streaminghttp import register_openers
import simplejson as sj
import re
from Crypto.Cipher import AES
from cStringIO import StringIO

_DEFAULT_LOGGER = None

PAD_LEN = 16
padding = lambda s: s + (PAD_LEN - len(s) % PAD_LEN) \
                        * chr(PAD_LEN - len(s) % PAD_LEN)
unpadding = lambda s: s[:-ord(s[-1])] if len(s) else s
dict_encoding = lambda dct, enc='utf-8': \
    dict((k, v.encode(enc) if isinstance(v, unicode) else v)
         for k, v in dct.iteritems())
utf8_to_gbk = lambda v: v.decode('utf-8').encode('gbk') if v else ''
decode_gbk = lambda v: urllib.unquote_plus(v).decode('gbk').encode('utf-8') if v else ''


def get_default_logger():
    global _DEFAULT_LOGGER
    if _DEFAULT_LOGGER is None:
        logger = logging.getLogger('_yeepay2_default_')
        if len(logger.handlers) == 0:
            hdl = logging.StreamHandler()
            hdl.setFormatter(logging.Formatter(
                '%(levelname)s %(asctime)s %(thread)d %(message)s'))
            hdl.setLevel(logging.DEBUG)
            logger.addHandler(hdl)
            logger.setLevel(logging.DEBUG)
        _DEFAULT_LOGGER = logger
    return _DEFAULT_LOGGER


def get_sign(params, secret=yp2const.YOP_SECRET_KEY, sign_alg=yp2const.YOP_SIGN_ALG):
    if not params or not isinstance(params, dict):
        raise Exception('there is no params')
    if not secret:
        raise Exception('there is no secret key')
    if not sign_alg:
        sign_alg = 'sha1'

    strings = [secret]
    for (key, value) in sorted(params.items(), key=lambda x: x[0]):
        if value:
            strings.append(key)
            strings.append(str(value))
    strings.append(secret)
    __alg_func = getattr(hashlib, sign_alg)
    return __alg_func(''.join(strings)).hexdigest()


def sign_params(params):
    params.pop('sign')
    sign = get_sign(params)
    params['sign'] = sign
    return params


def combine_url(url, query_dict):
    if not query_dict:
        return url
    if isinstance(query_dict, dict):
        query_dict = urllib.urlencode(query_dict)
    return url + '?' + query_dict


def aes_encrypt(data):
    if not isinstance(data, str):
        data = sj.dumps(data)
    cipher = AES.new(base64.b64decode(yp2const.YOP_SECRET_KEY))
    return base64.b64encode(cipher.encrypt(padding(data)))


def aes_decrypt(data):
    cipher = AES.new(base64.b64decode(yp2const.YOP_SECRET_KEY))
    js = unpadding(cipher.decrypt(base64.b64decode(data)))
    return js


def parse_result(result, logger=None, enc='utf-8', verbose=yp2const.YOP_VERBOSE_LOG):
    if logger is None:
        logger = get_default_logger()
    if not result:
        return False, {}
    try:
        if isinstance(result, dict):
            dct0 = result
        else:
            dct0 = sj.loads(result, encoding=enc)
        if 'result' in dct0:
            data = dct0.get('result')
            encrypt_js = re.sub('[\t\n]', '', sj.dumps(data))
            js = aes_decrypt(encrypt_js)
            dct = dict_encoding(sj.loads(js, encoding=enc), enc)
            if verbose:
                logger.debug('decrypted_json %s', js)
        else:
            js = result
            if verbose:
                logger.debug('undecrypted_json %s', js)
            return False, {}
    except Exception, e:
        logger.exception('ret_json_err e=%s,r=%s', e, result)
        return False, {}
    if not isinstance(dct, dict):
        logger.error('invalid_ret r=%s', dct)
        return False, {}
    return True, dct


def http_request(
        url, query_dict=None, post=1, post_dict=None,
        headers=None, timeout=40, verbose=yp2const.YOP_VERBOSE_LOG,
        tryn=1, retry_sleep=2, logger=None, **kwargs):
    t1 = time.time()
    if post and not post_dict:
        post_dict = query_dict if query_dict else ''
        query_dict = None
    if not headers:
        headers = {}
    if logger is None:
        logger = get_default_logger()

    try:
        if not post and not headers:
            _request = combine_url(url=url, query_dict=query_dict)
        else:
            url = combine_url(url=url, query_dict=query_dict)
            if post == 2:
                register_openers()
                datagen, _h = multipart_encode(post_dict)
                headers.update(_h)
            else:
                datagen = urllib.urlencode(post_dict) \
                    if post_dict else ''
            _request = urllib2.Request(url, datagen)
            for k, v in headers.iteritems():
                _request.add_header(k, v)
        request = urllib2.urlopen(_request, timeout=timeout)
        data = request.read()
        request.close()
        t2 = time.time()
        if verbose:
            logger.debug('yeepay2_req url=%s,qd=%s,time=%s',
                         url, query_dict, t2 - t1)
        return data
    except Exception, e:
        rcode = e.code if hasattr(e, 'code') else '?'
        rfp = e.fp if hasattr(e, 'fp') else '?'
        qdstr = str(query_dict)
        if qdstr and len(qdstr) >= 500:
            qdstr = qdstr[:500]
        logger.exception('err=%s,code=%s,fp=%s,url=%s,post=%d,q=%s,h=%s',
                         e, rcode, rfp, url, post, qdstr, headers)
        if tryn > 1:
            time.sleep(retry_sleep)
            return http_request(
                url=url, query_dict=query_dict, post=post,
                headers=headers, timeout=timeout, tryn=tryn - 1,
                retry_sleep=retry_sleep, logger=logger, **kwargs)
        return None


def restful(api, params={}, group='', version=yp2const.YOP_API_VERSION, logger=None, verbose=yp2const.YOP_VERBOSE_LOG):
    if not logger:
        logger = get_default_logger()
    if group:
        api = group + '/' + api
    url = '/'.join([yp2const.YOP_BASE_URL, 'rest', version, api])
    if not params:
        params = {}
    if 'requestNo' not in params:
        params['requestNo'] = '%s#%s' % (api[0:15], str(int(time.time() * 1000000)))
    params['merchantNo'] = yp2const.YOP_MERCHANT_NO
    params['appKey'] = yp2const.YOP_APP_KEY
    params['v'] = version[1:]
    params['method'] = '/'.join(['/rest', version, api])
    signed_params = sign_params(params)
    data = http_request(url, query_dict=signed_params, logger=logger)
    if verbose:
        logger.debug('api=%s \nparams=%s \ndata=%s', api, signed_params, data)
    try:
        json = sj.loads(data)
        ret = json.get('result', json.get('error', {}))
        return ret, ret.get('code', '-1') if json else '-1'
    except Exception, e:
        logger.exception('err=%s data=%s', e, data)
        return None, '-1'
