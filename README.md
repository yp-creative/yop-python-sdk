# yop-python-sdk

import yp2util
import yp2const

def reset_passwd_url(ouid, webCallBackUrl, returnUrl, logger=None):
    api = 'user/getPswdResetUrl'
    params = {'merchantUserId': ouid,
              'webCallBackUrl': webCallBackUrl,
              'returnUrl': returnUrl,
              }
    return yp2util.restful(api, params=params, logger=logger)
