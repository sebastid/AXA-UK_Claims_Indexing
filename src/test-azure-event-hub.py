import time
import urllib.parse
import hmac
import hashlib
import base64

def get_auth_token(sb_name, eh_name, sas_name, sas_value):
    """
    Returns an authorization token dictionary 
    for making calls to Event Hubs REST API.
    """
    uri = urllib.parse.quote_plus("https://{}.servicebus.windows.net/{}" \
                                  .format(sb_name, eh_name))
    sas = sas_value.encode('utf-8')
    expiry = str(int(time.time() + 10000))
    string_to_sign = (uri + '\n' + expiry).encode('utf-8')
    signed_hmac_sha256 = hmac.HMAC(sas, string_to_sign, hashlib.sha256)
    signature = urllib.parse.quote(base64.b64encode(signed_hmac_sha256.digest()))
    return  {"sb_name": sb_name,
             "eh_name": eh_name,
             "token":'SharedAccessSignature sr={}&sig={}&se={}&skn={}' \
                     .format(uri, signature, expiry, sas_name)
            }

sb_name = 'instabase-axa-uk'
eh_name = 'ib-claim-indexing-events'
sas_name = 'ib-axa-claim-indexing-policy'
sas_value = 'InZuTM2QnBIEtRspUDSAPu6iGNFtMKtDT46PKbrB8Hk='

sas_token = get_auth_token(sb_name, eh_name, sas_name, sas_value)
print(sas_token)

import requests
import json
MAX_RETRY_TIMEOUT = 128

def make_api_call(url, sas_token=None, data=None, method='post'):
    request_interval = 1
    headers = {
        'Content-Type': 'application/atom+xml;type=entry;charset=utf-8',
        'Authorization': sas_token
    }

    action = getattr(requests, method, None)

    response = action(url, data=data, headers=headers, timeout=60, verify=False)

    while response.status_code in [500, 502, 503, 504]:
        if request_interval >= MAX_RETRY_TIMEOUT: break
        time.sleep(request_interval)
        request_interval *= 2
        response = action(url, data=data, headers=headers, timeout=60, verify=False)
  
    if response.status_code in [401, 500, 502, 503, 504]:
        raise Exception('Failed to make api call to url: {}. Status code: {}'.format(url, response.status_code))

    return response

url = f'https://{sb_name}.servicebus.windows.net/{eh_name}/messages?timeout=60&api-version=2014-01'
json_data = json.dumps({ "DeviceId":"dev-01", "Temperature":"37.0" })
res = make_api_call(url, sas_token=sas_token['token'], data=json_data)
print(res)