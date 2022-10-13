import base64
import datetime
import hmac
import urllib.parse
import uuid

import requests
from flask import Flask, request, abort, Response

app = Flask(__name__)

API = 'https://alidns.aliyuncs.com/'


class Signature:
    @staticmethod
    def get(query_list, sk):
        if not sk:
            return bytes()
        string_to_sign = urllib.parse.quote('GET&/&', safe='&') + urllib.parse.quote(urllib.parse.urlencode(
            sorted(query_list))).replace("+", "%20").replace("*", "%2A").replace("%7E", "~")
        return base64.b64encode(
            hmac.new((sk + '&').encode('utf8'), string_to_sign.encode('utf8'), 'sha1').digest()
        )

    @staticmethod
    def parameters():
        return {
            'SignatureMethod': 'HMAC-SHA1',
            'SignatureNonce': str(uuid.uuid4()).replace('-', ''),
            'SignatureVersion': 1.0
        }


def get_domain_url(action, ak, sk, host_record='@', record_type='A', line='default', ttl=600, **kwargs):
    params = {
        'Format': 'JSON',
        'Version': '2015-01-09',
        'AccessKeyId': ak,
        'Timestamp': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        **Signature.parameters(),
        'Action': action,
        'Type': record_type,
    }
    if action == 'DescribeDomainRecords':
        params['DomainName'] = kwargs['domain']
        params['RRKeyWord'] = host_record
    elif action == 'UpdateDomainRecord':
        params.update({
            'RR': host_record,
            'RecordId': kwargs['record_id'],
            'Value': kwargs['value'],
            'Line': line,
            'TTL': ttl,
        })
    elif action == 'AddDomainRecord':
        params.update({
            'DomainName': kwargs['domain'],
            'RR': host_record,
            'Value': kwargs['value'],
            'Line': line,
            'TTL': ttl,
        })
    else:
        raise ValueError("unknown action")
    param_list = list(params.items())
    param_list.append(('Signature', Signature.get(param_list, sk).decode('utf8')))
    return API + '?' + urllib.parse.urlencode(param_list)


def update_domain_record(*args, **kwargs):
    domain_info = requests.get(get_domain_url('DescribeDomainRecords', *args, **kwargs))
    if domain_info.status_code != 200:
        return domain_info.content, domain_info.status_code
    records = domain_info.json().get('DomainRecords', {}).get('Record', [])
    if records:
        rid, rval = records[0]['RecordId'], records[0]['Value']
        if rval == kwargs['value']:
            return
        update_url = get_domain_url('UpdateDomainRecord', *args, record_id=rid, **kwargs)
    else:
        update_url = get_domain_url('AddDomainRecord', *args, **kwargs)
    resp = requests.get(update_url)
    return resp.content, resp.status_code


@app.route('/', methods=['GET'])
def update():
    ak, sk, domain, value = request.args.get('ak'), request.args.get('sk'), request.args.get('domain'), request.args.get('value')
    if not all([ak, sk, domain, value]):
        abort(400)
    z = domain.rsplit('.', 2)
    if len(z) == 3:
        rr, name = z[0], '.'.join(z[1:])
    else:
        rr, name = '@', '.'.join(z)
    resp, code = update_domain_record(
        ak, sk, domain=name, value=value,
        host_record=rr, record_type=request.args.get('type', 'A'),
    )
    return Response(resp, status=code, mimetype='application/json')


def handler(environ, start_response):
    return app(environ, start_response)


if __name__ == '__main__':
    app.run()
