#!/usr/bin/env python
"""
Computer Security - 2020s1
EXP03

zipcracker.py: a small program for gathering words of text file (dictionary) obtained in the last
experiment(exp02) and do a brute force attack to a zip file.


Students:
    Bruna Almeida Osti, RA 231024
    Rafael Cortez Sanchez, RA 094324
"""

import argparse
import os
import subprocess
import sys
from multiprocessing import Process, Lock, Manager

# Number of workers for parallel processing. Should be adjusted to take advantage of all
# processor cores available in the running machine
NUMBER_OF_WORKERS = 4
# How many password guesses are read from the dictionary file every time a worker
# subprocess pulls from it. Since those guesses are kept in memory, this constant can be
# set to small numbers when there are memory restrictions in the running machine
ENTRIES_PER_PULL = 1000
DEVNULL = open('/dev/null', 'w')


class BruteForceQueue:
    def __init__(self, file, password):
        self.lock = Lock()
        self.file = file
        self.password = password

    def get(self, quantity):
        passwords = []
        self.lock.acquire()
        for _ in range(quantity):
            passwd = self.file.readline().strip()
            if len(passwd) > 0:
                passwords.append(passwd)
            else:
                break
        self.lock.release()
        return passwords

    def was_found(self):
        return self.password.get() is not None

    def set_password(self, password):
        self.password.set(password)


def try_break(passwd, zipfile):
    try:
        subprocess.check_call(['unzip', '-o', '-q', '-P', passwd, '-d', '/tmp', zipfile], stderr=DEVNULL)
    except subprocess.CalledProcessError:
        return False
    return True


def brute_force(queue, zipfile):
    passwords = queue.get(ENTRIES_PER_PULL)
    while len(passwords) > 0 and not queue.was_found():
        for passwd in passwords:
            if try_break(passwd, zipfile):
                queue.set_password(passwd)
        passwords = queue.get(ENTRIES_PER_PULL)


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', metavar='zipfile', help='ZIP file path', required=True)
    parser.add_argument('-l', metavar='dictionary', help='Dictionary file path', required=True)
    parsed = parser.parse_args(argv[1:])
    dict_file = open(vars(parsed)['l'], 'r')
    queue = BruteForceQueue(dict_file, Manager().Value(str, None))
    zipfile = os.path.abspath(vars(parsed)['f'])
    if not os.path.isfile(zipfile):
        print('Zip file not found in provided path')
        exit(1)

    workers = []
    for _ in range(NUMBER_OF_WORKERS):
        new = Process(target=brute_force, args=(queue, zipfile))
        workers.append(new)
        new.start()
    for worker in workers:
        worker.join()

    dict_file.close()
    DEVNULL.close()
    if queue.was_found():
        print("The password is {}".format(queue.password.value))
        exit(0)
    else:
        exit(1)


if __name__ == '__main__':
    main(sys.argv)
