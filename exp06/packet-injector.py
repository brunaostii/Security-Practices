"""
TCP packet injector
NOTE: Requires SUPERUSER privileges to run
"""
# !/usr/bin/env python3
from scapy.layers.inet import TCP, IP
from scapy.all import sr1


def main():
    bad_ip_packet = IP(dst='192.168.104.100', src='192.168.104.143')
    bad_tcp_packet = TCP(dport=9999, sport=42992)
    encapsulated = bad_ip_packet / bad_tcp_packet / "AM_I_EVIL_YES_I_AM"
    if sr1(encapsulated) is not None:
        print('Injected!')


if __name__ == '__main__':
    main()
