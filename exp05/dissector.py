#!/usr/bin/env python3
"""Can be executed by:
   chmod +x dissector.py
   ./dissector -r package.pcap

   Help messages:
   ./dissector --help
"""

import sys, os
import argparse
from scapy.all import *


def main(archive):
    print('Opening {}...'.format(file_name))
    
   

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-r', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()
    file_name = args.r
    
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)
    
    main(file_name)
    sys.exit(0)