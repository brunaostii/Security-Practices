#!/usr/bin/env python3
"""Can be executed by:
   chmod +x dissector.py
   ./dissector -r package.pcap
"""
import sys

def main(archive):
    pass



if __name__ == "__main__":
    param = sys.argv[1:]
    
    if len(param):
        if param[0] == '-r':
            archive = param[1]
            main(archive)

        elif param[0] == '--help':
            print('-r package.pcap')
            sys.exit(0)

    else:
        print("Should read as argument a file in pcap format but none was given!")
        sys.exit(0)