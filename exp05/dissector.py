#!/usr/bin/env python3
"""Can be executed by:
   chmod +x dissector.py
   ./dissector -r package.pcap

   Help messages:
   ./dissector --help
"""

import argparse
import json
import os
import re
import sys
import uuid
import zlib

from scapy.all import rdpcap
from scapy.layers.http import HTTP, TCP

MANIFEST_FILE = 'manifest.json'


def update_manifest(filename, http_headers):

    if not os.path.isfile(MANIFEST_FILE):
        with open(MANIFEST_FILE, 'w') as fp:
            fp.write('{}')
    
    with open(MANIFEST_FILE, 'r') as fp:
        manifest = json.load(fp)
    manifest[filename] = http_headers
    
    with open(MANIFEST_FILE, 'w') as fp:
        json.dump(manifest, fp, indent=4)


def extract_payload(http_headers, payload):
    payload_type = http_headers["Content-Type"].split("/")[1].split(";")[0]
    content = None
    try:
        if "Content-Encoding" in http_headers.keys():
            if http_headers["Content-Encoding"] == "gzip":
                content = zlib.decompress(payload, 16 + zlib.MAX_WBITS)
            elif http_headers["Content-Encoding"] == "deflate":
                content = zlib.decompress(payload)
            else:
                content = payload
        else:
            content = payload
    except:
        pass

    filename = uuid.uuid4().hex + "." + payload_type
    fd = open(filename, "wb")
    fd.write(content)
    fd.close()
    update_manifest(filename, http_headers)


def main(archive):
    a = rdpcap(archive)
    sessions = a.sessions()

    for session in sessions:
        http_payload = b''
        http_header_parsed = None
        print('#### START SESSION ####')
        
        for p in sessions[session]:
            if p.haslayer(HTTP):
                payload = bytes(p[TCP].payload)
                print('#### START PAYLOAD ####')
                print(payload)
                print('#### END PAYLOAD ####')
                try:
                    http_header = payload[payload.index(b"HTTP/1."):payload.index(b"\r\n\r\n") + 2]
                except ValueError:
                    http_header = None
                if http_header is None:
                    http_payload += payload
                else:
                    http_header_raw = payload[:payload.index(b"\r\n\r\n") + 2]
                    if len(http_payload) > 0 and http_header_parsed is not None:
                        extract_payload(http_header_parsed, http_payload)
                        http_payload = b''
                    http_header_parsed = dict(
                        re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", http_header_raw.decode("utf8")))
                    if 'Server' not in http_header_parsed:  # is NOT an HTTP response
                        http_header_parsed = None
                        break
                    http_payload += payload[payload.index(b"\r\n\r\n") + 4:]
        
        print('#### END SESSION ####')
        if len(http_payload) > 0 and http_header_parsed is not None:
            extract_payload(http_header_parsed, http_payload)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-r', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()
    file_name = args.r

    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name))
        sys.exit(-1)

    main(file_name)
    sys.exit(0)
