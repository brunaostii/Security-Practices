#!/usr/bin/env python3
"""
HTTP Dissector
Students:   Bruna Almeida Osti
            Rafael Cortez Sanchez
#################################
Usage:
   chmod +x dissector.py
   ./dissector -r package.pcap
   Help messages:
   ./dissector --help
#################################

   Esse programa extrai conteudo de mensagens HTTP contidas em um arquivo PCAP.
   Um diretorio de nome ''extracted'' eh criado no caminho de execucao do script
   e os arquivos extraidos a partir das mensagens sao armazenados nesse diretorio.

   Alem disso, o script cria um arquivo ''manifest.json'' com informacoes sobre
   toodo conteudo extraido das mensagens HTTP: uma entrada para cada um dos
   arquivos em ''extracted''.

   Esse script depende da biblioteca Scapy, a qual pode ser instalado facilmente
   via pip:

   $pip install scapy
"""

import argparse
import json
import os
import re
import sys
import zlib

from scapy.all import rdpcap
from scapy.layers.http import HTTP, TCP

MANIFEST_FILE = 'manifest.json'
EXTRACTED_FILES_DIR = 'extracted'


def update_manifest(payload_type, http_headers):
    if not os.path.isdir(EXTRACTED_FILES_DIR):
        os.mkdir(EXTRACTED_FILES_DIR)
    if not os.path.isfile(MANIFEST_FILE):
        with open(MANIFEST_FILE, 'w') as fp:
            fp.write('{}')
    with open(MANIFEST_FILE, 'r') as fp:
        manifest = json.load(fp)
    file_count = len(manifest)
    filename = '{}.{}'.format(file_count, payload_type)
    manifest[filename] = http_headers
    with open(MANIFEST_FILE, 'w') as fp:
        json.dump(manifest, fp, indent=4, sort_keys=True)
    return '{}/{}'.format(EXTRACTED_FILES_DIR, filename)


def extract_payload(http_headers, payload):
    payload_type = http_headers["Content-Type"].split("/")[1].split(";")[0]
    if "Content-Encoding" in http_headers.keys():
        if http_headers["Content-Encoding"] == "gzip":
            content = zlib.decompress(payload, 16 + zlib.MAX_WBITS)
        elif http_headers["Content-Encoding"] == "deflate":
            content = zlib.decompress(payload)
        else:
            content = payload
    else:
        content = payload

    filepath = update_manifest(payload_type, http_headers)
    with open(filepath, "wb") as fd:
        fd.write(content)


def main(archive):
    a = rdpcap(archive)
    sessions = a.sessions()
    for session in sessions:
        http_payload = b''
        http_header_parsed = None
        for p in sessions[session]:
            if p.haslayer(HTTP):
                payload = bytes(p[TCP].payload)
                
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
                    http_payload += payload[payload.index(b"\r\n\r\n") + 4:]
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