"""
MO639 Computer Security
Experiment 6
Students: Bruna Almeida Osti
          Rafael Cortez Sanches

==================
Client Application
==================

This side is responsible for sending files to the server through a TCP connection. Files are sent in
chunks of bytes, their size is defined in the CHUNK_SIZE constant.

More information about this simple file transferring protocol is in server.py
"""
import socket
from time import sleep

HOST = 'localhost'
PORT = 9999
SLEEP_TIME = 2
CONNECTION_TIMEOUT = 5
CHUNK_SIZE = 1024
REAL_FILE = 'mensagem.txt'


def send_chunk(sock, chunk):
    message = '{:8d}'.format(len(chunk))
    message += chunk
    sock.send(message)
    response = sock.recv(1024)
    return response == 'CHUNKRCV'


def send_end_of_file(sock):
    sock.send('#####EOF')
    response = sock.recv(1024)
    return response == 'EOF#####'


def main():
    with open(REAL_FILE, 'r') as fp:
        bytes_to_send = fp.read()
    error_found = False
    file_size = len(bytes_to_send)
    sock = socket.create_connection((HOST, PORT), timeout=CONNECTION_TIMEOUT)
    while not error_found:
        cursor = 0
        while cursor < file_size:
            remaining_bytes = file_size - cursor
            next_chunk_size = min(CHUNK_SIZE, remaining_bytes)
            if not send_chunk(sock, bytes_to_send[cursor: cursor + next_chunk_size]):
                print('ERROR SENDING CHUNK')
                error_found = True
                break
            cursor += next_chunk_size
        if not error_found and not send_end_of_file(sock):
            print('ERROR ENDING TRANSFER')
            error_found = True
        sleep(SLEEP_TIME)
    sock.close()


if __name__ == '__main__':
    main()
