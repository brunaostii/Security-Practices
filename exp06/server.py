"""
MO639 Computer Security
Experiment 6
Students: Bruna Almeida Osti
          Rafael Cortez Sanches

==================
Server Application
==================

The server side of this simple file transferring application receives a file through a TCP connection and checks
if this file's hash value is what it was meant to be. The real purpose of this hash checking is to find out if a
TCP injection attack was successful or not.

The protocol works as follows:

Client sends TCP packets containing the following fields:
    CHUNK_SIZE  Header, 8 bytes long (TEXT)
    CHUNK_DATA  Variable size, defined in CHUNK_SIZE

Example of message chunk:

00000010helloworld

'helloworld' string is 10 bytes long, hence the prefix '00000010'. When the server successfully receives a chunk,
it replies to the client:

CHUNKRCV

Which is 8 bytes long, just like CHUNK_SIZE. When every file chunk has been transferred, the client must send the
following message:

#####EOF

And the server replies with:

EOF#####

Both messages are also 8 bytes long. After this, the server computes the hash of the received file and prints
whether it has been tampered with or not. In case it was, it also dumps the received payload into a text file.
"""
import SocketServer
import hashlib

FILE_HASH = None
HOST = 'localhost'
PORT = 9999
READ_MAX_LEN = 1024
REAL_FILE = 'mensagem.txt'
DUMP_FILE = 'dump.txt'


def check_file(payload):
    print('Received file!')
    check_hash = hashlib.sha1(payload).digest()
    matches = FILE_HASH == check_hash
    if not matches:
        print('FILE WAS CORRUPTED')
        with open(DUMP_FILE, 'w') as dumpfile:
            dumpfile.write(payload)
    else:
        print('FILE CHECKED: NO PROBLEMS DETECTED')
    print('#########################')


class FileChecker(SocketServer.BaseRequestHandler):

    def handle(self):
        print('Receiving data from {}'.format(self.request.getpeername()))
        payload = ''
        while True:
            header = self.request.recv(8)
            if header == '#####EOF':
                self.request.sendall('EOF#####')
                check_file(payload)
                print('Receiving data from {}'.format(self.request.getpeername()))
                payload = ''
                continue
            chunk_len = int(header)
            chunk_bytes = self.request.recv(chunk_len)
            if chunk_bytes is not None and chunk_len > 0:
                payload += chunk_bytes
            else:
                print('Connection error: no bytes received')
                break
            self.request.sendall('CHUNKRCV')
            # print('Received chunk:\n{}'.format(chunk_bytes))


if __name__ == "__main__":
    with open(REAL_FILE, 'r') as fp:
        FILE_HASH = hashlib.sha1(fp.read()).digest()
    server = SocketServer.TCPServer((HOST, PORT), FileChecker)
    server.serve_forever()
