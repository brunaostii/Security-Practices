import SocketServer
import hashlib

FILE_HASH = None
HOST = 'localhost'
PORT = 9999
READ_MAX_LEN = 1024


def check_file(payload):
    print('Received file!')
    check_hash = hashlib.sha1(payload).digest()
    matches = FILE_HASH == check_hash
    if not matches:
        print('FILE WAS CORRUPTED')
        with open('dump.csv', 'w') as dumpfile:
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
    with open('so_tags.csv', 'r') as fp:
        FILE_HASH = hashlib.sha1(fp.read()).digest()
    server = SocketServer.TCPServer((HOST, PORT), FileChecker)
    server.serve_forever()
