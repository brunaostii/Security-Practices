import SocketServer
import hashlib

FILE_HASH = None
HOST = 'localhost'
PORT = 9999
READ_MAX_LEN = 1024


class FileChecker(SocketServer.BaseRequestHandler):

    def handle(self):
        print('Receiving data...')
        payload = ''
        while True:
            header = self.request.recv(8)
            if header == '#####EOF':
                self.request.sendall('EOF#####')
                break
            chunk_len = int(header)
            chunk_bytes = self.request.recv(chunk_len)
            if chunk_bytes is not None and chunk_len > 0:
                payload += chunk_bytes
            else:
                print('Connection error: no bytes received')
                break
            self.request.sendall('CHUNKRCV')
            # print('Received chunk:\n{}'.format(chunk_bytes))
        print('Received file!')
        self.request.sendall('FILE_RECEIVED')
        check_hash = hashlib.sha1(payload).digest()
        print('MATCHES: {}'.format(FILE_HASH == check_hash))
        print('############')


if __name__ == "__main__":
    with open('so_tags.csv', 'r') as fp:
        FILE_HASH = hashlib.sha1(fp.read()).digest()
    server = SocketServer.TCPServer((HOST, PORT), FileChecker)
    server.serve_forever()
