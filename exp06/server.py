import SocketServer
import hashlib

FILE_HASH = None
HOST = 'localhost'
PORT = 9999
READ_MAX_LEN = 1024


class FileChecker(SocketServer.BaseRequestHandler):

    def handle(self):
        # self.request is the TCP socket connected to the client
        payload_size = int(self.request.recv(8).strip())
        print('Receiving data: {} bytes...'.format(payload_size))
        payload = ''
        while payload_size > 0:
            bytes_read = self.request.recv(READ_MAX_LEN)
            if bytes_read is not None:
                payload += bytes_read
            payload_size -= len(bytes_read)
            # print('Read {} bytes. Remaining: {}'.format(read_len, payload_size))
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
