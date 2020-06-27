import socket
from time import sleep

HOST = 'localhost'
PORT = 9999
SLEEP_TIME = 2
CONNECTION_TIMEOUT = 2


def main():
    with open('so_tags.csv', 'r') as fp:
        bytes_to_send = fp.read()
    print(bytes_to_send)
    while True:
        sock = socket.create_connection((HOST, PORT), timeout=CONNECTION_TIMEOUT)
        message = '{:8d}'.format(len(bytes_to_send))
        message += bytes_to_send
        sock.send(message)
        response = sock.recv(1024)
        if response == 'FILE_RECEIVED':
            print('File sent!')
        sock.close()
        sleep(SLEEP_TIME)


if __name__ == '__main__':
    main()
