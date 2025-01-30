# import fuzzer
from scapy.all import *
from scapy.contrib import *
from scapy.layers.all import *
import random as rd
# import gen
def make_pcap():
    packet1 = Ether()/IP(dst='8.8.8.8')/TCP(dport=53, flags='S')
    packet2 = IP(dst='192.168.49.129', version=4)/ICMP()
    packet3 = IP(dst='23.23.23.23') / ICMP()/DNS()
    packet4 = Ether()/IP(dst='8.8.8.8')/UDP(dport=63)
    wrpcap("banana.pcap", [packet1, packet2, packet3, packet4])

def make_pcap_real():
    #real TCP
    packet1 = Ether(dst='d8:c0:a6:3e:e2:03', src='2a:6d:e8:4c:ab:b1', type=2048)/IP(version=4, ihl=5, tos=80, len=52, id=4167, flags=0, frag=0, ttl=121, proto=6, chksum=1683, src='74.125.131.19', dst='192.168.156.97')/TCP(sport=443, dport=56743, seq=813148372, ack=2785799992, dataofs=8, reserved=0, flags=16, window=3603, chksum=37151, urgptr=0, options=[('NOP', None), ('NOP', None), ('SAck', (2785805057, 2785809123))])
    #real UDP
    packet2 = Ether(dst='d8:c0:a6:3e:e2:03', src='2a:6d:e8:4c:ab:b1', type=2048)/IP(version=4, ihl=5, tos=80, len=60, id=0, flags=2, frag=0, ttl=58, proto=17, chksum=22838, src='173.194.220.94', dst='192.168.156.97')/UDP(sport=443, dport=54033, len=40, chksum=27100)/Raw(load=b'@0k\x99\xeb")\x91\x9b\x0c\xe9i(\x93[:\xef\x80\x9fB\xeeE\x13\x8azP\x14e\t\xbb\xe8\x03')
    #real ICMP
    packet3 = Ether(dst='d8:c0:a6:3e:e2:03', src='2a:6d:e8:4c:ab:b1', type=2048)/IP(version=4, ihl=5, tos=80, len=60, id=0, flags=0, frag=0, ttl=107, proto=1, chksum=57943, src='8.8.8.8', dst='192.168.156.97')/ICMP(type=0, code=0, chksum=21846, id=1, seq=5, unused=b'')/Raw(load=b'abcdefghijklmnopqrstuvwabcdefghi')
    packet4 = Ether()/IP()/UDP()/DNS(qd=DNSQR(qname="example.com"))
    wrpcap("corpus.pcap", [packet1, packet2, packet3, packet4])

def read_real():
    pckts = rdpcap("real.pcapng")
    for i in range(0,10):
        print(pckts[i].command(), "\n")


if __name__ == '__main__':
    make_pcap_real()