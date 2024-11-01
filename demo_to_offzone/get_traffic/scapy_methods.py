from scapy.all import *
import time

def handler(pkt):
    print(pkt.summary())

sniff(prn=lambda pkt: handler(pkt))

t = AsyncSniffer(prn=lambda pkt: handler(pkt))
t.start()
time.sleep(1)
print("nice weather today")
time.sleep(1)
t.stop()

bridge_and_sniff(if1='wlo1', if2='eno1', xfrm12=handler,xfrm21=handler)