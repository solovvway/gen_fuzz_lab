from netfilterqueue import NetfilterQueue
from scapy.all import *
def set_nfqueue():
    os.system('sysctl net.ipv4.ip_forward=1')
    os.system('iptables -A OUTPUT -j NFQUEUE --queue-num 1')

# def unset_nfqueue():
#     os.system('sysctl net.ipv4.ip_forward=0')
#     os.system('iptables -F')
#     os.system('iptables -X')
#     os.system('iptables -A OUTPUT -j DROP')
def callback(payload):
    # Here is where the magic happens.
    data = payload.get_payload()
    pkt = IP(data)
    print(pkt.summary())
    payload.set_payload(bytes(pkt))
# This is the intercept
set_nfqueue()
nfqueue = NetfilterQueue()
nfqueue.bind(1, callback)
s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
try:
    nfqueue.run_socket(s)
except KeyboardInterrupt:
    print('')
s.close()
nfqueue.unbind()