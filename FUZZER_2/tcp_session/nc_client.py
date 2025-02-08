#!/usr/bin/env python
# The above line indicates that this is a python script.
# Author:  Ralph Bean <rbean@redhat.com>

# This line imports python objects from the scapy module
from scapy.all import sendp, TCP, IP

# Can we get scapy to talk with netcat?
# http://stackoverflow.com/questions/12062781/how-to-make-netcat-display-payload-of-packet
# Run "nc -l 9001"

# This will send one empty packet to tcp://127.0.0.1:9001
print('''sendp(TCP(dport=1234) / IP(dst="127.0.0.1"))''')

# It doesn't do a full tcp handshake, though.  We have to use SocketStream for
# that.  http://trac.secdev.org/scapy/wiki/TCP
import socket
from scapy.all import StreamSocket, Raw

s = socket.socket()
s.connect(("127.0.0.1", 1234))

ss = StreamSocket(s, Raw)
ss.sr1(Raw("Hello World"))

#  * What kind of payload is a zeromq SUB socket expecting?
#    (It's described here http://rfc.zeromq.org/spec:2 )