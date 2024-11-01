# Import necessary modules
import socket  # for working with sockets
import struct  # for packing and unpacking data
from ctypes import *  # for working with C data types

# Define a class to represent an IP header
class IP(Structure):
    # Define the fields of the IP header
    _fields_ = [
        ("ihl", c_ubyte, 4),  # Internet Header Length (4 bits)
        ("version", c_ubyte, 4),  # IP version (4 bits)
        ("tos", c_ubyte),  # Type of Service
        ("len", c_ushort),  # Total length of the IP packet
        ("id", c_ushort),  # Identification number of the packet
        ("offset", c_ushort),  # Fragment offset
        ("ttl", c_ubyte),  # Time To Live
        ("protocol_num", c_ubyte),  # Protocol number
        ("sum", c_ushort),  # Checksum
        ("src", c_uint32),  # Source IP address
        ("dst", c_uint32)  # Destination IP address
    ]

    # Create a new IP object from a socket buffer
    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)

    # Initialize the IP object
    def __init__(self, socket_buffer=None):
        self.socket_buffer = socket_buffer

        # Map protocol constants to their names
        self.protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            41: "IPv6",
            58: "ICMPv6",
            76: "IPv6-ICMP"
        }

        # Convert IP addresses to human-readable format
        self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))

        # Convert protocol number to human-readable format
        try:
            self.protocol = self.protocol_map.get(self.protocol_num, "Unknown protocol ({})".format(self.protocol_num))
        except IndexError:
            self.protocol = str(self.protocol_num)

# Create a raw socket to capture packets
rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

try:
    while True:
        # Read in a single packet
        raw_buffer = rawSocket.recvfrom(65535)[0]
        print(raw_buffer)

        # Create an IP header from the first 20 bytes of the buffer
        ip_header = IP(raw_buffer[:20])

        # Print the protocol, source IP address, and destination IP address
        print("Protocol: %s %s -> %s" % (
            ip_header.protocol,
            ip_header.src_address,
            ip_header.dst_address
        ))
        print('\n')
except KeyboardInterrupt:
    pass  # exit the loop when Ctrl+C is pressed