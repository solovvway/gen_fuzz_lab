import os
import sys
import socket
from scapy.all import *
from netfilterqueue import NetfilterQueue
def expand(x):
    if x.payload:
        yield x
    while x.payload:
        x = x.payload
        yield x
def set_nfqueue():
    os.system('sysctl net.ipv4.ip_forward=1')
    os.system('iptables -A OUTPUT -j NFQUEUE --queue-num 1')

def unset_nfqueue():
    os.system('sysctl net.ipv4.ip_forward=0')
    os.system('iptables -F')
    os.system('iptables -X')
    os.system('iptables -A OUTPUT -j DROP')

def callback(payload):
    # Here is where the magic happens.
    data = payload.get_payload()
    pkt = IP(data)
    pkt.show()
    payload.set_payload(bytes(pkt))

def intercept(callback):
    set_nfqueue()
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, callback)
    s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        nfqueue.run_socket(s)
    except KeyboardInterrupt:
        print('')
    finally:
        unset_nfqueue()
    s.close()
    nfqueue.unbind()


def crossover(data1,data2):
    id_1 = random.randint(0, len(data1) - 1)
    id_2 = random.randint(0, len(data1) - 1)
    return bytes(data1[:id_1] + data2[id_2 + 1:])

def mutations(a):
    mutation_idx = random.randint(0, 6)
    if mutation_idx == 0:  # Bit flipping
        bit_idx = random.randint(0, len(a) * 8 - 1)
        byte_idx = bit_idx // 8
        bit_mask = 1 << (bit_idx % 8)
        a = bytearray(a)
        if a[byte_idx] & bit_mask:
            a[byte_idx] &= ~bit_mask
        else:
            a[byte_idx] |= bit_mask
        return bytes(a)
    elif mutation_idx == 1:  # Byte flipping
        byte_idx = random.randint(0, len(a) - 1)
        a = bytearray(a)
        a[byte_idx] = ~a[byte_idx] & 0xFF
        return bytes(a)
    elif mutation_idx == 2:  # Add/subtract values
        val = random.randint(-128, 127)
        a = [(x + val) & 0xFF for x in a]
        return bytes(a)
    elif mutation_idx == 3:  # Replace bytes with special values
        special_val = random.randint(0, 3)
        if special_val == 0:
            a = [0] * len(a)
        elif special_val == 1:
            a = [0xFF] * len(a)
        elif special_val == 2:
            a = [0xA5] * len(a)
        elif special_val == 3:
            a = [0x5A] * len(a)
        return bytes(a)
    elif mutation_idx == 4:  # Replace individual bytes with random values
        a = [random.randint(0, 255) for _ in a]
        return bytes(a)
    elif mutation_idx == 5:  # Delete blocks of bytes
        block_size = random.randint(1, len(a) // 2)
        return bytes(a[block_size:])
    elif mutation_idx == 6:  # Replace blocks of bytes
        block_size = random.randint(1, len(a) // 2)
        return bytes([random.randint(0, 255) for _ in range(block_size)] + list(a)[block_size:])
    
def raw_mutations(pkt):
    data = raw(pkt)
    # print(f'Original data: {data=}')
    mutated_data = mutations(data)
    # print(f'Mutated data: {mutated_data=}')
    return Ether(mutated_data)

def scapy_def_rand(pkt):
    return fuzz(pkt)

def scapy_fix_rand(p, _inplace=0):

    if not _inplace:
        p = p.copy()
    q = p
    while not isinstance(q, NoPayload):
        for f in q.fields_desc:
            if isinstance(f, PacketListField):
                for r in getattr(q, f.name):
                    fuzz(r, _inplace=1)
            elif isinstance(f, MultipleTypeField):
                # the type of the field will depend on others
                rnd = f.randval()
                if rnd is not None:
                    setattr(q, f.name, rnd)
            elif f.default is not None:
                if not isinstance(f, ConditionalField) or f._evalcond(q):
                    rnd = f.randval()
                    if rnd is not None:
                        setattr(q, f.name, rnd)
        q = q.payload
    return p

def layer_crossover(packet1, packet2):
    n = random.randint(1, len(packet1.layers())-1)
    # print(packet1[n],'\n',packet2[n])
    packet1[n] = packet2[n]
    return packet1

def layer_crossover_mutation(packet1,packet2):
    global layer_crossover,mutations
    print(f'Original data: {packet1=} {packet2=}')
    data = layer_crossover(packet2,packet2)
    mutated_data = mutations(raw(data))
    print(f'Mutated data: {Ether(mutated_data)=}')
    return Ether(mutated_data)

if __name__ == "__main__":
    pass
    # main()