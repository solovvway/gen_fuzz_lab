from scapy.all import *
import random
def expand(x):
    if x.payload:
        yield x
    while x.payload:
        x = x.payload
        yield x
def crossover(data1,data2):
    id_1 = random.randint(0, len(data1) - 1)
    id_2 = random.randint(0, len(data1) - 1)
    return bytes(data1[:id_1] + data2[id_2 + 1:])

def mutations(a):
    mutation_idx = random.randint(0, 7)
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
    elif mutation_idx == 7:
        return a
    
def raw_mutations(pkt_1,pkt_2):
    global crossover,mutations
    data1 = raw(pkt_1)
    data2 = raw(pkt_2)
    print(f'Original data: {data1=} {data2=}')
    data = crossover(data1,data2)
    mutated_data = mutations(data)
    print(f'Mutated data: {mutated_data=}')
    return Ether(mutated_data)


# def layer_crossover(packet1, packet2):
#     n = random.randint(1, len(packet1.layers()))
#     layers1 = [i.name for i in expand(packet1)]
#     layers2 = [i.name for i in expand(packet2)]
#     packet1[layers1[n]] = packet2[layers2[n]]
#     return packet1
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

if __name__ == '__main__':
    pkt_1 = Ether(dst='ff:aa:ff:aa:ff:aa')/IP(dst='127.0.0.1')/TCP()
    pkt_2 = Ether()/IP(dst='182.168.0.1')/UDP()/DNS()
    population = [pkt_1,pkt_2]
    # pkt1 = layer_crossover_mutation(pkt_1,pkt_2)
    pkt1 = raw_mutations(pkt_1,pkt_2)
    try:
        pkt1.show()
    except:
        print('malformed packet')