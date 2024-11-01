import random
from scapy.all import *

def get_field_bytes(pkt, name):
    fld, val = pkt.getfield_and_val(name)
    return bytes(fld.i2m(pkt, val))

pkt = Ether()/IP()/TCP()

# Get a list of fields in the packet
print(pkt.layers())
for layer in pkt.layers():
    fields = layer.fields_desc
    field_idx = random.randint(0, len(fields) - 1)
    selected_field = fields[field_idx]

    try:
        a = list(get_field_bytes(pkt.getlayer(layer), selected_field.name))
        print(a)
        mutation_idx = random.randint(0, 7)
        if mutation_idx == 0:  # Bit flipping
            bit_idx = random.randint(0, len(a) * 8 - 1)
            a[bit_idx // 8] ^= 1 << (bit_idx % 8)
        elif mutation_idx == 1:  # Byte flipping
            byte_idx = random.randint(0, len(a) - 1)
            a[byte_idx] = ~a[byte_idx] & 0xFF
        elif mutation_idx == 2:  # Add/subtract values
            val = random.randint(-128, 127)
            a = [(x + val) & 0xFF for x in a]
        elif mutation_idx == 3:  # Replace bytes with special values
            special_val = random.choice([0x00, 0xFF, 0xA5, 0x5A])
            a = [special_val] * len(a)
        elif mutation_idx == 4:  # Replace individual bytes with random values
            a = [random.randint(0, 255) for _ in a]
        elif mutation_idx == 5:  # Delete blocks of bytes
            block_size = random.randint(1, len(a) // 2)
            del a[:block_size]
        elif mutation_idx == 6:  # Replace blocks of bytes
            block_size = random.randint(1, len(a) // 2)
            a[:block_size] = [random.randint(0, 255) for _ in range(block_size)]
        elif mutation_idx == 7:  # Splicing
            splice_idx = random.randint(0, len(a) - 1)
            a = a[:splice_idx] + a[splice_idx + 1:]
        print(a)
        setattr(pkt, selected_field.name, bytes(a))
        pkt.show()
    except:
        pass
