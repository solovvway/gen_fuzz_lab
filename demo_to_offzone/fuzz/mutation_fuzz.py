from scapy.all import *
import random

def get_field_bytes(pkt, name):
    fld, val = pkt.getfield_and_val(name)
    return bytes(fld.i2m(pkt, val))

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


# def mutate_in_every_layer(pkt):
#     global mutations
# #перебираем протокольные уровни
#     for layer in pkt.layers():
#         #перебираем поля в протоколе
#         fields = layer.fields_desc
#         field_idx = random.randint(0, len(fields) - 1)
        
#         while True:
#             try:
#                 selected_field = fields[field_idx]
#                 byte_value = list(get_field_bytes(pkt.getlayer(layer), selected_field.name))
#                 # print(byte_value)
#                 byte_value = mutations(byte_value)
#                 print(byte_value)
#                 setattr(pkt, selected_field.name, bytes(byte_value))
#                 print(selected_field.name)
#                 break
#             except:
#                 if field_idx <len(fields) - 1:
#                     field_idx+=1
#                 else:
#                     break

#     return pkt

# def mutate_random_field(pkt):
#     global mutations
#     #случано выбираем уровень
#     layer=random.choice(pkt.layers())
#     #случайно выбираем поле
#     fields = layer.fields_desc
#     field_idx = random.randint(0, len(fields) - 1)
#     while True:
#         try:
#             selected_field = fields[field_idx]
#             byte_value = list(get_field_bytes(pkt.getlayer(layer), selected_field.name))
#             # print(byte_value)
#             byte_value = mutations(byte_value)
#             print(byte_value, ''.join(byte_value))
#             setattr(pkt, selected_field.name, bytes(byte_value))
#             print(selected_field.name)
#             break
#         except:
#             if field_idx <len(fields) - 1:
#                 field_idx+=1
#             else:
#                 break
#     return pkt

def raw_mutations(pkt):
    data = raw(pkt)
    print(f'Original data: {data=}')
    mutated_data = mutations(data)
    print(f'Mutated data: {mutated_data=}')
    return Ether(mutated_data)

if __name__ == '__main__':
    pkt = Ether()/IP()/TCP(sport=80)
    # print('scapy_def_rand')
    pkt1 = scapy_def_rand(pkt)
    # print('scapy_fix_rand')
    # pkt1 = scapy_fix_rand(pkt)

    # pkt1 = raw_mutations(pkt)
    try:
        pkt1.show()
    except:
        print('malformed packet')