import random
from scapy.all import *
# def get_raw_field_bytes(pkt, layer, selected_field):
#     # get the correct field object
#     field_obj = getattr(pkt.getlayer(layer), selected_field.name)
#     print(field_obj)
#     # get the length of the field
#     field_len = len(field_obj)
#     # create a bytearray to store the raw bytes
#     raw_bytes = bytearray(field_len)
#     # iterate over the field bytes and get their raw values
#     for i in range(field_len):
#         raw_bytes[i] = ByteField.getfield_v(pkt.getlayer(layer), selected_field.name, i, True)
#     return raw_bytes
# Create a packet
pkt = Ether()/IP()/TCP()

# Get a list of fields in the packet
print(pkt.layers())
for layer in pkt.layers():
    fields = layer.fields_desc
    print(fields)
    # Randomly select a field
    field_idx = random.randint(0, len(fields) - 1)
    selected_field = fields[field_idx]
    print(selected_field)
    random_value = RandField()
    setattr(layer, selected_field.name, random_value)
    print(getattr(pkt.getlayer(layer),selected_field.name))
    # if selected_field.type == types.IPAddrField:
    #     # Change IP address field to a random IP address
    #     pkt.getlayer(layer.__class__).fields[selected_field.name] = RandIP()
    # elif selected_field.type == types.IntField:
    #     # Change integer field to a random integer
    #     pkt.getlayer(layer.__class__).fields[selected_field.name] = random.randint(0, 0xFFFFFFFF)
    # elif selected_field.type == types.ShortField:
    #     # Change short integer field to a random short integer
    #     pkt.getlayer(layer.__class__).fields[selected_field.name] = random.randint(0, 0xFFFF)
    # elif selected_field.type == types.ByteField:
    #     # Change byte field to a random byte
    #     pkt.getlayer(layer.__class__).fields[selected_field.name] = random.randint(0, 0xFF)
    # elif selected_field.type == types.FlagField:
    #     # Change flag field to a random flag
    #     pkt.getlayer(layer.__class__).fields[selected_field.name] = random.choice([0, 1])
    # elif selected_field.type == types.MACAddrField:
    #     # Change MAC address field to a random MAC address
    #     pkt.getlayer(layer.__class__).fields[selected_field.name] = RandMAC()
    # else:
    #     # Change other types of fields (e.g. string, etc.) to a random value
    #     pkt.getlayer(layer.__class__).fields[selected_field.name] = RandString()

    # # Display the modified packet
    # pkt.show()

    # print(Field.getfield(selected_field,selected_field,raw(pkt)))
    # field_value = pkt.getfieldval(selected_field.name)
    # print(f'{field_value=}')


    
    # Convert the field value to bytes
    # if field_value is not None:
    #     field_bytes = bytearray([field_value]) if isinstance(field_value, int) else bytes(field_value)
    #     print(field_bytes)
    # a = bytearray(str(getattr(pkt.getlayer(layer),selected_field.name)).encode())

    # Get the value of the selected field as bytes
    # a = bytearray(pkt.getlayer(layer).raw_packet_cache[selected_field.i2m[pkt.getlayer(layer)])[selected_field.i2len//8:selected_field.i2len//8 + selected_field.i2len//8]    # a = bytearray(getattr(pkt, selected_field.name))
    # a = get_raw_field_bytes(pkt, layer, selected_field)
    # a = Field.getfield(pkt,layer,selected_field)
    # print(a)

    # # Randomly select a fuzzing mutation
    # mutation_idx = random.randint(0, 7)
    # if mutation_idx == 0:  # Bit flipping
    #     bit_idx = random.randint(0, len(a) * 8 - 1)
    #     a[bit_idx // 8] ^= 1 << (bit_idx % 8)
    # elif mutation_idx == 1:  # Byte flipping
    #     byte_idx = random.randint(0, len(a) - 1)
    #     a[byte_idx] = ~a[byte_idx] & 0xFF
    # elif mutation_idx == 2:  # Add/subtract values
    #     val = random.randint(-128, 127)
    #     a = [(x + val) & 0xFF for x in a]
    # elif mutation_idx == 3:  # Replace bytes with special values
    #     special_val = random.choice([0x00, 0xFF, 0xA5, 0x5A])
    #     a = [special_val] * len(a)
    # elif mutation_idx == 4:  # Replace individual bytes with random values
    #     a = [random.randint(0, 255) for _ in a]
    # elif mutation_idx == 5:  # Delete blocks of bytes
    #     block_size = random.randint(1, len(a) // 2)
    #     del a[:block_size]
    # elif mutation_idx == 6:  # Replace blocks of bytes
    #     block_size = random.randint(1, len(a) // 2)
    #     a[:block_size] = [random.randint(0, 255) for _ in range(block_size)]
    # elif mutation_idx == 7:  # Splicing
    #     splice_idx = random.randint(0, len(a) - 1)
    #     a = a[:splice_idx] + a[splice_idx + 1:]

    # # Set the fuzzed value back to the packet
    # setattr(pkt, selected_field.name, bytes(a))

    # Display the modified packet
    # pkt.show()