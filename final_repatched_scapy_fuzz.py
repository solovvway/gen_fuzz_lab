from scapy.all import *

# def fuzz_packet(pkt):
#     # randomly select a layer to fuzz
#     layer = choice(pkt.layers())
#     print(layer)
#     # use fuzz() to modify the layer
#     fuzzed_layer = fuzz(pkt.getlayer(layer))
#     # replace the original layer with the fuzzed layer
#     try:
#         pkt[layer] = fuzzed_layer
#     except:
#         pass
#     finally:
#         return pkt
# def fuzz_packet(pkt):
#     # randomly select a layer to fuzz
#     layer = choice(pkt.layers())
#     print(layer)
#     # mutate a specific field of the layer
#     field = choice(layer.fields_desc)
#     layer.setfieldval(field.name, RandString(field.sz))
#     return pkt
def fuzz_new_new(p,  # type: Packet
             _inplace=0,  # type: int
             ):
    # type: (...) -> Packet
    """
    Transform a layer into a fuzzy layer by replacing all field values with random objects.

    :param p: the Packet instance to fuzz
    :return: the fuzzed packet.
    """
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
def fuzz_new(p,  # type: Packet
         _inplace=0,  # type: int
         ):
    # type: (...) -> Packet
    """
    Transform a layer into a fuzzy layer by replacing some default values
    by random objects.

    :param p: the Packet instance to fuzz
    :return: the fuzzed packet.
    """
    if not _inplace:
        p = p.copy()
    q = p
    while not isinstance(q, NoPayload):
        new_default_fields = {}
        multiple_type_fields = []  # type: List[str]
        for f in q.fields_desc:
            if isinstance(f, PacketListField):
                for r in getattr(q, f.name):
                    fuzz(r, _inplace=1)
            elif isinstance(f, MultipleTypeField):
                # the type of the field will depend on others
                multiple_type_fields.append(f.name)
            elif f.default is not None:
                if not isinstance(f, ConditionalField) or f._evalcond(q):
                    rnd = f.randval()
                    if rnd is not None:
                        # new_default_fields[f.name] = rnd
                        new_default_fields[f.name] = rnd
        # Process packets with MultipleTypeFields
        if multiple_type_fields:
            # freeze the other random values
            new_default_fields = {
                key: (val._fix() if isinstance(val, VolatileValue) else val)
                for key, val in six.iteritems(new_default_fields)
            }
            q.default_fields.update(new_default_fields)
            # add the random values of the MultipleTypeFields
            for name in multiple_type_fields:
                fld = cast(MultipleTypeField, q.get_field(name))
                rnd = fld._find_fld_pkt(q).randval()
                if rnd is not None:
                    new_default_fields[name] = rnd
        print(q.packetfields)
        q.default_fields.update(new_default_fields)
        q = q.payload
    return p
def fuzz_packet(pkt):
    layer = choice(pkt.layers())
    print(layer)
    for field in layer.fields_desc:
        # if field.default is not None:
        print(field.name,  field.default)
        setattr(pkt[layer], field.name, field.default)
    return pkt
# capture a packet
pkt = sniff(count=1)[0]
# pkt = Ether()/IP()/TCP()

# fuzz the packet
fuzzed_pkt = fuzz_new_new(pkt)

# send the fuzzed packet
# send(fuzzed_pkt)
fuzzed_pkt.show()