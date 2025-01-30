import sys
import random
from scapy.all import *
from structures import *
# обязательные переменные
network = "192.168.1.0/24"



# dump = sniff(filter=f'net {network}', count=52)
# dump = [Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/UDP()/DNS(), 
#         Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/UDP()/DNS()]
dump = [Ether()/IP(dst='127.0.0.1')]
# класс объекта популяции
# объект популяции состоит из адресов источника и назначения и состава заголовков. Если они одинаковые, считаем пакет тем же 


uniq_dump = []

# генерируем уникальном множество пакетов
for i in dump:
    # .get() в scapy не работает
    ip_src = getattr(i.__getitem__('IP'), 'src', None) class Sender:
    def __init__(self, iface='eth0'):
        self.iface = iface

    def send_packet(self, packet):
        # Print the packet before sending
        print("PACKET BEFORE SENDING:", packet.command())

        # Remove checksum for IP packets
        if IP in packet:
            del packet[IP].chksum  # Remove checksum to recalculate

        # Measure response time
        start_time = time.time()
        response = sendp(packet, iface=self.iface, verbose=0) if Ether in packet else send(packet, iface=self.iface, verbose=0)
        end_time = time.time()

        # Measure RTT
        if response:
            rtt = (end_time - start_time) * 1000  # Convert to milliseconds
            print(f"Packet sent: {packet.summary()}, RTT: {rtt:.2f} ms")
        else:
            print(f"Packet sent: {packet.summary()}, No response")

    ip_dst = getattr(i.__getitem__('IP'), 'dst', None)

    mac_src = getattr(i.__getitem__('Ether'), 'src', None) 
    mac_dst = getattr(i.__getitem__('Ether'), 'dst', None)

    layers = i.layers()

    unit_instance = Unit(ip_src=ip_src, ip_dst=ip_dst, mac_src=mac_src, mac_dst=mac_dst, layers=layers, pdu=i)

    # unit_instance.show()

    if unit_instance not in uniq_dump:
        uniq_dump.append(unit_instance)
    # else:
        # print("Ununiq")

# Инициализировать популяцию
population = Population()
for i in uniq_dump:
    population.add(i,1)
print(population.show())

a,b = population.choice_two()
mutator = Mutator()
pkt_after_fuzz = mutator.gen_fuzz(a,b)
print(pkt_after_fuzz.command())

sender = Sender(iface="lo")
sender.send_packet(pkt_after_fuzz)