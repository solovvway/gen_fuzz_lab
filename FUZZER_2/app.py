import sys
from numpy.random import choice,randint
from scapy.all import *
from structures import *
# обязательные переменные
network = "192.168.1.0/24"



# dump = sniff(filter=f'net {network}', count=52)
# dump = [Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/UDP()/DNS(), 
#         Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/UDP()/DNS()]
dump = [Ether()/IP(dst='127.0.0.1'),Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/UDP()/DNS()]
# класс объекта популяции
# объект популяции состоит из адресов источника и назначения и состава заголовков. Если они одинаковые, считаем пакет тем же 


uniq_dump = []

# генерируем уникальном множество пакетов
for i in dump:
    # .get() в scapy не работает
    ip_src = getattr(i.__getitem__('IP'), 'src', None)
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
print(a,b)
pkt_after_fuzz = mutator.gen_fuzz(a,b)
print(pkt_after_fuzz.command())

sender = Sender(iface="lo")
sender.send_packet(pkt_after_fuzz)