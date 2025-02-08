from cli_tool.structures import *
from feedback.feedback import *
# from traffic_view.view_2 import *

# ВВодим подсеть
network = input("Enter network:")

sniffer = Sniffer(iface='lo', network=network)
# print("\nАсинхронный перехват:")
input("Нажмите Enter для запуска сниффера...")  # Ожидание ввода перед запуском сниффера
async_packets = sniffer.async_sniff()  # Сниффер запускается здесь
print("Перехват запущен. Нажмите Enter для остановки...")
input()  # Ожидание ввода для остановки
# input()  # Ожидание ввода для остановки
dump = sniffer.stop_async_sniff()
# dump = sniffer.sync_sniff()

# input()
# t = AsyncSniffer(iface="lo", filter=f'net 127.0.0.1/32')
# input()
# dump = t.stop()
for pkt in dump:
    print(pkt)

# Create uniq dump
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
    if unit_instance not in uniq_dump:
        uniq_dump.append(unit_instance)

# генерируем уникальном множество протоколов
uniq_protocols = set()
for i in uniq_dump:
    for j in i.layers:
        uniq_protocols.add(j.__name__)

# тестовая версия, его нужно получать из веб-интерфейса по uniq_protocols
# proto_weights = {
#     'IP':1,
#     'TCP':2,
#     'DNS':3,
#     'Raw':228
# }

proto_weights = {}
for i in uniq_protocols:
    while True:
        try:
            weight = int(input(f'weight for proto {i}: '))
            proto_weights[i] = weight
            break
        except ValueError:
            print("Пожалуйста, введите корректное целое число.")


# make population
population = Population()
for i in uniq_dump:
    weight = proto_weights[i.pdu.lastlayer()._name]
    population.add(i,weight)
print(population.show())

# weights = {
#     'crossovers': [99, 3],  # Новые веса для методов кроссовера
#     'mutations': [99, 2, 1, 1, 2, 1, 1, 1]  # Новые веса для методов мутации
# }
mutator = Mutator()
mutator.input_weights()

while True:
    # mutator = Mutator()
    a,b = population.choice_two()
    # print(a,b)
    pkt_after_fuzz = mutator.gen_fuzz(a,b)
    print(pkt_after_fuzz.command())
    input("Click to send traffic")
    sender = Sender(iface="lo")
    sender.send_packet(pkt_after_fuzz)