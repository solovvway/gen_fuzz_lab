from cli_tool.structures import *
from feedback.feedback import *
# from traffic_view.view_2 import *
import keyboard 
from scapy.all import ARP, Ether, srp

# ВВодим подсеть
network = input("Enter network:")

def get_ip_by_mac(target_mac):
    global network
    # Составляем ARP-запрос
    arp = ARP(pdst=network)  # Укажите вашу подсеть
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Отправляем пакет и получаем ответы
    result = srp(packet, timeout=3, verbose=0)[0]

    # Сопоставляем MAC-адрес с IP-адресом
    for sent, received in result:
        if received.hwsrc.lower() == target_mac.lower():
            return received.psrc
    return network.split("/")[0]



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

# время начала местирования для построения графика относительно времени начала тестирования
start_time = time.time()
feedback = Feedback()

while True:
    # mutator = Mutator()
    a,b = population.choice_two()
    # print(a,b)
    pkt_after_fuzz = mutator.gen_fuzz(a,b)
    print(pkt_after_fuzz.command())
    input("Click to send traffic")
    sender = Sender(iface="lo")
    sender.send_packet(pkt_after_fuzz)

    # обновляем популяцию для того, чтобы пересчитать веса
    # в мутированном пакете может не парситься даже IP
    if pkt_after_fuzz.haslayer('IP'):
        ip_src = getattr(pkt_after_fuzz.__getitem__('IP'), 'src', None)
        ip_dst = getattr(pkt_after_fuzz.__getitem__('IP'), 'dst', None)
    else:
        ip_src = None 
        ip_dst = None
        
    if pkt_after_fuzz.haslayer('Ether'):
        mac_src = getattr(pkt_after_fuzz.__getitem__('Ether'), 'src', None)
        mac_dst = getattr(pkt_after_fuzz.__getitem__('Ether'), 'dst', None)
    else:
        mac_src = None 
        mac_dst = None

        # Получение обратной связи в качестве ее значения используем время ответа
    if ip_dst is None and mac_dst is not None:
        # Если IP-адрес назначения не определен, но MAC-адрес назначения доступен,
        # используем ARP-запрос для получения IP-адреса
        try:
            ip_dst = get_ip_by_mac(mac_dst)
        # если даже по ARP не получил IP используй адрес из заданной подсети
        except Exception as e:
            print(f"Не удалось получить IP-адрес по MAC-адресу {mac_dst}: {e}")
            ip_dst = network.split("/")[0]


    # mac_src = getattr(pkt_after_fuzz.__getitem__('Ether'), 'src', None) 
    # mac_dst = getattr(pkt_after_fuzz.__getitem__('Ether'), 'dst', None)
    layers = pkt_after_fuzz.layers()
    unit_after_fuzz = Unit(ip_src=ip_src, ip_dst=ip_dst, mac_src=mac_src, mac_dst=mac_dst, layers=layers, pdu=i)
    
    # получение обратной связи в качестве ее значения используем время ответа
    weight = feedback.ping_feedback(ip_dst)
    # сохраняем значение чтобы построить график времени ответа в конце
    feedback.collect_ping_data(start_time=start_time, response_time=weight)
    # обновляем популяцию
    population.add(unit_after_fuzz,weight)
    # if keyboard.is_pressed('q'):
    #     print("Завершение цикла...")
    #     break  # Выход из цикла

feedback.plot_ping_data('plot_ping_data.png')
