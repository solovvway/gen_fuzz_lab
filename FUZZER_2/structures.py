from scapy.all import *


class Unit:
    def __init__(self, ip_src, ip_dst, mac_src, mac_dst, layers,pdu):
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.mac_src = mac_src
        self.mac_dst = mac_dst
        self.layers = layers
        self.pdu = pdu

    def show(self):
        return f"IP Src: {self.ip_src}, \nIP Dst: {self.ip_dst},\n MAC Src: {self.mac_src},\n MAC Dst: {self.mac_dst}, \n  Layers: {self.layers}"

# переопределяем методы для того, чтобы классы поддерживали базовый синтаксис python по сравнению это служебные методы
    def __eq__(self, other):
        if isinstance(other, Unit):
            return (self.ip_src == other.ip_src and
                    self.ip_dst == other.ip_dst and
                    self.mac_src == other.mac_src and
                    self.mac_dst == other.mac_dst)
        return False

    def __hash__(self):
        return hash((self.ip_src, self.ip_dst, self.mac_src, self.mac_dst))

# популяция состоит из Unit-ов с весами
class Population:
    def __init__(self):
        self.population = {}
    def add(self,unit, weight):
        self.population.update({unit:weight})
    def show(self):
        for unit in self.population:
            return f"{unit.show()}, {self.population[unit]}" 
    # выбор 2х pdu для кроссовера
    def choice_two(self):
        pkt1 = random.choice(list(self.population.keys()))
        pkt2 = random.choice(list(self.population.keys()))
        return pkt1, pkt2

    # выбор только 1 pdu для мутационного фаззинга
    def choice_one(self):
        return random.choice(list(self.population.keys()))

class Mutator:
    def __init__(self):
        # Constructor
        self.crossovers = [
            self.layer_crossover,
            self.raw_crossover
        ]
        self.mutations = [
            self.bit_flipping,
            self.byte_flipping,
            self.add_value,
            self.replace_spec_value,
            self.replace_rand_value,
            self.delete_byte_block,
            self.replace_byte_block,
            self.add_one_to_rand_byte
        ]

    def mut_fuzz(self,pkt1):
        pkt1 = pkt1.pdu
        mutation = random.choice(self.mutations)
        return mutation(pkt1)
    # случайный выбор кроссовера и мутации
    # выполнение кроссовера и мутации
    def gen_fuzz(self,pkt1,pkt2):
        pkt1 = pkt1.pdu
        pkt2 = pkt2.pdu
        crossover = random.choice(self.crossovers)
        mutation = random.choice(self.mutations)
        after_crossover = crossover(pkt1,pkt2)
        return mutation(after_crossover)

    # Crossover
    # обе функции кроссовера принимают на вход 2 пакета scapy и выдают 1 пакет, соединенный
    # объединение по заголовкам. 
    def layer_crossover(self, pkt1: Ether, pkt2: Ether) -> Ether:
        n = random.randint(1, min(len(pkt1.layers()), len(pkt2.layers())) - 1)
        q = pkt1.copy()
        q[n].payload = pkt2[n]
        return q

    # объединение по байтам
    def raw_crossover(self, pkt1: Ether, pkt2: Ether) -> Ether:
        raw1 = raw(pkt1)
        raw2 = raw(pkt2)

        id_1 = random.randint(0, len(raw1) - 1)
        id_2 = random.randint(0, len(raw2) - 1)

        new_raw = raw1[:id_1] + raw2[id_2:]

        return Ether(new_raw)

    # Mutations
    def bit_flipping(self, pkt: Ether) -> Ether:
        pkt_raw = raw(pkt)
        bit_idx = random.randint(0, len(pkt_raw) * 8 - 1)
        byte_idx = bit_idx // 8
        bit_mask = 1 << (bit_idx % 8)
        pkt_bytes = bytearray(pkt_raw)

        # инвертирование 
        pkt_bytes[byte_idx] ^= bit_mask

        return Ether(bytes(pkt_bytes))

    def byte_flipping(self, pkt: Ether) -> Ether:
        pkt_raw = raw(pkt)
        byte_idx = random.randint(0, len(pkt_raw) - 1)
        pkt_bytes = bytearray(pkt_raw)

        # сложение с байтом со всеми единицами
        pkt_bytes[byte_idx] = ~pkt_bytes[byte_idx] & 0xFF

        return Ether(bytes(pkt_bytes))

    # добавление к каждому байту значения от -128 до 127
    def add_value(self, pkt: Ether) -> Ether:
        pkt_raw = raw(pkt)
        val = random.randint(-128, 127)
        pkt_bytes = [(x + val) & 0xFF for x in pkt_raw]

        return Ether(bytes(pkt_bytes))

    # замена специальными значениями
    def replace_spec_value(self, pkt: Ether) -> Ether:
        pkt_raw = raw(pkt)
        special_val = random.randint(0, 3)

        if special_val == 0:
            pkt_bytes = [0] * len(pkt_raw)  # пустой пакет
        elif special_val == 1:
            pkt_bytes = [0xFF] * len(pkt_raw)  # все единицы
        elif special_val == 2:
            pkt_bytes = [0xA5] * len(pkt_raw)  # магическое число
        elif special_val == 3:
            pkt_bytes = [0x5A] * len(pkt_raw)  # другое магическое число

        return Ether(bytes(pkt_bytes))

    # замена бит случайными значениями
    def replace_rand_value(self, pkt: Ether) -> Ether:
        pkt_raw = raw(pkt)
        pkt_bytes = [random.randint(0, 255) for _ in pkt_raw]

        return Ether(bytes(pkt_bytes))

    # удаление блока байт
    def delete_byte_block(self, pkt: Ether) -> Ether:
        pkt_raw = raw(pkt)
        block_size = random.randint(1, len(pkt_raw) // 2)

        return Ether(bytes(pkt_raw[block_size:]))

    # замена блока байтов случайными значениями
    def replace_byte_block(self, pkt: Ether) -> Ether:
        pkt_raw = raw(pkt)
        block_size = random.randint(1, len(pkt_raw) // 2)
        new_block = [random.randint(0, 255) for _ in range(block_size)]

        return Ether(bytes(new_block + list(pkt_raw)[block_size:]))

    # сложение случайного байта с единицей
    def add_one_to_rand_byte(self, pkt: Ether) -> Ether:
        pkt_raw = raw(pkt)
        pkt_bytes = bytearray(pkt_raw)
        byte_idx = random.randint(0, len(pkt_bytes) - 1)
        pkt_bytes[byte_idx] = (pkt_bytes[byte_idx] + 1) & 0xFF

        return Ether(bytes(pkt_bytes))
    
class Sender:
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
