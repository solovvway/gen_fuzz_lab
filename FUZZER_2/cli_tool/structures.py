from scapy.all import *
import random
from collections import OrderedDict


class Unit:
    def __init__(self, ip_src, ip_dst, mac_src, mac_dst, layers, pdu):
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.mac_src = mac_src
        self.mac_dst = mac_dst
        self.layers = layers
        self.pdu = pdu

    def show(self):
        return f"IP Src: {self.ip_src}, \nIP Dst: {self.ip_dst},\n MAC Src: {self.mac_src},\n MAC Dst: {self.mac_dst}, \n  Layers: {self.layers}"

    def __eq__(self, other):
        if isinstance(other, Unit):
            return (self.ip_src == other.ip_src and
                    self.ip_dst == other.ip_dst and
                    self.mac_src == other.mac_src and
                    self.mac_dst == other.mac_dst)
        return False

    def __hash__(self):
        return hash((self.ip_src, self.ip_dst, self.mac_src, self.mac_dst))


class Population:
    def __init__(self):
        self.population = {}

    def add(self, unit, weight):
        self.population.update({unit: weight})

    def show(self):
        output = []
        for unit in self.population:
            output.append(f"{unit.show()}, {self.population[unit]}")
        return output

    def choice_two(self):
        print(f'{list(self.population.values())=}')
        pkt1 = random.choices(list(self.population.keys()), weights=list(self.population.values()), k=1)[0]
        pkt2 = random.choices(list(self.population.keys()), weights=list(self.population.values()), k=1)[0]
        return pkt1, pkt2

    def choice_one(self):
        return random.choices(list(self.population.keys()), weights=list(self.population.values()), k=1)[0]


class Mutator:
    def __init__(self, weights=None):
        self.crossovers = OrderedDict([
            (self.layer_crossover, 1),
            (self.raw_crossover, 1)
        ])
        self.mutations = OrderedDict([
            (self.bit_flipping, 1),
            (self.byte_flipping, 1),
            (self.add_value, 1),
            (self.replace_spec_value, 1),
            (self.replace_rand_value, 1),
            (self.delete_byte_block, 1),
            (self.replace_byte_block, 1),
            (self.add_one_to_rand_byte, 1)
        ])
        # если переданы веса, использовать их для инициализации мутатора
        if weights:
            if 'crossovers' in weights:
                for method, weight in zip(self.crossovers.keys(), weights['crossovers']):
                    self.crossovers[method] = weight
            
            if 'mutations' in weights:
                for method, weight in zip(self.mutations.keys(), weights['mutations']):
                    self.mutations[method] = weight
    def mut_fuzz(self, pkt1):
        pkt1 = pkt1.pdu
        mutation = random.choices(list(self.mutations.keys()), weights=list(self.mutations.values()), k=1)[0]
        return mutation(pkt1)

    def gen_fuzz(self, pkt1, pkt2):
        pkt1 = pkt1.pdu
        pkt2 = pkt2.pdu
        crossover = random.choices(list(self.crossovers.keys()), weights=list(self.crossovers.values()), k=1)[0]
        mutation = random.choices(list(self.mutations.keys()), weights=list(self.mutations.values()), k=1)[0]
        after_crossover = crossover(pkt1, pkt2)
        return mutation(after_crossover)

    def layer_crossover(self, pkt1: Ether, pkt2: Ether) -> Ether:
        n = random.randint(1, min(len(pkt1.layers()), len(pkt2.layers())) - 1)
        q = pkt1.copy()
        q[n].payload = pkt2[n]
        return q

    def raw_crossover(self, pkt1: Ether, pkt2: Ether) -> Ether:
        raw1 = raw(pkt1)
        raw2 = raw(pkt2)

        id_1 = random.randint(0, len(raw1) - 1)
        id_2 = random.randint(0, len(raw2) - 1)

        new_raw = raw1[:id_1] + raw2[id_2:]

        return Ether(new_raw)

    def bit_flipping(self, pkt: Ether) -> Ether:
        pkt_raw = raw(pkt)
        bit_idx = random.randint(0, len(pkt_raw) * 8 - 1)
        byte_idx = bit_idx // 8
        bit_mask = 1 << (bit_idx % 8)
        pkt_bytes = bytearray(pkt_raw)

        pkt_bytes[byte_idx] ^= bit_mask

        return Ether(bytes(pkt_bytes))

    def byte_flipping(self, pkt: Ether) -> Ether:
        pkt_raw = raw(pkt)
        byte_idx = random.randint(0, len(pkt_raw) - 1)
        pkt_bytes = bytearray(pkt_raw)

        pkt_bytes[byte_idx] = ~pkt_bytes[byte_idx] & 0xFF

        return Ether(bytes(pkt_bytes))

    def add_value(self, pkt: Ether) -> Ether:
        pkt_raw = raw(pkt)
        val = random.randint(-128, 127)
        pkt_bytes = [(x + val) & 0xFF for x in pkt_raw]

        return Ether(bytes(pkt_bytes))

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

    def replace_rand_value(self, pkt: Ether) -> Ether:
        pkt_raw = raw(pkt)
        pkt_bytes = [random.randint(0, 255) for _ in pkt_raw]

        return Ether(bytes(pkt_bytes))

    def delete_byte_block(self, pkt: Ether) -> Ether:
        pkt_raw = raw(pkt)
        block_size = random.randint(1, len(pkt_raw) // 2)

        return Ether(bytes(pkt_raw[block_size:]))

    def replace_byte_block(self, pkt: Ether) -> Ether:
        pkt_raw = raw(pkt)
        block_size = random.randint(1, len(pkt_raw) // 2)
        new_block = [random.randint(0, 255) for _ in range(block_size)]

        return Ether(bytes(new_block + list(pkt_raw)[block_size:]))

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
        print("PACKET BEFORE SENDING:", packet.command())

        if IP in packet:
            del packet[IP].chksum  # Remove checksum to recalculate

        start_time = time.time()
        response = sendp(packet, iface=self.iface, verbose=0) if Ether in packet else send(packet, iface=self.iface, verbose=0)
        end_time = time.time()

        if response:
            rtt = (end_time - start_time) * 1000  # Convert to milliseconds
            print(f"Packet sent: {packet.summary()}, RTT: {rtt:.2f} ms")
        else:
            print(f"Packet sent: {packet.summary()}, No response")

class Sniffer:
    def __init__(self, network, iface='eth0'):
        self.iface = iface
        self.captured_packets = []
        self.network = None
        subnet_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$')
        if subnet_pattern.match(network):
            self.network = network 
        

    def packet_callback(self, packet):
        self.captured_packets.append(packet)

    def sync_sniff(self, count=10):
        """
        Синхронный метод для перехвата пакетов.
        :param count: Количество пакетов для перехвата.
        :return: Список перехваченных пакетов.
        """
        self.captured_packets = []  # Сбросить предыдущие пакеты
        sniff(iface=self.iface, count=count, prn=self.packet_callback, filter=f'net {self.network}')
        return self.captured_packets

    def async_sniff(self):
        """
        Асинхронный метод для перехвата пакетов.
        :return: Список перехваченных пакетов.
        """
        self.captured_packets = []  # Сбросить предыдущие пакеты
        self.sniffer = AsyncSniffer(iface=self.iface, prn=self.packet_callback,  filter=f'net {self.network}')
        self.sniffer.start()
        return self.captured_packets

    def stop_async_sniff(self):
        """
        Остановить асинхронный перехват пакетов.
        :return: Список перехваченных пакетов.
        """
        self.sniffer.stop()
        return self.captured_packets


if __name__ == '__main__':
    sniffer = Sniffer(iface='lo', network='127.0.0.1/32')

    # Синхронный перехват
    # print("Синхронный перехват:")
    # packets = sniffer.sync_sniff(count=5)
    # for pkt in packets:
    #     print(pkt)

    # Асинхронный перехват
    print("\nАсинхронный перехват:")
    async_packets = sniffer.async_sniff()
    print("Перехват запущен. Нажмите Enter для остановки...")
    input()  # Ожидание ввода для остановки
    captured_packets = sniffer.stop_async_sniff()
    for pkt in captured_packets:
        print(pkt)