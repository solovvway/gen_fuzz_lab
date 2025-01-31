from scapy.all import *
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D


osi_layers = {
    # Уровень 1: Физический уровень
    'Ether': 2,  # Уровень 2: Канальный уровень
    '802.11': 2,    # Уровень 2: Канальный уровень (Wi-Fi)
    'Bluetooth': 2,  # Уровень 2: Канальный уровень (Bluetooth)
    'DSL': 1,       # Уровень 1: Физический уровень
    'ISDN': 1,      # Уровень 1: Физический уровень

    # Уровень 2: Канальный уровень
    'PPP': 2,       # Уровень 2: Канальный уровень (Point-to-Point Protocol)
    'Frame Relay': 2,  # Уровень 2: Канальный уровень
    'HDLC': 2,      # Уровень 2: Канальный уровень (High-Level Data Link Control)

    # Уровень 3: Сетевой уровень
    'IP': 3,        # Уровень 3: Сетевой уровень (Internet Protocol)
    'IPv4': 3,      # Уровень 3: Сетевой уровень (Internet Protocol version 4)
    'IPv6': 3,      # Уровень 3: Сетевой уровень (Internet Protocol version 6)
    'ICMP': 3,      # Уровень 3: Сетевой уровень (Internet Control Message Protocol)
    'IGMP': 3,      # Уровень 3: Сетевой уровень (Internet Group Management Protocol)
    'ARP': 3,       # Уровень 3: Сетевой уровень (Address Resolution Protocol)

    # Уровень 4: Транспортный уровень
    'TCP': 4,       # Уровень 4: Транспортный уровень (Transmission Control Protocol)
    'UDP': 4,       # Уровень 4: Транспортный уровень (User  Datagram Protocol)
    'SCTP': 4,      # Уровень 4: Транспортный уровень (Stream Control Transmission Protocol)

    # Уровень 5: Сеансовый уровень
    'RPC': 5,       # Уровень 5: Сеансовый уровень (Remote Procedure Call)
    'NetBIOS': 5,   # Уровень 5: Сеансовый уровень

    # Уровень 6: Представительский уровень
    'TLS': 6,       # Уровень 6: Представительский уровень (Transport Layer Security)
    'SSL': 6,       # Уровень 6: Представительский уровень (Secure Sockets Layer)

    # Уровень 7: Прикладной уровень
    'HTTP': 7,      # Уровень 7: Прикладной уровень (Hypertext Transfer Protocol)
    'HTTPS': 7,     # Уровень 7: Прикладной уровень (HTTP Secure)
    'FTP': 7,       # Уровень 7: Прикладной уровень (File Transfer Protocol)
    'SFTP': 7,      # Уровень 7: Прикладной уровень (SSH File Transfer Protocol)
    'SMTP': 7,      # Уровень 7: Прикладной уровень (Simple Mail Transfer Protocol)
    'POP3': 7,      # Уровень 7: Прикладной уровень (Post Office Protocol version 3)
    'IMAP': 7,      # Уровень 7: Прикладной уровень (Internet Message Access Protocol)
    'DNS': 7,       # Уровень 7: Прикладной уровень (Domain Name System)
    'DHCP': 7,      # Уровень 7: Прикладной уровень (Dynamic Host Configuration Protocol)
    'SNMP': 7,      # Уровень 7: Прикладной уровень (Simple Network Management Protocol)
    'Telnet': 7,    # Уровень 7: Прикладной уровень (Telnet)
    'SSH': 7,       # Уровень 7: Прикладной уровень (Secure Shell)
}

# Пример использования
def get_osi_layer(protocol):
    """Возвращает номер уровня OSI для данного протокола."""
    return osi_layers.get(protocol, None)
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


class NetDot:
    def __init__(self,x,y,z):
        self.x = x
        self.y = y
        self.z = z

dump = [Ether()/IP(dst='127.0.0.1'),Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/UDP()/DNS(),Ether()/IP(dst='127.0.0.1')/TCP()] 

uniq_dump = []
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

    # Полный уникальный набор протоколов в uniq_dump
netDots = []
for i in uniq_dump:
    protocols = [layer.__name__ for layer in i.pdu.layers()]
    x = get_osi_layer(protocols[0]) if len(protocols) > 0 else 0
    y = get_osi_layer(protocols[1]) if len(protocols) > 1 else 0
    z = get_osi_layer(protocols[2]) if len(protocols) > 2 else 0
    netdot = NetDot(x=x, y=y, z=z)
    netDots.append(netdot)

# Визуализация в 3D
fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')

# Извлечение координат для графика
x_coords = [dot.x for dot in netDots]
y_coords = [dot.y for dot in netDots]
z_coords = [dot.z for dot in netDots]

# Отображение точек на графике
ax.scatter(x_coords, y_coords, z_coords)

# Настройка меток осей
ax.set_xlabel('Уровень 2 (Канальный уровень)')
ax.set_ylabel('Уровень 3 (Сетевой уровень)')
ax.set_zlabel('Уровень 4 (Транспортный уровень)')

# Установка меток на осях
# Уровень 2
ax.set_xticks([2])  # Уровень 2
ax.set_xticklabels(['2'])  # Метка для уровня 2

# Уровень 3
ax.set_yticks([3])  # Уровень 3
ax.set_yticklabels(['3'])  # Метка для уровня 3

# Уровень 4
ax.set_zticks([4])  # Уровень 4
ax.set_zticklabels(['4'])  # Метка для уровня 4

# Показ графика
filename = 'traffic_visualization.png'
plt.savefig(filename)
plt.close()  # Закрыть фигуру, чтобы освободить память