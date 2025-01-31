from scapy.all import sniff
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

class TrafficVisualizer: 
    def __init__(self):  
        self.protocols = { 
            'layer2': [],  # Протоколы второго уровня 
            'layer3': [],  # Протоколы третьего уровня 
            'layer4': []    # Протоколы четвертого уровня 
        }

    def packet_callback(self, packet):
        # Извлечение протоколов из пакета
        if packet.haslayer('Ether'):
            self.protocols['layer2'].append(packet['Ether'].type)
        if packet.haslayer('IP'):
            self.protocols['layer3'].append(packet['IP'].proto)
        if packet.haslayer('TCP'):
            self.protocols['layer4'].append(4)  # TCP
        elif packet.haslayer('UDP'):
            self.protocols['layer4'].append(17)  # UDP

    def start_sniffing(self, count=100):
        sniff(prn=self.packet_callback, count=count)

    def visualize(self, filename='traffic_visualization.png'):
        # Преобразование протоколов в уникальные значения
        layer2_protocols = list(set(self.protocols['layer2']))[:2]  # 2 уникальных протокола второго уровня
        layer3_protocols = list(set(self.protocols['layer3']))[:2]  # 2 уникальных протокола третьего уровня
        layer4_protocols = list(set(self.protocols['layer4']))[:2]  # 2 уникальных протокола четвертого уровня

        # Создание 3D графика
        fig = plt.figure()
        ax = fig.add_subplot(111, projection='3d')

        # Отображение точек
        ax.scatter(range(len(layer2_protocols)), range(len(layer3_protocols)), range(len(layer4_protocols)), c='r', marker='o')

        ax.set_xlabel('Layer 2 Protocols')
        ax.set_ylabel('Layer 3 Protocols')
        ax.set_zlabel('Layer 4 Protocols')

        # Установка меток на осях только если есть протоколы
        if layer2_protocols:
            ax.set_xticks(range(len(layer2_protocols)))
            ax.set_xticklabels(layer2_protocols)
        if layer3_protocols:
            ax.set_yticks(range(len(layer3_protocols)))
            ax.set_yticklabels(layer3_protocols)
        if layer4_protocols:
            ax.set_zticks(range(len(layer4_protocols)))
            ax.set_zticklabels(['TCP', 'UDP'][:len(layer4_protocols)])  # Убедитесь, что количество меток соответствует количеству протоколов

        # Сохранение графика в файл
        plt.savefig(filename)
        plt.close()  # Закрыть фигуру, чтобы освободить память

if __name__ == "__main__":
    visualizer = TrafficVisualizer() 
    print("Начинаем захват трафика...") 
    visualizer.start_sniffing(count=10)  # Захват 10 пакетов 
    print("Захват завершен. Сохраняем данные в файл...") 
    visualizer.visualize(filename='traffic_visualization.png')  # Сохранение графика в файл
    print("График сохранен как 'traffic_visualization.png'.")