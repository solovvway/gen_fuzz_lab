#from scapy.all import Ether, IP, TCP, ICMP
from scapy.all import *
from scapy.contrib import *
from scapy.layers.all import *
import random as rd
# импортируем для обновления популяции после отправки
import gen



#создает пакет из переданной строки
def packet_create(str_com):
    str_com.encode('unicode_escape')
    try:
        exec(r"y=" + fr'''{str_com}''', globals())
    except:
        str_com = str_com.rpartition('/')[0]
        try:
            if str_com[-1] != ')': str_com+=")"
            exec(r"y=" + fr'''{str_com}''', globals())
        except:
            pass
#выдает список заголовков пакета
def get_packet_layers(packet):
    counter = 0
    layers = []
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break
        layers.append(layer.name)
        counter += 1
        ##print(layers)
    return layers

#непрерывный семантически-верный фаззинг в соответствии с заголовком, но это на будущее
def fuzz(packet):
    global y
    pckt = f'fuzz({packet.command()})'
    packet_create(f"{pckt}")
    sender(y)

#отправка сгенерированного пакета и в зависимости от ответа действие
def sender(packet,population,pcap='corpus.pcap'):
    if packet is False:
        return False
    
    try:
        ans = sr(packet, timeout=2)
        #вычисление задержки на ответ, планируется использование в качестве метрики
        print(ans)
        print(ans[0])
        print(ans[0].time)
        print(ans[0].sent_time)
        
        timestamp = ans[0][0][1].time - ans[0][0][0].time
        print('timestamp', timestamp)
        #print('Probe', ans[0][0][0], '\n', 'Response', ans[0][0][1])
        # если получен ответ на пакет, он добавляется в успешные
        #print("packet written in pcap")


        population.update_pop(packet,timestamp)
        population.norm_pop()
        print('Got answer')
        wrpcap(pcap, packet, append=True)
        print(f'Written into {pcap}')
        return True

    except:
        #print('Unanswered probe/////', ans[1][0], '////')
        #wrpcap("banana.pcap", packet, append=True)
        #print("Pcap written")

        #timestamp = ans[0][1].time - ans[0][0].sent_time
        print('Unanswered probe')

        #only for test with no laboratory
        #
        # if population.update_pop(packet,0.1):
        #     print(f'Population updated with packet {str(packet)}')
        #
        
        wrpcap('discarded.pcap', packet, append=True)
        print('Written into discarded.pcap')
        return False
        #при неудачной доставке формула задержки вычисляется иначе
        #timestamp = ans[0][1].time - ans[0][0].sent_time


class Crossover():
    def __init__(self):
        #Constructor
        self.crossovers = [
            self.crossover_headers,
            self.crossover_headers_fields]
        self.iterations=0

    def mutate(self, packet1, packet2):
        crossover = random.choice(self.crossovers)
        
        return crossover(packet1, packet2)


    #склейка двух пакетов в один
    def crossover_headers(self, packet1, packet2):
        print(f'Tipe of crossover in fuzzer - crossover_headers')
        global y
        #выбор пакета-основы
        main = rd.choice([packet1, packet2]).command().split('/')
        if main == packet1.command().split('/'):
            sub = packet2.command().split('/')
        else:
            sub = packet1.command().split('/')

        #вычисление места с которого начнется замена
        pos = random.randint(1, len(main) - 1)
        result = []
        print(f'Change headers below {pos}-header')
        for i in range(0, max(len(main), len(sub))):
            if i < pos:
                try:
                    result.append(sub[i])
                except:
                    #print("Ошибка присоединения ")
                    break
            else:
                try:
                    result.append(main[i])
                except:
                    #print("Ошибка присоединения")
                    break

        a = str('/'.join(result))
        b = f"baby_packet={a}"
        ##print(b)
        packet_create(f"{a}")
        return y
    #замена значений одного пакета на значения другого
    def crossover_headers_fields(self, packet1, packet2):
        print(f'Tipe of crossover in fuzzer - crossover_headers_fields')
        children = rd.choice([packet1, packet2])
        main = children
        if children == packet1:
            sub = packet2
        else:
            sub = packet1
        pos = random.randint(1, len(main) - 1)
        i = 0
        print(f'Change headers below {pos}-header')
        for layer in get_packet_layers(children):
            ##print(layer)
            try:
                attributes = getattr(sub[layer], 'fields_desc')
                ##print(attributes)
                for attr in attributes:
                    if i < pos:
                        if attr.name != 'dst' or attr.name != 'src':
                            attr_value = getattr(sub[layer], attr.name)
                            ##print(pos, attr.name, attr_value)
                            setattr(children[layer],
                                    f'{attr.name}', attr_value)
                    i += 1
            except:
                
                #print(f"Layer {layer} has not found in another packet")
                pass
        return children

