
from scapy.all import *
from scapy.contrib import *
from scapy.layers.all import *
#from console_app import packet
#это задел под генетический фаззинг
class Seed:
    def __init__(self, pack):
        """Initialize from seed data"""
        self.packet = Ether(_pkt=pack)
        self.all_parts = list()
        self.layer_own = list()
        self.packet_data = str()
# не инициализирую популяцию прямо с единицами данных из scapy потому, что они не хешируются
class Population:
    def __init__(self):
        """Initialize from seed data"""
        self.pop = {}
    def create_pop (self, packets):
        for i in range(0, len(packets)):
            self.pop.update({str(packets[i].command()):[i,1.0]})
        print(self.pop)
        #return self.pop
# обновление популяции должно наступать после отправки пакета
    def update_pop (self, candidate,metric):
        print(f'{self.pop=}')
        print(f'{str(candidate)=}')
        if str(candidate) not in self.pop.keys():
            self.pop.update({str(candidate.command()):[len(self.pop),float(metric)]})
            return True
        else:
            print(self.pop)
            print(self.pop[str(candidate)][0])
            self.pop.update({str(candidate.command()):[self.pop[str(candidate)][0],metric]})
            print(self.pop)
            return False
    def norm_pop (self):
        print(f'{self.pop=}')
        norm_value = 0
        for p in self.pop.keys():
            norm_value = self.pop[p][1]
        for p in self.pop.keys():
            self.pop[p][1] = self.pop[p][1]/norm_value
        #print(self.pop)
        #return self.pop

    def choose(self, packets):
        print(self.pop)
        candidates = [i[0] for i in self.pop.values()]
        cand_weights = [i[1] for i in self.pop.values()]
        # Внимание, могут быть вабраны одинаковые пакеты и тогда на выходе скорее всего тоже будет одинаковый
        print(f'{candidates=}, {cand_weights=}' )
        #Сделал, чтобы отдавал разные номера
        while True:
            a,b= random.choices(candidates, weights=cand_weights,k=2)
            if a!=b: break
        return packets[a],packets[b]

packet = rdpcap('corpus.pcap')

population = Population()
population.create_pop(packet)
#print(population.choose(packet))
