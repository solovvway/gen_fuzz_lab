
import fuzzer
from scapy.all import Ether, IP, TCP, ICMP,DNS
from scapy.all import *
import random as rd
import gen
import dev
banner = '''#     #              #######                                         ###       ####### 
##    # ###### ##### #       #    # ###### ###### ###### #####      #   #      #       
# #   # #        #   #       #    #     #      #  #      #    #    #     #     #       
#  #  # #####    #   #####   #    #    #      #   #####  #    #    #     #     ######  
#   # # #        #   #       #    #   #      #    #      #####     #     # ###       # 
#    ## #        #   #       #    #  #      #     #      #   #      #   #  ### #     # 
#     # ######   #   #        ####  ###### ###### ###### #    #      ###   ###  #####  
                                                                                    '''

print(banner)
#dev.make_pcap()
check = False
packet = rdpcap('corpus.pcap')
print("Список пакетов в исходном корпусе")
for i in range(0, len(packet)):
    print("     ",i,"   ", packet[i].summary())
input("нажмите чтобы начать генерацию пакетов")
for i in range(0,15):
    pck1 = random.choice(packet)
    pck2 = random.choice(packet)
    print("     ",fuzzer.Crossover().mutate(pck1, pck2).summary())
input("нажмите чтобы начать тестирование")
while not check:
    population = gen.Population()
    population.create_pop(packet)
    pck = population.choose(packet)
    print("Кандидаты для кроссовера")
    print(pck[0],'\n', pck[1])
    check = fuzzer.sender(fuzzer.Crossover().mutate(pck[0], pck[1]),population)
    #break
    check=True
print("Один из пакетов достиг цели, прекращено выполнение программы")

