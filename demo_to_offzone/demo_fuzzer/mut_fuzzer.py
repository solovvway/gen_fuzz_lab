import fuzzing_mod
from scapy.all import *
import time


######################CREATE CORPUS##############

#with sniffing
corpus = sniff(count=20)

#with Asyncsniffing
# corpus = AsyncSniffer(count=20)
# corpus.start()
# time.sleep(1)
# print("something else")
# time.sleep(1)
# corpus.stop()

#with interseption by netfilter, intersept stop after Ctrl+C
# corpus = []
# def my_callback(payload):
#     global corpus
#     data = payload.get_payload()
#     pkt = IP(data)
#     corpus.append(pkt)
#     # pkt.show()
#     print(corpus)
#     payload.set_payload(bytes(data))
# fuzzing_mod.intercept(my_callback)
# print(corpus)

##################FUZZING################


# scapy fixed fuzz function
# while True:
#     PDU = random.choice(corpus)
#     print('Choised PDU', PDU.summary())
#     PDU.show()
#     mutated_PDU = fuzzing_mod.scapy_fix_rand(PDU)
#     print('Mutated PDU', mutated_PDU.summary())
#     mutated_PDU.show()
#     for i in range(10):
#         sendp(mutated_PDU)  

#real mutation fuzzing
while True:
    PDU = random.choice(corpus)
    print('Choised PDU', PDU.summary())
    PDU.show()
    mutated_PDU = fuzzing_mod.raw_mutations(PDU)
    print('Mutated PDU', mutated_PDU.summary())
    mutated_PDU.show()
    sendp(mutated_PDU)  