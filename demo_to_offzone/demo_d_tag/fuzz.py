import fuzzing_mod
from scapy.all import *

# pkt1 = Ether(dst='ff:ff:ff:ff:ff:ff')/Dot1Q(vlan=1)/IP(dst='10.10.10.11')/ICMP()
population = [Ether(dst='ff:ff:ff:ff:ff:ff')/Dot1Q(vlan=1)/IP(dst='10.10.10.11')/ICMP()]

sendp(population[0], iface='tap0')

while True:
    pkt1 = random.choice(population)
    pkt2 = random.choice(population)
    print(' first packet:',pkt1.summary(),'\n','second packet:',pkt2.summary())
    PDU = fuzzing_mod.layer_crossover_mutation(pkt1,pkt2)
    print('Result:',PDU.command())
    sendp(PDU, iface='tap0')