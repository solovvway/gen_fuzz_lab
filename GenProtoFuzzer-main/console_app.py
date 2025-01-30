import click
import fuzzer
#from scapy.all import Ether, IP, TCP, ICMP,DNS
from scapy.all import *
from scapy.contrib import *
from scapy.layers.all import *
import random as rd
import gen
import dev

@click.command()
@click.option('-pcap', default=None, help='Specify to select pcap to create a test case.')
@click.option('-i', default=None, help='Listen to traffic from an interface to create a test case')
@click.option('-n', default=10, type=int, help='Specify the number of packets to capture')
@click.option('-v', count=True, help='Enable verbose logging')
@click.option('-raw_mutate', default=None, type=int, help='Generate a specified number of packets and display them')
def cli(pcap, i, n,v,raw_mutate):
    # Show the banner
    banner()
    # If -pcap option is specified
    if pcap:
        click.echo(f'Listening to traffic from pcap {pcap}')
        #packet = rdpcap(pcap)
        start_test(v,pcap)
    # If -i option is specified
    elif i:
        click.echo(f'Listening to traffic from interface {i}')
        try:
            packet = sniff(count=n, iface=i)
            pcap='corpus.pcap'
            wrpcap(pcap, packet, append=True)
            print(packet.nsummary())
            print(f'Captured {n} packets from interface {i}')
            start_test(v,pcap)
        except:
            click.echo(f'Can`t capture traffic from interafce {i}')
    elif raw_mutate:
        packet = rdpcap('corpus.pcap')
        if v == 0:
            for i in range(0,raw_mutate):
                pck1 = random.choice(packet)
                pck2 = random.choice(packet)
                click.echo(f'Packet number {i}')
                click.echo("     ",fuzzer.Crossover().mutate(pck1, pck2).summary())
                click.echo("")
        if v > 0:
            for i in range(0,raw_mutate):
                pck1 = random.choice(packet)
                pck2 = random.choice(packet)
                click.echo(f'Packet number {i}')
                click.echo("     ",fuzzer.Crossover().mutate(pck1, pck2).show2())
                click.echo("")
    else:
        click.echo("Error: No action specified.")
        click.echo("Please use either -pcap or -i option.")


def banner():
    banner = '''#     #              #######                                         ###       ####### 
##    # ###### ##### #       #    # ###### ###### ###### #####      #   #      #       
# #   # #        #   #       #    #     #      #  #      #    #    #     #     #       
#  #  # #####    #   #####   #    #    #      #   #####  #    #    #     #     ######  
#   # # #        #   #       #    #   #      #    #      #####     #     # ###       # 
#    ## #        #   #       #    #  #      #     #      #   #      #   #  ### #     # 
#     # ######   #   #        ####  ###### ###### ###### #    #      ###   ###  #####                                                                         '''
    click.echo(banner)
    click.echo()

def start_test(v,pcap):
    packet = rdpcap(pcap)
    click.echo('')
    click.echo(f'List of packets in test corpus')
    if v == 0:
        for i in range(0, len(packet)):
            print("     ",i,"   ", packet[i].summary())
    else:
        for i in range(0, len(packet)):
            print("     ",i,"   ", packet[i].show2())
    click.echo('')    
    input("Press any button to start test")
    #print('process_pcap(pcap)')
    check=False

    # если генерация популяуии здесь, то тестирование будет с памятью
    population = gen.Population()
    population.create_pop(packet)
    while not check:
        '''# если генерация популяции здесь, то тестирование будет без памяти
        population = gen.Population()
        population.create_pop(packet)'''
        packet = rdpcap(pcap)
        pck = population.choose(packet)
        if v == 0:
            click.echo("Candidates to crossover")
            print('>    ',pck[0])
            print('>    ',pck[1])
            click.echo("")
            click.echo("Packet after mutate")
            result_packet = fuzzer.Crossover().mutate(pck[0], pck[1])
            print(result_packet)
            click.echo("")
            check = fuzzer.sender(result_packet,population,pcap)

            #print('>    ', result_packet)
        if v > 0:
            click.echo("Candidates to crossover")
            print('>    ',pck[0].show2())
            print('>    ',pck[1].show2())
            click.echo("")
            click.echo("Packet after mutate")
            result_packet = fuzzer.Crossover().mutate(pck[0], pck[1])
            click.echo("")
            check = fuzzer.sender(result_packet,population,pcap)
            print('>    ', result_packet.show2())
        
        click.echo("____________________________________________________________________________")
        #break
        #check=True
    click.echo("Stop testing")

if __name__ == '__main__':
    cli()