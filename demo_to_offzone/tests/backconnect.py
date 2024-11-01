from scapy.all import IP, ICMP, sr1
import netifaces
import threading
import time
import matplotlib.pyplot as plt
import numpy as np

def get_targets(corpus):
    my_ip = set()
    for iface in netifaces.interfaces():
        iface_details = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in iface_details:
            my_ip.add(iface_details[netifaces.AF_INET][0]['addr'])

    all = {i[IP].dst for i in corpus}
    return all.difference(my_ip)

def ping_back(target):
    echo_request = IP(dst=target)/ICMP(type=8)
    response = sr1(echo_request, timeout=1, verbose=0)
    if response:
        print(f"Response received from {target} in {response.time}")
        return response.time, time.time()
    else:
        print(f"No response received from {target}")
        return None

def main():
    targets = get_targets([IP(), IP(dst='9.9.9.9'), IP(dst='2.2.2.2')])
    times1 = []
    times2 = []
    for target in targets:
        times1.append({target:[]})
        times2.append({target:[]})
        t1,t2 = ping_back(target)
        if t1 != None: 
            times1[target].append(t1)
            times2[target].append(t2)
        





if __name__ == "__main__":
    main()

# from scapy.all import IP, ICMP, sr1
# import netifaces
# import threading
# import time
# import matplotlib.pyplot as plt
# import numpy as np
# import signal

# def get_targets(corpus):
#     my_ip = set()
#     for iface in netifaces.interfaces():
#         iface_details = netifaces.ifaddresses(iface)
#         if netifaces.AF_INET in iface_details:
#             my_ip.add(iface_details[netifaces.AF_INET][0]['addr'])

#     all = {i[IP].dst for i in corpus}
#     return all.difference(my_ip)

# def ping_back(target):
#     times = []
#     while True:
#         echo_request = IP(dst=target)/ICMP(type=8)
#         response = sr1(echo_request, timeout=1, verbose=0)
#         if response:
#             print(f"Response received from {target} in {response.time}")
#             times.append((response.time, time.time()))
#         else:
#             print(f"No response received from {target}")
#         time.sleep(1)

# def main():
#     targets = get_targets([IP(), IP(dst='9.9.9.9'), IP(dst='2.2.2.2')])
#     threads = []
#     times = [[] for _ in range(len(targets))]

#     for i, target in enumerate(targets):
#         t = threading.Thread(target=ping_back, args=(target,))
#         threads.append(t)
#         t.start()

#     while True:
#         try:
#             for t in threads:
#                 t.join(0.1)
#         except KeyboardInterrupt:
#             for t in threads:
#                 t.join()
#             for i, target in enumerate(targets):
#                 plt.plot([t[1] for t in times[i]], [t[0] for t in times[i]])
#                 plt.xlabel('Real time (seconds)')
#                 plt.ylabel('Response time (seconds)')
#                 plt.title(f"Response times for {target}")
#                 plt.show()

# if __name__ == "__main__":
#     main()