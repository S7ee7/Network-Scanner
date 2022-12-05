import scapy.all as scapy
import optparse
from mac_vendor_lookup import MacLookup
import time
from termcolor import colored

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-r", "--range", dest="network_ip", help="Network IP address to apply scan on")
    options = parser.parse_args()[0]

    if not options.network_ip:
        parser.error("[-] Network IP was not provided")

    return options.network_ip

def scan_network(network_ip):
    arp_request = scapy.ARP(pdst=network_ip)
    arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = arp_broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered

def art_print():
    print(colored("""
           __________                                 
         .'----------`.                              
         | .--------. |                             
         | |########| |       __________              
         | |########| |      /__________\             
.--------| `--------' |------|    --=-- |-------------.
|        `----,-.-----'      |o ======  |             | 
|       ______|_|_______     |__________|             | 
|      /  %%%%%%%%%%%%  \                             | 
|     /  %%%%%%%%%%%%%%  \                            | 
|     ^^^^^^^^^^^^^^^^^^^^                            | 
+-----------------------------------------------------+
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ 
    """, "yellow"))

def display_clients():
    art_print()
    print("IP address\t MAC Address\t\tVendor")
    print("-" * 50)
    clients_list = []
    network_ip = get_arguments()

    while True:
        answered = scan_network(network_ip)
        for ans in answered:
            if ans[1].psrc not in clients_list:
                clients_list.append(ans[1].psrc)
                print(ans[1].psrc, "\t",ans[1].hwsrc, "\t", MacLookup().lookup(ans[1].hwsrc))

        time.sleep(5)

try:
    display_clients()
except KeyboardInterrupt:
    print("[-] Exiting Network Scanner...")
