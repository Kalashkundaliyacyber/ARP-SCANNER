from scapy.layers.l2 import ARP
from scapy.layers.l2 import Ether 
from scapy.sendrecv import srp

broadcast = "FF:FF:FF:FF:FF:FF"
ip_range = "192.168.24.1/24"

# Create ARP request packet
my_arp_packet = ARP(pdst=ip_range)
ether_layer = Ether(dst=broadcast)
packet = ether_layer / my_arp_packet

# Send ARP request packet
ans, unans = srp(packet, iface="eth0", timeout=2)

# Process and print responses
for snd, rcv in ans:
    ip = rcv[ARP].psrc
    mac = rcv[Ether].src
    print(f"IP = {ip} \t MAC = {mac}")
