from scapy.layers.inet import *
from scapy.all import *
import ip_mac_config
# 18:67:B0:B3:A7:50
for i in range(100):
    udp_packet = Ether(src=ip_mac_config.IP_Mac_Config(None).get_src_mac(), dst="34:97:F6:D2:16:46") / IP(dst="192.168.1.1") / UDP(sport=65000, dport=65000)
    sendp(udp_packet, iface="Ethernet")
# udp_packet = Ether(src=ip_mac_config.IP_Mac_Config("").get_src_mac(), dst="18:67:b0:b3:a7:50") / IP(dst="192.168.1.2") / UDP(sport=65000, dport=65000)
# sendp(udp_packet, iface="Ethernet")
