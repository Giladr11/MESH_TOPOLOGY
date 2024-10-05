from scapy.layers.inet import *
from scapy.all import *


class IPS_Manager:
    def __init__(self, iface, base_threshold=100, time_window=10):
        self.iface = iface
        self.base_threshold = base_threshold
        self.time_window = time_window
        self.udp_packets = defaultdict(list)
        self.blocked_nodes = []

    def detect_udp_flood(self, syn_packet):
        current_time = time.time()
        src_mac = syn_packet[Ether].src
        self.udp_packets[src_mac].append(current_time)
        self.udp_packets[src_mac] = [timestamp for timestamp in self.udp_packets[src_mac] if current_time - timestamp <= self.time_window]

        if len(self.udp_packets[src_mac]) > self.base_threshold:
            return True
        return False

    def send_block_broadcast(self, attacker_mac):
        print(f"Sending a block broadcast packet for the mac address: {attacker_mac}")
        broadcast_packet = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x9002) / Raw(load=attacker_mac.encode('utf-8'))
        sendp(broadcast_packet, iface=self.iface)
        self.block_node(attacker_mac)

    def block_node(self, attacker_mac):
        self.blocked_nodes.append(attacker_mac)
        print(f"Successfully Blocked the mac address: {attacker_mac}")
        print("current Blocked Nodes: ", self.blocked_nodes)
