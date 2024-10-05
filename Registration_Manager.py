from scapy.layers.inet import *
from scapy.all import *
import ip_mac_config
import pickle


class Registration_Manager:
    def __init__(self, username, iface, ip=None):
        self.username = username
        self.ip = ip
        self.iface = iface
        self.ip_array = []
        self.known_usernames_file = 'known_usernames.txt'
        self.username_status = False
        self.mac = ip_mac_config.IP_Mac_Config.get_src_mac(None)
        self.blocked_list = None
        print(self.mac)

    def analyze_response_packets(self, packet):
        if packet.haslayer(Ether) and packet.haslayer(Raw) and packet[Ether].src != self.mac and packet[Ether].dst == self.mac:
            print("received response packet: ", packet.show())
            response_data = packet[Raw].load.rstrip(b'\x00').decode('utf-8')
            ip, username, pickled_blocked_list = response_data.split(':')
            print("the received ip is: ", ip)
            print("the received username is: ", username)
            self.ip_array.append(ip)

            with open(self.known_usernames_file, 'w') as file:
                file.write(f"{username}\n")

            if self.username.lower() == username.lower():
                self.username_status = True

    def check_username(self):
        if os.path.exists(self.known_usernames_file):
            with open(self.known_usernames_file, 'r') as file:
                for username in file:
                    if self.username.lower() == username.strip().lower():
                        return True

        print("Sending broadcast to check username availability...")
        broadcast_packet = Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff", type=0x9001)
        sendp(broadcast_packet, iface=self.iface)
        sniff(iface=self.iface, prn=self.analyze_response_packets, timeout=4)
        return self.username_status

    def assign_ip(self):
        print("the ip array is: ", self.ip_array)
        if self.ip_array:
            newest_ip = max(self.ip_array)
            self.ip = newest_ip[:10]+str(int(newest_ip[10:])+1)
            return self.ip

        else:
            return "192.168.1.1"  # First ip in the network

    def username_broadcast_response(self, packet):
        print("Sending response to the username broadcast request...")
        print(self.ip)
        response_packet = Ether(dst=packet[Ether].src) / Raw(load=(self.ip+":"+self.username+":").encode('utf-8'))
        print("response packet: ", response_packet.show())
        sendp(response_packet, iface=self.iface)

    def analyze_blocked_list_packets(self, packet):
        if packet.haslayer(Ether) and packet.haslayer(Raw) and packet[Ether].src != self.mac and packet[Ether].dst == self.mac:
            if pickle.loads(packet[Raw].load):
                self.blocked_list = pickle.loads(packet[Raw].load)

    def request_blocked_list(self):
        print("Requesting the Blocked list...")
        broadcast_packet = Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff", type=0x9003)
        sendp(broadcast_packet, iface=self.iface)
        sniff(iface=self.iface, prn=self.analyze_blocked_list_packets, timeout=4, count=1)
        print("Blocked list: ", self.blocked_list)
        return self.blocked_list

    def send_blocked_list(self, packet, blocked_list):
        print("Sending blocked list to the username broadcast request...")
        blocked_list_packet = Ether(dst=packet[Ether].src) / Raw(load=pickle.dumps(blocked_list))
        print("Sending blocked list: ", blocked_list)
        sendp(blocked_list_packet, iface=self.iface)
