import subprocess
from scapy.arch import get_if_hwaddr


class IP_Mac_Config:
    def __init__(self, ip):
        self.ip = ip

    def set_new_ip(self):
        print(f"Setting the ip: {self.ip}")

        subprocess.run(["netsh", "interface", "ip", "add", "address", "Ethernet", self.ip, "255.255.255.0"],
                           check=True)

        print(f"successfully set IP address {self.ip}")
        return self.ip

    @staticmethod
    def set_dhcp_mode():
        try:
            subprocess.run(["netsh", "interface", "ip", "set", "address", "Ethernet", "dhcp"], check=True)
            print("Switched to DHCP successfully.")

        except Exception as e:
            print(f"Failed to switch to DHCP: {e}")

    def get_src_mac(self):
        return get_if_hwaddr("Ethernet")
