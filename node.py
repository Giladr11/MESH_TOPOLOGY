import ipaddress
import os.path
from scapy.layers.inet import *
from scapy.all import *
from scapy.layers.l2 import ARP
import tkinter as tk
from tkinter import Button, ttk, font
from PIL import Image, ImageTk
import pyttsx3
from ip_mac_config import IP_Mac_Config
from abc import ABC, abstractmethod
from Registration_Manager import Registration_Manager
from IPS_Manager import IPS_Manager


LOGIN_SCREEN_TITLE = "Welcome to MeshTalk!"
LOGIN_SCREEN_WIDTH = '600'
LOGIN_SCREEN_HEIGHT = '450'
LOGIN_SCREEN_BG = "login_bg.png"
INITIAL_SEQ = random.randint(0, 4294967296)  # The Range Of Sequence Numbers
SYN_FLAG = 'S'
ACK_FLAG = 'A'
FIN_FLAG = 'F'
ETH_INTERFACE = "Ethernet"  # The Ethernet Interface
DEFAULT_PORT = 65000  # Default Port Number For All Devices


class Login_Screen:
    def __init__(self, first_screen):
        IP_Mac_Config(None).set_dhcp_mode()
        if os.path.exists('user_db.json'):
            os.remove('user_db.json')
        if os.path.exists('known_usernames.txt'):
            os.remove('known_usernames.txt')

        self.first_screen = first_screen
        self.first_screen.title(LOGIN_SCREEN_TITLE)
        self.first_screen.geometry(LOGIN_SCREEN_WIDTH+'x'+LOGIN_SCREEN_HEIGHT)

        self.login_background_image = Image.open(LOGIN_SCREEN_BG)
        self.login_background_photo = ImageTk.PhotoImage(self.login_background_image)
        self.login_background_label = tk.Label(first_screen, image=self.login_background_photo)
        self.login_background_label.place(relwidth=1, relheight=1)

        self.welcome_label = tk.Label(first_screen
                                      , text=LOGIN_SCREEN_TITLE
                                      , font=("Comic Sans MS", 25)
                                      , bg='black'
                                      , foreground='blue')

        self.welcome_label.pack(pady=(50, 10))

        self.username_label = tk.Label(first_screen
                                       , text="Choose a Username:"
                                       , font=("Comic Sans MS", 17, 'bold')
                                       , bg='black'
                                       , foreground='yellow')
        self.username_label.pack(pady=(65, 10))

        self.username_entry = tk.Entry(first_screen
                                       , font=("verdana", 14)
                                       , bg='light yellow'
                                       , foreground='black')

        self.username_entry.pack(pady=(20, 10))

        self.press_enter_label = tk.Label(first_screen
                                          , text="Press Enter to connect to MeshTalk..."
                                          , font=("Comic Sans MS", 15)
                                          , bg='black'
                                          , foreground='white')

        self.press_enter_label.pack(pady=(20, 10))

        self.response_label = tk.Label(first_screen
                                       , text=""
                                       , font=("Comic Sans MS", 15)
                                       , bg='black')

        self.first_screen.bind('<Return>', lambda event: self.check_username())

    def switch_to_chat(self, new_ip):
        username = self.username_entry.get()
        self.first_screen.destroy()

        main_screen = tk.Tk()
        Application(main_screen, username, new_ip)
        main_screen.mainloop()

    def check_username(self):
        if self.username_entry.get() == "":
            self.response_label.config(text="You Must Choose a Username!"
                                       , foreground='red'
                                       , font=("Comic Sans MS", 16))

            self.response_label.place(x=153, y=370)
            self.first_screen.update_idletasks()

            pyttsx3.speak("You Must Choose a Username!")

        else:
            registration_manager = Registration_Manager(self.username_entry.get(), ETH_INTERFACE)

            self.response_label.config(
                text=f"Checking the username: '{self.username_entry.get()}'..."
                , foreground='light blue'
                , font=("Comic Sans MS", 16))

            self.response_label.place_forget()
            self.response_label.place(x=156, y=370)
            self.first_screen.update_idletasks()
            pyttsx3.speak(f"Checking the username: '{self.username_entry.get()}'")

            username_status = registration_manager.check_username()

            if username_status is True:
                self.response_label.config(text=f"The username '{self.username_entry.get()}' is already taken..."
                                           , foreground='red'
                                           , font=("Comic Sans MS", 16))

                self.response_label.place_forget()
                self.response_label.place(x=140, y=370)
                self.first_screen.update_idletasks()
                pyttsx3.speak(f"The username {self.username_entry.get()} is already taken...")

            else:
                blocked_list = registration_manager.request_blocked_list()
                if blocked_list:
                    ips_manager.blocked_nodes = blocked_list

                new_ip = registration_manager.assign_ip()
                print("my new ip is: ", new_ip)

                self.response_label.config(text=f"Connecting to the Chat as '{self.username_entry.get()}'..."
                                           , foreground='green'
                                           , font=("Comic Sans MS", 16))

                self.response_label.place_forget()
                self.response_label.place(x=140, y=370)
                self.first_screen.update_idletasks()

                pyttsx3.speak(f"Connecting to the Chat as {self.username_entry.get()}...")

                self.switch_to_chat(new_ip)


class Connections(ABC):
    def __init__(self, username, ip):
        self.ip_mac_conifg = IP_Mac_Config(ip)
        self.registerion_manager = Registration_Manager(username=username, iface=ETH_INTERFACE, ip=ip)
        self.username = username
        self.eth_interface = ETH_INTERFACE
        self.src_ip = self.ip_mac_conifg.set_new_ip()
        # self.src_ip = "192.168.1.1"
        self.src_mac = self.ip_mac_conifg.get_src_mac()
        self.port = DEFAULT_PORT
        self.nodes_dict = {}  # (ip, mac) : [username, seq, ack]
        print("src ip:", self.src_ip)
        print("src mac is:", self.src_mac)
        print("my username is: ", self.username)

    # Finding all the devices Connected to the Hub
    def arp_scan(self):
        try:
            net = ipaddress.ip_network('192.168.1.0/24')

            # ARP Scanning
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x0806) / ARP(pdst=str(net))
            answered, unanswered = srp(arp_request, timeout=2, iface=self.eth_interface, retry=2)

            for send, receive in answered:
                if receive.psrc != self.src_ip:
                    self.nodes_dict[receive.psrc, receive.hwsrc] = [None, 0, 0]

        except Exception as e:
            print(e)

    def connect(self):
        count = 1
        for user_ip, user_mac in self.nodes_dict.keys():
            try:
                print(f"node {count}: ({user_ip},{user_mac})")

                syn_packet = (Ether(src=self.src_mac, dst=user_mac)
                              / IP(src=self.src_ip, dst=user_ip)
                              / TCP(sport=self.port
                                    , dport=self.port
                                    , flags=SYN_FLAG
                                    , seq=INITIAL_SEQ
                                    , ack=0))

                print("syn_packet: (syn/ack)", syn_packet[TCP].seq, syn_packet[TCP].ack)

                syn_ack_packet = srp1(syn_packet, iface=self.eth_interface)

                print("syn_ack_packet: (syn/ack)", syn_ack_packet[TCP].seq, syn_ack_packet[TCP].ack)

                ack_packet = (Ether(src=self.src_mac, dst=user_mac)
                               / IP(src=self.src_ip, dst=user_ip)
                              / TCP(sport=self.port
                                    , dport=self.port
                                    , flags=ACK_FLAG
                                    , seq=syn_ack_packet[TCP].ack
                                    , ack=syn_ack_packet[TCP].seq + 1))

                print("ack_packet: (syn/ack)", ack_packet[TCP].seq, ack_packet[TCP].ack)

                #  The user sends me a packet with his username
                node_username_packet = srp1(ack_packet, iface=self.eth_interface)
                print("received username packet. sending my username packet..")
                node_username = node_username_packet[Raw].load.decode('utf-8')
                print(f"the user's username is {node_username}")

                #  sending the user an acknowledgment packet with my username
                response_ack_packet = (Ether(src=self.src_mac, dst=user_mac)
                                                / IP(src=self.src_ip, dst=user_ip)
                                                / TCP(sport=self.port, dport=self.port
                                                      , flags=ACK_FLAG
                                                      , seq=node_username_packet[TCP].ack
                                                      , ack=node_username_packet[TCP].seq + len(node_username))
                                                / Raw(load=self.username.encode('utf-8')))

                sendp(response_ack_packet, iface=self.eth_interface)

                result_seq = response_ack_packet[TCP].seq
                result_ack = response_ack_packet[TCP].ack

                print("end of establishing connection seq including username transfers: ", result_seq)
                print("end of establishing connection ack including username transfers: ", result_ack)

                self.nodes_dict[(user_ip, user_mac)] = [node_username, result_seq, result_ack]

                print("Finished establishing a connection!!")
                print(self.nodes_dict)

            except Exception as e:
                print(e)

    def inc_seq_ack(self, new_seq, new_ack, user_ip, user_mac):
        self.nodes_dict[(user_ip, user_mac)][1] = new_seq
        self.nodes_dict[(user_ip, user_mac)][2] = new_ack

    def syn_ack_replay(self, syn_packet):
        try:
            print("someone is establishing a connection with you. Sending a syn_ack packet...")
            syn_ack_packet = (Ether(src=self.src_mac, dst=syn_packet[Ether].src)
                              / IP(src=self.src_ip, dst=syn_packet[IP].src)
                              / TCP(sport=syn_packet[TCP].dport
                                    , dport=syn_packet[TCP].sport
                                    , flags=SYN_FLAG + ACK_FLAG
                                    , seq=INITIAL_SEQ
                                    , ack=syn_packet[TCP].seq + 1))

            print("syn_packet (seq,ack) ", syn_packet.seq, syn_packet.ack)
            print("syn_ack_packet (seq,ack) ", syn_ack_packet.seq, syn_ack_packet.ack)

            ack_packet = srp1(syn_ack_packet, iface=self.eth_interface)

            print("received ack sending username packet..")
            print("ack_packet (seq,ack) ", ack_packet.seq, ack_packet.ack)

            username_packet = (Ether(src=self.src_mac, dst=ack_packet[Ether].src)
                              / IP(src=self.src_ip, dst=ack_packet[IP].src)
                              / TCP(sport=ack_packet[TCP].dport
                                    , dport=ack_packet[TCP].sport
                                    , flags=''
                                    , seq=ack_packet[TCP].ack
                                    , ack=ack_packet[TCP].seq)
                              / Raw(load=self.username.encode('utf-8')))

            node_username_ack_packet = srp1(username_packet, iface=self.eth_interface)
            print("received username packet...")

            node_username = node_username_ack_packet[Raw].load.decode('utf-8')
            print(f"the user's username is {node_username}")

            user_mac = node_username_ack_packet[Ether].src
            user_ip = node_username_ack_packet[IP].src

            seq = node_username_ack_packet[TCP].ack
            ack = node_username_ack_packet[TCP].seq + len(node_username)

            self.nodes_dict[user_ip, user_mac] = [node_username, seq, ack]
            print(self.nodes_dict)

            self.display_connect(node_username)

        except Exception as e:
            print(e)

    # Sends ack response to data packets
    def send_ack_response(self, data_packet):
        try:
            ack_respone_packet = (Ether(src=self.src_mac, dst=data_packet[Ether].src)
                                  / IP(src=self.src_ip, dst=data_packet[IP].src)
                                  / TCP(sport=self.port, dport=self.port
                                        , flags=ACK_FLAG, seq=data_packet[TCP].ack
                                        , ack=data_packet[TCP].seq + len(data_packet[Raw].load.decode('utf-8'))))

            print("sending ack response packet...")
            sendp(ack_respone_packet, iface=self.eth_interface)

            self.nodes_dict[data_packet[IP].src, data_packet[Ether].src][1] = ack_respone_packet[TCP].seq
            self.nodes_dict[data_packet[IP].src, data_packet[Ether].src][2] = ack_respone_packet[TCP].ack

        except Exception as e:
            print(e)

    def send_private_message(self, payload, username):
        try:
            user_ip, user_mac = next(((key[0], key[1])
                                      for key, value in self.nodes_dict.items()
                                      if value[0] == username))

            saved_seq, saved_ack = self.nodes_dict[user_ip, user_mac][1:]

            data_packet = (Ether(src=self.src_mac, dst=user_mac)
                           / IP(src=self.src_ip, dst=user_ip)
                           / TCP(sport=self.port, dport=self.port
                                 , seq=saved_seq, ack=saved_ack,
                                 flags='')
                           / Raw(load=payload.encode('utf-8')))

            print("Sending a data packet...")
            user_ack_packet = srp1(data_packet, iface=self.eth_interface, verbose=True, timeout=3)
            if user_ack_packet:
                print("the ack packet flag is: ", user_ack_packet[TCP].flags)

                self.inc_seq_ack(user_ack_packet[TCP].ack, user_ack_packet[TCP].seq, user_ip, user_mac)

        except Exception as e:
            print(e)

    def send_broadcast_message(self, payload):
        for user_ip, user_mac in self.nodes_dict.keys():
            try:
                username = self.nodes_dict[user_ip, user_mac][0]
                self.send_private_message(payload, username)

            except Exception as e:
                print(e)

    def disconnect(self):
        for user_ip, user_mac in self.nodes_dict.keys():
            try:
                saved_seq, saved_ack = self.nodes_dict[user_ip, user_mac][1:]

                fin_packet = (Ether(src=self.src_mac, dst=user_mac)
                               / IP(src=self.src_ip, dst=user_ip)
                               / TCP(sport=self.port, dport=self.port
                                     , seq=saved_seq, ack=saved_ack,
                                     flags=FIN_FLAG + ACK_FLAG))

                print("Sending a Fin packet...")
                sendp(fin_packet, iface=self.eth_interface, verbose=True)

            except Exception as e:
                print(e)

    @abstractmethod
    def update_nodes_list(self):
        pass

    @abstractmethod
    def display_message(self, message, message_type):
        pass

    @abstractmethod
    def display_connect(self, username):
        pass

    @abstractmethod
    def display_disconnect(self):
        pass

    @abstractmethod
    def receive_message(self, message, node):
        pass

    def handle_received_packets(self, packet):
        if packet.haslayer(Ether) and packet[Ether].dst == "ff:ff:ff:ff:ff:ff" and packet[Ether].src != self.src_mac:
            if packet[Ether].type == 0x9001:
                self.registerion_manager.username_broadcast_response(packet)

            elif packet[Ether].type == 0x9002 and packet.haslayer(Raw):
                blocked_mac = packet[Raw].load.rstrip(b'\x00').decode('utf-8')
                print(f"Received Block Broadcast packet.. Blocking the mac addr: {blocked_mac}")
                if blocked_mac not in ips_manager.blocked_nodes:
                    ips_manager.block_node(blocked_mac)

            elif packet[Ether].type == 0x9003:
                print("Received Blocked List Request.. Sending response...")
                print("Before calling the send function Blocked nodes list: ", ips_manager.blocked_nodes)
                self.registerion_manager.send_blocked_list(packet, ips_manager.blocked_nodes)

        elif packet.haslayer(Ether) and packet.haslayer(UDP) and packet[Ether].src != self.src_mac:
            if ips_manager.detect_udp_flood(packet) and packet[Ether].src not in ips_manager.blocked_nodes:
                print(f"A UDP flood Attack was Detected from the Mac Address: '{packet[Ether].src}'!")
                ips_manager.block_node(packet[Ether].src)
                if self.nodes_dict:
                    print("Sending Block Broadcast Packet...")
                    ips_manager.send_block_broadcast(packet[Ether].src)

        elif packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].sport == DEFAULT_PORT and packet[IP].src != self.src_ip:
            if packet[TCP].flags == SYN_FLAG:
                self.syn_ack_replay(packet)
                print("Adding the new username to the nodes_listbox")
                self.update_nodes_list()

            elif packet.haslayer(Raw) and packet[TCP].flags != ACK_FLAG:
                crafted_message = packet[Raw].load.decode('utf-8')
                self.send_ack_response(packet)
                node_username = self.nodes_dict[(packet[IP].src, packet[Ether].src)][0]
                print(f"the message from {node_username} is: ", packet[Raw].load.decode('utf-8'))
                self.receive_message(crafted_message, node_username)

            elif packet[TCP].flags == ACK_FLAG:
                new_seq = packet[TCP].ack
                new_ack = packet[TCP].seq + 1
                user_ip = packet[IP].src
                user_mac = packet[Ether].src
                self.inc_seq_ack(new_seq, new_ack, user_ip, user_mac)

            elif FIN_FLAG in packet[TCP].flags:
                print("Received a Fin packet. Removing from the devices dictionary...")
                del self.nodes_dict[packet[IP].src, packet[Ether].src]
                print("devices dict: ", self.nodes_dict)
                self.display_disconnect()
                self.update_nodes_list()

    @staticmethod
    def custom_filter(packet):
        return packet[Ether].src not in ips_manager.blocked_nodes

    def receive(self):
        sniff(lfilter=self.custom_filter, iface=self.eth_interface, prn=self.handle_received_packets)


class Application(Connections):
    def __init__(self, main_screen, username, ip):
        Connections.__init__(self, username, ip)
        self.username = username
        self.chat_screen = main_screen
        self.chat_screen.title("MeshTalk")
        self.chat_screen.protocol("WM_DELETE_WINDOW", self.on_close)

        self.bg_color = 'sky blue'

        print("starting arp scan")
        self.arp_scan()
        print("finished arp scan")

        print(f"the nodes: {self.nodes_dict}")

        # Configure the main window
        self.chat_screen.geometry('900x600')
        self.chat_screen.minsize(600, 400)
        self.chat_screen.config(bg=self.bg_color)
        self.chat_screen.resizable(True, True)

        self.chat_history = {}
        self.connected_nodes = []
        self.active_chat = None
        self.unread_messages = {}

        # Styling configurations
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('InputFrame.TFrame', background='light gray')
        self.style.configure('EmojiPanel.TFrame', background='light gray')

        # Create PanedWindow
        self.paned_window = ttk.PanedWindow(self.chat_screen, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        # Left frame for nodes list
        self.left_frame = ttk.Frame(self.paned_window, width=200)
        self.paned_window.add(self.left_frame, weight=1)

        # Search entry
        self.search_entry = PlaceholderEntry(False, self.left_frame, font=('Arial', 12), relief=tk.FLAT, placeholder="Search Users...")
        self.search_entry.pack(fill=tk.X, padx=5, pady=5)
        self.search_entry.bind('<KeyRelease>', self.filter_nodes)

        # Right frame for chat display and input
        self.right_frame = ttk.Frame(self.chat_screen)
        self.paned_window.add(self.right_frame, weight=4)

        # Input area for typing messages
        self.input_frame = ttk.Frame(self.right_frame, style='InputFrame.TFrame')
        self.input_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.input_frame.grid_columnconfigure(1, weight=1)

        self.active_users_label = tk.Label(self.left_frame, text="Active Users:", font=('Arial', 12), bg='#A9CCE3',
                                           width=10)
        self.active_users_label.pack(side=tk.TOP, pady=(5, 0), fill="x")

        # Nodes listbox and scrollbar
        self.nodes_listbox = tk.Listbox(self.left_frame, height=600, bg='medium aquamarine', fg='black',
                                        selectbackground='turquoise', selectforeground='black', font=('Verdana', 14))
        self.nodes_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.nodes_listbox.bind("<<ListboxSelect>>", self.on_select_node)
        self.nodes_listbox.bind('<Motion>', self.on_hover)
        self.nodes_listbox.bind('<Leave>', self.on_leave)

        self.users_scrollbar = ttk.Scrollbar(self.left_frame, orient='vertical', command=self.nodes_listbox.yview)
        self.users_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.nodes_listbox.config(yscrollcommand=self.users_scrollbar.set)
        self.nodes_listbox.bind('<MouseWheel>', self.on_mousewheel_users_scrollbar)

        #  Profile window
        self.profile_window = None
        self.chat_screen.bind("<Unmap>", self.on_unmap_profile_window)

        self.chat_screen.bind("<Configure>", self.move_profile_window)
        self.chat_screen.bind("<Button-1>", self.check_profile_window_focus)

        self.myprofile_button = tk.Button(self.nodes_listbox, text=f"My Profile", activebackground="medium aquamarine", command=self.open_my_profile_window, width=10, bg="medium aquamarine")
        self.myprofile_button.pack(side=tk.BOTTOM, pady=(3, 0), fill='x')

        self.myprofile_button.bind("<Enter>", self.profile_button_on_motion)
        self.myprofile_button.bind("<Leave>", self.profile_button_on_motion)

        self.userprofile_button = tk.Button(self.nodes_listbox, text="", activebackground="medium aquamarine", command=self.open_user_profile_window, width=10, bg="medium aquamarine")

        self.userprofile_button.bind("<Enter>", self.profile_button_on_motion)
        self.userprofile_button.bind("<Leave>", self.profile_button_on_motion)

        # Current_node Header
        self.current_node_header = tk.Label(self.right_frame, text="There are no Connected Users yet", fg="black", bg='#FFCCCC')
        self.current_node_header.pack(side=tk.TOP, fill=tk.X)

        # Create a canvas for messages and a scrollbar
        self.canvas = tk.Canvas(self.right_frame, bg='#FDF4EE', highlightthickness=0)
        self.scrollbar = tk.Scrollbar(self.right_frame, orient='vertical', command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.bind('<MouseWheel>', self.on_mousewheel_chat_scrollbar)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.last_message_y = 5

        # Message input field
        self.message_entry = PlaceholderEntry(True, self.input_frame, font=("Ariel", 13), bg='white', placeholder="Enter a message here...")
        self.message_entry.grid(row=0, column=1, sticky='ew', padx=(5, 5), pady=(5, 5))
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.bind("<Shift-Return>", self.insert_newline)
        self.message_entry.bind("<FocusIn>", self.on_message_entry_focus)

        # Send button
        self.send_button = Button(self.input_frame, text="➤", command=lambda: self.send_message(None), bg='light gray', activebackground='light gray', font=('Arial', 17), borderwidth=0)
        self.send_button.bind("<Enter>", self.button_on_motion)
        self.send_button.bind("<Leave>", self.button_on_motion)
        self.send_button.grid(row=0, column=2, padx=(0, 5), pady=(5, 5), sticky='nsew')

        # Emoji button
        self.emoji_button = Button(self.input_frame, text="😊", command=self.open_emoji_window, bg='light gray', activebackground='light gray', font=('Arial', 13), borderwidth=0)
        self.emoji_button.bind("<Motion>", self.button_on_motion)
        self.emoji_button.bind("<Leave>", self.button_on_motion)
        self.emoji_button.bind("<Button-1>", self.button_on_motion)
        self.emoji_button.grid(row=0, column=0, padx=(5, 0), pady=(5, 5), sticky='nsew')

        self.emoji_window = None
        self.chat_screen.bind("<Unmap>", self.on_unmap_emoji_window)
        self.chat_screen.bind("<Map>", self.on_map_emoji_window)
        self.style = ttk.Style()
        self.style.theme_use('default')
        self.style.configure('Blue.TFrame', background='DeepSkyBlue4')

        self.style.configure('TNotebook.Tab'
                             , background='SteelBlue2'
                             , padding=[3, 2], font=('Helvetica', 12))

        self.style.map('TNotebook.Tab',
                       background=[('selected', 'blue')],  # Color for the active tab
                       foreground=[('selected', 'white')])

        if self.nodes_dict:
            self.connect()
            self.update_nodes_list()

        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

    def display_connect(self, node_username):
        if node_username and node_username not in self.chat_history:
            self.chat_history[node_username] = []
            self.update_nodes_list()

            if len(self.connected_nodes) == 1:
                self.nodes_listbox.select_set(0)
                self.on_select_node(None)

    def display_disconnect(self):
        selection = self.nodes_listbox.curselection()
        if selection:
            index = selection[0]
            node_username = self.nodes_listbox.get(index)
            if node_username == "Everyone":
                return
            self.connected_nodes.remove(node_username)
            del self.chat_history[node_username]
            self.nodes_listbox.delete(index)
            self.update_nodes_list()

    def on_close(self):
        self.disconnect()
        self.ip_mac_conifg.set_dhcp_mode()
        print("You have Disconnected from MeshTalk!")
        self.chat_screen.destroy()

    def update_nodes_list(self):
        self.nodes_listbox.delete(0, tk.END)
        self.connected_nodes = [node[0] for node in self.nodes_dict.values()]

        if len(self.connected_nodes) == 0:
            self.canvas.forget()
            self.userprofile_button.pack_forget()
            self.current_node_header.config(text="There are no Connected Users yet", bg="#FFCCCC")
            self.scrollbar.pack_forget()

        else:
            self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            self.userprofile_button.pack(side=tk.BOTTOM, pady=(3, 0), fill='x')
            self.userprofile_button.config(text=f"{self.active_chat}'s Profile")
            display_text = ""

            nodes_unread_count_tuple_list = [(node, self.unread_messages.get(node, 0)) for node in self.connected_nodes]

            nodes_unread_count_tuple_list.sort(key=lambda x: x[1], reverse=True)

            if len(self.connected_nodes) >= 2:
                if "Everyone" in self.unread_messages and self.unread_messages["Everyone"] > 0:
                    display_text = f"({self.unread_messages['Everyone']} unread)"

                if display_text != "":
                    self.nodes_listbox.insert(tk.END, "Everyone"+"-"+display_text)

                else:
                    self.nodes_listbox.insert(tk.END, "Everyone")

            for node, unread_count in nodes_unread_count_tuple_list:
                display_text = ""
                if node in self.unread_messages and unread_count > 0:
                    display_text = f"({unread_count} unread)"
                if display_text != "":
                    self.nodes_listbox.insert(tk.END, node+"-"+display_text)
                else:
                    self.nodes_listbox.insert(tk.END, node)
                if node == self.active_chat:
                    index = self.find_index_of_username(node)
                    if index != -1:
                        self.nodes_listbox.selection_clear(0, tk.END)
                        self.nodes_listbox.selection_set(index)
                        self.nodes_listbox.see(index)

                self.current_node_header.config(text=f"Chat with {node}", bg="#D4D6FA")

    def send_message(self, event):
        if not self.message_entry.is_placeholder() and not self.message_entry.get().isspace():
            if self.canvas.winfo_ismapped():
                node_username = self.nodes_listbox.get(tk.ACTIVE)
                message = self.message_entry.get()
                if node_username != "Everyone":
                    crafted_message = f"0:{message}"
                    if message and self.message_entry.is_placeholder() is False:
                        self.display_message(message, 'sent')
                        self.send_private_message(crafted_message, node_username)

                else:
                    crafted_message = f"1:{message}"
                    if crafted_message and self.message_entry.is_placeholder() is False:
                        self.display_message(message, 'sent')
                        self.send_broadcast_message(crafted_message)

                if node_username:
                    if node_username not in self.chat_history:
                        self.chat_history[node_username] = []
                    self.chat_history[node_username].append((message, 'sent'))
                self.message_entry.delete(0, tk.END)
                self.message_entry.put_placeholder()

    def receive_message(self, crafted_message, node_username):
        listbox_node, message = crafted_message.split(':', 1)
        final_message = node_username + ": " + message
        if listbox_node == '1':
            if "Everyone" not in self.chat_history:
                self.chat_history["Everyone"] = []

            self.chat_history["Everyone"].append((final_message, 'received'))

            if "Everyone" == self.active_chat:
                self.display_message(final_message, 'received')

            else:
                if "Everyone" in self.unread_messages:
                    self.unread_messages["Everyone"] += 1
                else:
                    self.unread_messages["Everyone"] = 1
                self.update_nodes_list()
        else:
            if node_username not in self.chat_history:
                self.chat_history[node_username] = []

            self.chat_history[node_username].append((message, 'received'))

            if node_username == self.active_chat:
                self.display_message(message, 'received')

            else:
                if node_username in self.unread_messages:
                    self.unread_messages[node_username] += 1
                else:
                    self.unread_messages[node_username] = 1
                self.update_nodes_list()

    def display_message(self, message, message_type):
        self.canvas.update_idletasks()  # Update layout to get accurate dimensions
        canvas_width = self.canvas.winfo_width()  # Get current canvas width
        pad = 5
        text_pad = 10  # Padding from edge of the canvas

        # Set colors and anchors based on the message type
        rect_color = "#DCF8C6" if message_type == 'sent' else "white"
        anchor = 'ne' if message_type == 'sent' else 'nw'

        # Define text position dynamically based on message type
        text_x = canvas_width - text_pad if message_type == 'sent' else text_pad

        # Create text with dynamic x position
        text_id = self.canvas.create_text(text_x, self.last_message_y, text=message, anchor=anchor,
                                          fill="black", font=('Arial', 11), width=280)

        # Get the bounding box of the text
        bbox = self.canvas.bbox(text_id)

        # Calculate rectangle coordinates based on message type
        if message_type == 'sent':
            rect_x1 = bbox[0] - pad  # Adjust left side of the rectangle
            rect_x2 = canvas_width - text_pad  # Right side always at the edge minus padding
        else:
            rect_x1 = text_pad  # Start directly at the padding
            rect_x2 = bbox[2] + pad  # Adjust right side of the rectangle

        # Create rectangle based on calculated coordinates
        rect_id = self.canvas.create_rectangle(rect_x1, bbox[1] - pad, rect_x2, bbox[3] + pad,
                                               outline="#DCF8C6", fill=rect_color, width=0)

        self.canvas.tag_lower(rect_id, text_id)
        self.last_message_y = bbox[3] + 15  # Move to the next line after the current message

        # Ensure the scroll region encompasses the new content
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.canvas.yview_moveto(1)

    def on_select_node(self, event):
        selection = self.nodes_listbox.curselection()
        if selection:
            index = selection[0]

            node_username = self.nodes_listbox.get(index).split('-(')[0]
            self.active_chat = node_username
            self.userprofile_button.config(text=f"{node_username}'s Profile")

            if node_username in self.unread_messages:
                self.unread_messages[node_username] = 0

            self.display_messages(node_username)
            self.update_nodes_list()
            self.current_node_header.config(text=f"Chat with {node_username}", bg="#D4D6FA")

    def message_entry_on_select_node(self, node_username):
        index = self.find_index_of_username(node_username)
        if index != -1:
            self.active_chat = node_username
            self.nodes_listbox.selection_set(index)
            self.nodes_listbox.see(index)
            self.display_messages(node_username)
            self.current_node_header.config(text=f"Chat with {node_username}", bg="#D4D6FA")

    def find_index_of_username(self, username):
        listbox_size = self.nodes_listbox.size()
        for index in range(listbox_size):
            if self.nodes_listbox.get(index) == username:
                return index
        return -1

    def on_message_entry_focus(self, event):
        self.message_entry.clear_if_placeholder()
        info = self.current_node_header['text']
        if info != "There are no Connected Users yet":
            node_username = info[len("Chat with "):]
            self.message_entry_on_select_node(node_username)

    def display_messages(self, node_username):
        self.canvas.delete("all")  # Clear the canvas
        self.last_message_y = 5  # Reset the starting y position

        if node_username in self.chat_history:
            for message, message_type in self.chat_history[node_username]:
                self.display_message(message, message_type)

    def filter_nodes(self, event):
        if self.nodes_dict:
            search_term = self.search_entry.get().strip().lower()
            self.nodes_listbox.delete(0, tk.END)

            if not search_term:
                self.update_nodes_list()
                return

            filtered_nodes = [node for node in self.connected_nodes if search_term in node.lower()]

            if filtered_nodes:
                for node in filtered_nodes:
                    self.nodes_listbox.insert(tk.END, node)
                    self.nodes_listbox.itemconfig(tk.END, {'fg': 'black'})
            else:
                self.nodes_listbox.insert(tk.END, f"No results for '{search_term}'")
                self.nodes_listbox.itemconfig(tk.END, {'fg': 'red'})

    def insert_newline(self, event):
        self.message_entry.insert(tk.INSERT, "\n")
        return "break"

    def on_mousewheel_chat_scrollbar(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def on_mousewheel_users_scrollbar(self, event):
        self.nodes_listbox.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def on_hover(self, event):
        index = self.nodes_listbox.nearest(event.y)
        if self.nodes_listbox.bbox(index):
            if event.y < self.nodes_listbox.bbox(index)[1] + self.nodes_listbox.bbox(index)[3]:
                self.reset_backgrounds()
                self.nodes_listbox.itemconfig(index, bg='turquoise')
            else:
                self.reset_backgrounds()

    def on_leave(self, event):
        self.reset_backgrounds()

    def reset_backgrounds(self):
        for i in range(self.nodes_listbox.size()):
            self.nodes_listbox.itemconfig(i, bg='medium aquamarine')

    @staticmethod
    def button_on_motion(e):
        e.widget.config(bg='light gray')

    @staticmethod
    def profile_button_on_motion(e):
        e.widget.config(bg='medium aquamarine')

    def open_my_profile_window(self):
        self.profile_window = ProfileWindow(self.left_frame, self.username, self.src_ip, self.src_mac)
        self.profile_window.mainloop()

    def open_user_profile_window(self):
        if self.active_chat and self.active_chat != "Everyone":
            node_ip, node_mac = next(((key[0], key[1])
                                      for key, value in self.nodes_dict.items()
                                      if value[0] == self.active_chat))
            print(f"Opening user_profile_window: node_ip={node_ip}, node_mac={node_mac}")
            self.profile_window = ProfileWindow(self.left_frame, self.active_chat, node_ip, node_mac)
            self.profile_window.show()

    def move_profile_window(self, event):
        if self.profile_window and self.profile_window.winfo_exists():
            left_frame_x = self.left_frame.winfo_rootx()
            left_frame_y = self.left_frame.winfo_rooty()
            left_frame_width = self.left_frame.winfo_width()
            left_frame_height = self.left_frame.winfo_height()
            self.profile_window.geometry(f"{left_frame_width}x{left_frame_height}+{left_frame_x}+{left_frame_y}")

    def check_profile_window_focus(self, event):
        if self.profile_window and self.profile_window.winfo_exists() and event.widget != self.profile_window:
            self.profile_window.lift()

    def handle_profile_restore(self, event):
        if self.chat_screen.state() == "iconic":
            self.profile_window.iconify()

    def on_unmap_profile_window(self, event):
        if self.profile_window and self.profile_window.winfo_exists():
            self.profile_window.withdraw()

    def open_emoji_window(self):
        if self.emoji_window and self.emoji_window.winfo_exists():
            self.on_close_emoji_window()
        else:
            self.emoji_window = DraggableWindow(self.chat_screen)
            self.emoji_window.attributes('-topmost', True)
            self.emoji_window.title("Emoji Panel")
            self.emoji_window.configure(bg='SlateGray2')

            tab_control = ttk.Notebook(self.emoji_window)
            emoji_categories = self.get_emoji_categories()
            for category, emojis in emoji_categories.items():
                tab = ttk.Frame(tab_control, style='Blue.TFrame')
                tab_control.add(tab, text=category)
                self.arrange_emojis_in_tabs(tab, emojis)

            tab_control.pack(expand=1, fill="both")
            self.emoji_window.protocol("WM_DELETE_WINDOW", self.on_close_emoji_window)

    def on_close_emoji_window(self):
        self.emoji_window.destroy()
        self.emoji_window = None

    def on_map_emoji_window(self, event):
        if self.emoji_window and self.emoji_window.winfo_exists():
            self.emoji_window.deiconify()

    def on_unmap_emoji_window(self, event):
        if self.emoji_window and self.emoji_window.winfo_exists():
            self.emoji_window.withdraw()

    def insert_emoji(self, emoji):
        self.message_entry.clear_if_placeholder()
        self.message_entry.insert(tk.END, emoji)

    def arrange_emojis_in_tabs(self, tab, emojis):
        for idx, emoji in enumerate(emojis):
            button = Button(tab, text=emoji, background='yellow2', font=font.Font(size=15),
                            command=lambda e=emoji: self.insert_emoji(e))
            button.grid(row=idx // 10, column=idx % 10, sticky='wens', padx=5, pady=5)

    @staticmethod
    def get_emoji_categories():
        # Simplified version with only one category for brevity
        return {
                'Smileys & Emotion': ["😀", "😃", "😄", "😁", "😆", "😅", "🤣", "😂", "🙂", "🙃", "😉", "😊", "😇", "🥰", "😍", "🤩",
                                      "😘",
                                      "😗", "😚", "😙", "😋", "😛", "😜", "🤪", "😝"],

                'People & Body': ["👋", "🤚", "🖐", "✋", "🖖", "👌", "🤏", "✌", "🤞", "🤟", "🤘", "🤙", "👈", "👉", "👆", "👇", "☝",
                                  "👍",
                                  "👎", "✊", "👊", "🤛", "🤜", "👏", "🙌"],

                'Animals & Nature': ["🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼", "🐨", "🐯", "🦁", "🐮", "🐷", "🐽", "🐸", "🐵",
                                     "🙈",
                                     "🙉", "🙊", "🐒", "🐔", "🐧", "🐦", "🐤", "🦆"],

                'Food & Drink': ["🍏", "🍎", "🍐", "🍊", "🍋", "🍌", "🍉", "🍇", "🍓", "🍈", "🍒", "🍑", "🍍", "🥭", "🥥", "🥝", "🍅",
                                 "🍆",
                                 "🥑", "🥦", "🥒", "🥬", "🥕", "🌽", "🌶"],

                'Travel & Places': ["🏠", "🏡", "🏘", "🏚", "🏠", "🏢", "🏣", "🏤", "🏥", "🏦", "🏨", "🏩", "🏪", "🏫", "🏬", "🏭", "🏯",
                                    "🏰", "💒", "🗼", "🗽", "🗿", "🏛", "🏟", "🎡"],

                'Activities': ["⚽", "🏀", "🏈", "⚾", "🥎", "🎾", "🏐", "🏉", "🎱", "🏓", "🏸", "🥅", "🏒", "🏑", "🏏", "🥍", "🏹", "🎣",
                               "🤿", "🥊", "🥋", "🎽", "🛹", "🛼", "🛶", "🧗", "🏋️", "🧗‍♂️", "🧗‍♀️", "🏋️‍♂️", "🏋️‍♀️"],

                'Objects': ["⌚", "📱", "💻", "📲", "🖥", "🖨", "⌨", "🖱", "🖲", "🕹", "🗜", "💽", "💾", "💿", "📀", "📼", "📷", "📸",
                            "📹",
                            "🎥", "🎞", "📞", "📟", "📠", "📺"],

                'Symbols': ["", "❤", "🧡", "💛", "💚", "💙", "💜", "🖤", "🤍", "🤎", "💔", "❣", "💕", "💞", "💓", "💗", "💖", "💘",
                            "💝", "💟",
                            "☮", "✝", "☪", "🕉", "☸", "✡"],

                'Flags': ["🏁", "🚩", "🎌", "🏴", "🏳", "🏴‍☠️", "🇺🇳", "🇪🇺", "🇺🇸", "🇬🇧", "🇫🇷", "🇪🇸", "🇩🇪", "🇮🇹", "🇷🇺",
                          "🇨🇳", "🇯🇵", "🇰🇷", "🇮🇳", "🇧🇷", "🇨🇦", "🇲🇽", "🇦🇺", "🇳🇿"]
            }


#  Profile Window
class ProfileWindow(tk.Toplevel):
    def __init__(self, master, username, ip, mac):
        super().__init__(master)
        self.title("Profile")
        self.overrideredirect(True)
        left_frame_x = master.winfo_rootx()
        left_frame_y = master.winfo_rooty()
        left_frame_width = master.winfo_width()
        left_frame_height = master.winfo_height()
        self.geometry(f"{left_frame_width}x{left_frame_height}+{left_frame_x}+{left_frame_y}")

        self.username = username
        self.ip = ip
        self.mac = mac

        # Slide animation
        self.slide_animation()

        # Configure background color
        self.configure(bg="aquamarine")

        # Close button
        close_button = tk.Label(self, text="❮", font=("Arial", 14), bg="gray", fg="white")
        close_button.pack(side="top", fill="x")
        close_button.bind("<Button-1>", self.close_profile)

        tk.Label(self, text="Username:", bg="aquamarine", fg="black", font=("Arial", 13)).pack()
        tk.Label(self, text=self.username, bg="aquamarine", fg="black", font=("Arial", 12)).pack()

        tk.Label(self, text="IP Address:", bg="aquamarine", fg="black", font=("Arial", 13)).pack()
        tk.Label(self, text=self.ip, bg="aquamarine", fg="black", font=("Arial", 12)).pack()

        tk.Label(self, text="MAC Address:", bg="aquamarine", fg="black", font=("Arial", 13)).pack()
        tk.Label(self, text=self.mac, bg="aquamarine", fg="black", font=("Arial", 12)).pack()

        self.bind("<FocusOut>", self.on_focus_out)

    def slide_animation(self):
        self.attributes('-alpha', 0)  # Make window transparent initially
        self.deiconify()  # Show window
        for i in range(1, 11):
            alpha = i / 10
            self.attributes('-alpha', alpha)
            self.update_idletasks()
            self.after(20)

    def on_focus_out(self, event):
        self.attributes('-topmost', True)

    def close_profile(self, event):
        self.master.profile_window = None
        self.destroy()

    def show(self):
        self.deiconify()


# Making the emoji window draggable even though it doesnt have a title bar
class DraggableWindow(tk.Toplevel):
    def __init__(self, chat_screen, **kwargs):
        super().__init__(chat_screen, **kwargs)
        self.overrideredirect(True)
        self.bind("<ButtonPress-1>", self.start_drag)
        self.bind("<B1-Motion>", self.do_drag)
        self.bind("<ButtonRelease-1>", self.stop_drag)

        self._drag_data = {"x": 0, "y": 0}

    def start_drag(self, event):
        self._drag_data["x"] = event.x
        self._drag_data["y"] = event.y

    def do_drag(self, event):
        dx = event.x - self._drag_data["x"]
        dy = event.y - self._drag_data["y"]

        x = self.winfo_x() + dx
        y = self.winfo_y() + dy

        self.geometry(f"+{x}+{y}")

    def stop_drag(self, event):
        self._drag_data["x"] = 0
        self._drag_data["y"] = 0


#  Placeholder for the message entry widget
class PlaceholderEntry(tk.Entry):
    def __init__(self, set_when_none_backspace, master=None, placeholder="Enter text here...", placeholder_color='gray', **kwargs):
        super().__init__(master, **kwargs)
        self.set_when_none_backspace = set_when_none_backspace
        self.placeholder = placeholder
        self.placeholder_color = placeholder_color
        self.default_fg_color = 'black'  # Default typing color
        self.put_placeholder()

        self.bind("<FocusIn>", self.foc_in)
        self.bind("<FocusOut>", self.foc_out)
        self.bind("<Key>", self.on_key_press)

    def put_placeholder(self):
        if not self.get().strip():
            self.delete(0, tk.END)
            self.insert(0, self.placeholder)
            self['fg'] = self.placeholder_color

    def foc_in(self, *args):
        if self['fg'] == self.placeholder_color and self.get() == self.placeholder:
            self.delete('0', 'end')
            self['fg'] = self.default_fg_color

    def foc_out(self, *args):
        if not self.get().strip():
            self.put_placeholder()

    def on_key_press(self, event):
        if self['fg'] == self.placeholder_color and self.get() == self.placeholder:
            self.delete(0, 'end')
            self['fg'] = self.default_fg_color

        if self['fg'] == self.placeholder_color and self.get() == self.placeholder:
            if event.keysym in ('Left', 'Right', 'Up', 'Down', 'Home', 'End'):
                return

            self.delete('0', 'end')
            self['fg'] = self.default_fg_color

        elif event.keysym == 'BackSpace' and self.get() == '':
            if self.set_when_none_backspace is False:
                if self.get() == self.placeholder or not self.get():
                    return
            else:
                self.after_idle(self.foc_out)

    def clear_if_placeholder(self):
        if self.get() == self.placeholder and self['fg'] == self.placeholder_color:
            self.delete(0, 'end')
            self['fg'] = self.default_fg_color

    def is_placeholder(self):
        return self.get() == self.placeholder and self['fg'] == self.placeholder_color


def main():
    root = tk.Tk()
    app = Login_Screen(root)
    root.mainloop()


if __name__ == "__main__":
    ips_manager = IPS_Manager(ETH_INTERFACE)
    main()
