from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from colorama import init, Fore
# initialize colorama
init()
# define colors
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET

def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        print("Yes")
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method = packet[HTTPRequest].Method.decode()
        print(f"\n{GREEN}[+] Requested {url} with {method}{RESET}")
        print(f"\n{GREEN}{packet.summary()}")
        if packet.haslayer(Raw) and method == "POST":
            print(f"\n{RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}")
    elif packet.haslayer(DNS):
        print(packet.summary())
    elif packet.haslayer(TCP) and packet[TCP].dport == 443:
        raw_data = bytes(packet[TCP].payload)
        if raw_data.startswith(b'\x16\x03'):  # TLS handshake
            # SNI is inside Client Hello → Extension type 0x00
            try:
                server_name_index = raw_data.find(b'\x00\x00')  # Type 0 (SNI)
                if server_name_index != -1:
                    length = raw_data[server_name_index + 5]
                    hostname = raw_data[server_name_index + 6: server_name_index + 6 + length]
                    print(f"{GREEN}[+] HTTPS to: {hostname.decode(errors='ignore')}{RESET}")
            except:
                pass

if __name__ == "__main__":
    sniff(prn=process_packet, store=False)
