import scapy.all as scapy
import requests
from scapy.layers.inet import IP
import whois
import socket
import time

def print_header():
    header = """
 _______          __                       __     __________               __           __       _____                .__                              
 \\      \\   _____/  |___  _  _____________|  | __ \\______   \\____    ____ |  | __ _____/  |_    /  _  \\   ____ _____  |  | ___.__.________ ___________ 
 /   |   \\_/ __ \\   __\\ \\/ \\/ /  _ \\_  __ \\  |/ /  |     ___|__  \\ _/ ___\\|  |/ // __ \\   __\\  /  /_\\  \\ /    \\\\__  \\ |  |<   |  |\\___   // __ \\_  __ \\
/    |    \\  ___/|  |  \\     (  <_> )  | \\/    <   |    |    / __ \\\\  \\___|    <\\  ___/|  |   /    |    \\   |  \\/ __ \\|  |_\\___  | /    /\\  ___/|  | \\/
\\____|__  /\\___  >__|   \\/\\_/ \\____/|__|  |__|_ \\  |____|   (____  /\\___  >__|_ \\\\___  >__|   \\____|__  /___|  (____  /____/ ____|/_____ \\\\___  >__|   
        \\/     \\/                              \\/                \\/     \\/     \\/    \\/               \\/     \\/     \\/     \\/           \\/    \\/        
    """
    print(header)
    print("="*80)
    print("Welcome to the Enhanced Network Packet Analyzer.")
    print("Features:")
    print("- Capture and analyze packets.")
    print("- Domain information lookup (with IP address and WHOIS info).")
    print("="*80)


def start_sniffing():
    """Capture packets and analyze them."""
    def process_packet(packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            
            # Additional details for TCP and UDP
            if packet.haslayer(scapy.TCP):
                tcp_layer = packet[scapy.TCP]
                print(f"Packet captured: {ip_src} -> {ip_dst}, Protocol: TCP")
                print(f"   - Source Port: {tcp_layer.sport}")
                print(f"   - Destination Port: {tcp_layer.dport}")
                print(f"   - Sequence Number: {tcp_layer.seq}")
                print(f"   - Acknowledgment Number: {tcp_layer.ack}")
                print(f"   - Flags: {tcp_layer.flags}")
            elif packet.haslayer(scapy.UDP):
                udp_layer = packet[scapy.UDP]
                print(f"Packet captured: {ip_src} -> {ip_dst}, Protocol: UDP")
                print(f"   - Source Port: {udp_layer.sport}")
                print(f"   - Destination Port: {udp_layer.dport}")
                print(f"   - Length: {len(packet)}")
                print(f"   - Checksum: {udp_layer.chksum}")

    print("Starting packet capture...")
    scapy.sniff(prn=process_packet)


def get_domain_info(domain):
    """Fetch domain-related information using WHOIS and get the domain's IP address."""
    try:
        print(f"Fetching domain info for: {domain}")
        # Perform WHOIS lookup
        domain_info = whois.whois(domain)

        # Retrieve IP address
        ip_address = socket.gethostbyname(domain)

        # Print domain details
        print(f"Domain: {domain_info.domain_name}")
        print(f"IP Address: {ip_address}")
        print(f"Registrar: {domain_info.registrar}")
        print(f"Creation Date: {domain_info.creation_date}")
        print(f"Expiration Date: {domain_info.expiration_date}")
        print(f"Name Servers: {', '.join(domain_info.name_servers)}")
    except socket.gaierror:
        print("Error: Could not resolve the domain IP address.")
    except Exception as e:
        print(f"Could not retrieve information for this domain: {e}")


def main():
    print_header()

    while True:
        print("\nSelect an option:")
        print("1. Capture and analyze packets.")
        print("2. Domain information lookup.")
        print("3. Exit.")

        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            start_sniffing()

        elif choice == '2':
            domain = input("Enter the domain name (e.g., example.com): ")
            get_domain_info(domain)

        elif choice == '3':
            print("Exiting the program. Goodbye!")
            break

        else:
            print("Invalid choice. Please select a valid option.")


if __name__ == "__main__":
    main()