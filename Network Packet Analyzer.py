from scapy.all import sniff, IP, TCP, UDP, Raw

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
    print("Welcome to Mr Srinivas's Network Packet Analyzer Tool!.")
    print("- It Captures and analyze the packets.")
    print("="*80)

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source: {ip_layer.src}, Destination: {ip_layer.dst}")
        
        # Check for TCP packets
        if TCP in packet:
            print(f"Protocol: TCP, Payload: {bytes(packet[TCP].payload)}")
        
        # Check for UDP packets
        elif UDP in packet:
            print(f"Protocol: UDP, Payload: {bytes(packet[UDP].payload)}")
        
        # For other protocols
        else:
            print(f"Protocol: {packet.summary()}")
        
        print("=" * 40)

def start_sniffer():
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, filter="ip", store=0)

if __name__ == "__main__":
    print_header()
    start_sniffer()
