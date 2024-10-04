# Mr. Srinivas's Network Packet Analyzer Tool

## 1. Description
This repository contains the Network Packet Analyzer tool, developed as part of the Prodigy InfoTech Cybersecurity Internship (Task-05). The tool is designed to capture and analyze network packets on a given interface, providing critical insights into network traffic for educational and ethical purposes.

The tool is written in Python, utilizing Scapy, a powerful network packet manipulation library, to capture live network traffic and analyze various details about captured packets, including source and destination IP addresses, protocols (TCP, UDP), packet flags, and more.

This analyzer is ideal for educational demonstrations of packet sniffing and basic network traffic analysis, and it promotes the ethical use of network analysis tools.
## 2. Features
- Live Packet Capture: Monitors a specified network interface (e.g., eth0) and captures live packets.
- Detailed Packet Analysis:
  1. Source and Destination IP addresses.
  2. Protocols used (TCP, UDP).
  3. TCP-specific details such as flags, sequence numbers, acknowledgment numbers.
  4. UDP-specific details such as source/destination ports, checksum, and length.
- Domain Information Lookup: Allows the user to lookup WHOIS information for a given domain, providing domain registrar details, IP addresses, name servers, and more.
- Menu-driven Interface: Simple and intuitive command-line interface to choose between packet capture, domain information lookup, or exiting the tool.

  
## 3. How to Use
Step 1- Clone the Repository: To use the tool, first clone the repository to your local machine:
```bash
https://github.com/mr-srinivas14/PRODIGY_CS_05.git
```
Step 2- Install Dependencies: This project relies on the following Python libraries:

- Scapy: For packet capture and analysis.
- requests: For making HTTP requests.
- whois: For performing WHOIS lookups. Install the required dependencies using pip:
```bash
pip install scapy requests whois
```
Step 3- Running the Tool: To run the tool, navigate to the repository directory and run the Python script:
```bash
python3 NetworkPacketAnalyzer.py
```
Menu Options:

1. Capture and Analyze Packets: Choose this option to start live packet sniffing on the network.
2. Domain Information Lookup: Use this option to get WHOIS details for a domain.
3. Exit: Closes the tool.

## 4. Example
1. Packet Capture: When running the tool and choosing the packet capture option, the tool captures live packets from the network and displays detailed information for each captured packet.
- Sample Output:
```bash
Packet captured: 192.168.1.10 -> 192.168.1.1, Protocol: TCP
   - Source Port: 443
   - Destination Port: 80 (HTTP)
   - Sequence Number: 123456789
   - Acknowledgment Number: 987654321
   - Flags: SYN, ACK

Packet captured: 192.168.1.10 -> 8.8.8.8, Protocol: UDP
   - Source Port: 49152
   - Destination Port: 53 (DNS)
   - Length: 60
   - Checksum: 0xABCD
```
2. Domain Information Lookup: Using the domain information lookup, the user can retrieve important domain information such as Domain name, IP address, Registrar, Name servers, and Domain creation and expiration dates.
- Sample Output:
```bash
Fetching domain info for: github.com
Domain: ['GITHUB.COM', 'github.com']
IP Address: 20.207.73.82
Registrar: MarkMonitor, Inc.
Creation Date: 2007-10-09 18:20:50
Expiration Date: [datetime.datetime(2026, 10, 9, 18, 20, 50), datetime.datetime(2026, 10, 9, 0, 0)]
Name Servers: DNS1.P08.NSONE.NET, DNS2.P08.NSONE.NET, DNS3.P08.NSONE.NET, DNS4.P08.NSONE.NET, NS-1283.AWSDNS-32.ORG, NS-1707.AWSDNS-21.CO.UK, NS-421.AWSDNS-52.COM, NS-520.AWSDNS-01.NET, ns-421.awsdns-52.com, ns-1283.awsdns-32.org, dns4.p08.nsone.net, dns2.p08.nsone.net, ns-1707.awsdns-21.co.uk, dns1.p08.nsone.net, dns3.p08.nsone.net, ns-520.awsdns-01.net
```

**Credits:** : Developed By ```Mr Srinivas```
