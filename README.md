# Mr. Srinivas's Network Packet Analyzer Tool

## 1. Description
This repository contains the Network Packet Analyzer tool, developed as part of the Prodigy InfoTech Cybersecurity Internship (Task-05). The tool is designed to capture and analyze network packets on a given interface, providing critical insights into network traffic for educational and ethical purposes.

The tool is written in Python, utilizing Scapy, a powerful network packet manipulation library, to capture live network traffic and analyze various details about captured packets, including source and destination IP addresses, protocols (TCP, UDP), packet flags, and more.

This analyzer is ideal for educational demonstrations of packet sniffing and basic network traffic analysis, and it promotes the ethical use of network analysis tools.

## Features
- **Packet Capture**: Captures live network packets in real-time.
- **Protocol Analysis**: Identifies and displays various network protocols (TCP, UDP).
- **Detailed Information**: Shows source and destination IP addresses, protocol types, and payload data.
- **Simple and User-Friendly**: Easy to set up and use for educational purposes.

  
## 3. How to Use
Step 1 - Clone the Repository: To use the tool, first clone the repository to your local machine:
```bash
https://github.com/mr-srinivas14/PRODIGY_CS_05.git
```
Step 2 - Install Dependencies: This project relies on the following Python libraries:

- Scapy: For packet capture and analysis.
- requests: For making HTTP requests.
```bash
pip install scapy
```
Step 3 - Navigate to the Downloded Directory


Step 4 - Running the Tool: To run the tool, navigate to the repository directory and run the Python script:
```bash
sudo python3 Network Packet Analyzer.py
```

## 4. Example

Starting packet sniffer...
Source: 192.168.1.5, Destination: 192.168.1.10
Protocol: TCP, Payload: b'Some payload data'
========================================
Source: 192.168.1.10, Destination: 192.168.1.5
Protocol: UDP, Payload: b'More payload data'
========================================


**Credits:** : Developed By ```Mr Srinivas```
