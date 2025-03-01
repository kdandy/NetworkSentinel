# NetworkSentinel - AI-Powered Network Sniffing & Exploitation

![Network Sentinel](https://img.shields.io/badge/Status-Active-brightgreen) ![Python](https://img.shields.io/badge/Python-3.x-blue) ![License](https://img.shields.io/badge/License-MIT-yellow)

## Overview
NetworkSentinel is an advanced **real-time network packet analyzer and exploitation framework** powered by **AI**.  
It enables **live traffic monitoring**, **AI-based data classification**, and **automated attacks** such as ARP Spoofing and MITM.

## Features
- **Live Packet Sniffing** – Captures network packets in real-time.
- **AI-Powered Analysis** – Uses machine learning to classify sensitive network traffic.
- **CNAME & WHOIS Checks** – Identifies misconfigured domains and expired services.
- **Cloudflare Protection Detection** – Checks if a subdomain is protected by Cloudflare.
- **Network Exploitation** – Includes **ARP Spoofing & MITM attacks** for security testing.

## Installation
### **Prerequisites**
- **Python 3.x**
- **Pip & Virtual Environment**
- **Admin Privileges (for network sniffing & attacks)**

### **Setup**
Clone the repository and set up the virtual environment:
```sh
git clone https://github.com/kdandy/NetworkSentinel.git
cd NetworkSentinel
```

### Create and activate virtual environment
```sh
python3 -m venv .venv
source .venv/bin/activate  # On macOS/Linux
.venv\Scripts\activate     # On Windows
```

### Install dependencies
```sh
pip install -r requirements.txt
```

## Usage
Run the tool with **root privileges** for network sniffing:
```sh
sudo python3 NetworkSentinel.py
```

### **Command Options**
1. **Sniff Network Traffic**  
   ```sh
   sudo python3 NetworkSentinel.py
   ```
   - Captures packets in real-time.

2. **Analyze Packets with AI**  
   Inside the program, type:
   ```sh
   analyze
   ```
   - AI classifies sensitive packets.

3. **Launch ARP Spoofing Attack**  
   Inside the program, type:
   ```sh
   arp_spoof
   ```
   - Enter **Target IP** & **Gateway IP** for a MITM attack.

4. **Exit the Program**  
   ```sh
   exit
   ```

## 📊 Example Output
| 🌐 Source IP | 🎯 Destination IP | ⚠️ Protocol | 🔍 AI Risk Level |
|-------------|------------------|------------|------------------|
| 192.168.1.10 | 192.168.1.1 | TCP | 🔴 High |
| 192.168.1.12 | 8.8.8.8 | UDP | 🟢 Low |
| 192.168.1.14 | 192.168.1.100 | TCP | 🟡 Medium |

## ⚠️ Disclaimer
This tool is intended for **educational and security research purposes only**.  
Unauthorized use on networks you do not own **is illegal**.

## 📜 License
📝 Licensed under the **MIT License**.
