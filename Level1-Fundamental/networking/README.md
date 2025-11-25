# 🌐 Networking - Invisible Infrastructure

## 🔍 Apa Itu Networking?

Networking adalah hubungan antar devices untuk berbagi resources dan informasi. Dalam cyber security, networking adalah pondasi untuk understanding attacks dan defenses.

**Mengapa Critical:**
- 80% attacks berbasis network (scanning, injection)
- Understanding routers, switches, firewalls
- Basis untuk protocol analysis dan traffic inspection

## 🔗 TCP/IP Stack Deep Dive

### Nakshatran Suite vs OSI Model
TCP/IP adalah practical standard yang digunakan real world. Tidak lebih baik dari OSI, tapi lebih simple.

### TCP/IP Architecture
```
Application Layer (HTTP, FTP, SSH)
↕️
Transport Layer (TCP/UDP)
↕️
Internet Layer (IP, ICMP, ARP, RARP)
↕️
Network Access/Physical Layer (Ethernet, WiFi)
```

### TCP vs UDP Decision
- **TCP:** Reliable, connection-oriented, ordered delivery
- **UDP:** Fast, connectionless, best-effort delivery

### TCP 3-Way Handshake (Dijk Windows)
1. **SYN:** Active open, ISN sequence number
2. **SYN+ACK:** Passive open, acknowledge ISN
3. **ACK:** Connection established dengan window size

**Why important:**
- Detects port scanning (nmap stealth scan)
- Understands session hijacking
- Basis untuk firewall rules

**Capture analysis:** `tcpdump -i eth0 tcp port 80 -w capture.pcap`

## 📡 IP Addressing & Subnetting Mastery

### IPv4 Structure
- 32 bits: 192.168.1.1
- Classes: A (0xxx), B (10xx), C (110x), etc.
- CIDR: 192.168.1.0/24 (24 bits network)

### Subnetting Formula
```
Network Bits = CIDR prefix
Host Bits = 32 - Network Bits
Hosts Available = 2^(32-N) - 2

Example /24:
Network Bits = 24, Host Bits = 8
Hosts = 2^8 - 2 = 256 - 2 = 254 hosts
```

### IPv4 Exhaustion Problems
- NAT (Network Address Translation)
- CIDR (Classless Inter-Domain Routing)
- IPv6 transition

## ☎️ DNS - Domain Name System

### DNS Resolution Chain
```
Browser Cache → OS Cache → Router → ISP DNS → Root Servers
                           ↓
                    TLD Servers (*.com) → Authoritative Servers
```

### DNS Record Types
- **A:** IPv4 address (host → IP)
- **AAAA:** IPv6 address
- **CNAME:** Canonical name (alias)
- **MX:** Mail exchange
- **TXT:** Text records (SPF, DKIM)
- **NS:** Name server
- **PTR:** Reverse DNS (IP → hostname)

### DNS Attacks Awareness
- **DNS Spoofing:** Fake DNS responses
- **DNS Cache Poisoning:** Pollute resolver cache
- **NXDOMAIN Flood:** DDoS terhadap DNS
- **DNS Rebinding:** Change IP after DNS lookup

### DNS Tools Mastery
```bash
nslookup google.com            # Basic lookup
dig google.com A               # Specific record
host google.com                # Simple reverse
dnsrecon -d google.com         # Comprehensive enum
dnsbrute -t target.com -w wordlist  # Brute subdomain
```

## 🔒 Firewalls & Network Security

### Firewall Categories
- **Package Filtering:** IP/port based filtering
- **Stateful Inspection:** Connection tracking
- **Application Layer:** Deep packet inspection
- **Next-Gen Firewall (NGFW):** Threat intelligence

### Fortigate/Sophos Understanding
**Fortigate UTM Features:**
- Intrusion Prevention System (IPS)
- Web filtering
- Antivirus & malware protection
- SSL inspection
- VPN capabilities

### iptables Command Structure
```bash
iptables -A CHAIN -i interface -p protocol --dport port -j ACTION

# Chains:
# INPUT: packets coming into machine
# OUTPUT: packets going out from machine
# FORWARD: packets being routed (routers)

# Example rule:
iptables -A FORWARD -s 192.168.1.0/24 -d 10.0.0.0/8 -j DROP
```

### Stateful Tracking
- Tracks connection states: NEW, ESTABLISHED, RELATED, INVALID
- Allows complex rules seperti FTP passive mode

## 📊 Network Analysis & Troubleshooting

### ICMP Beyond Ping
```bash
ping -c 4 -s 2000 target.com    # Oversized ping (MTU test)
ping -p ff target.com           # Ping of death (old vuln)
```

**ICMP Types:**
- Echo (ping): 8 Request, 0 Reply
- Time ExCEEDED: 11 (traceroute)
- Destination Unreachable: 3
- Parameter Problem: 12
- Source Quench: 4

### Traceroute Variants
```bash
traceroute google.com              # Standard UDP
tracert google.com                 # Windows
mtr google.com                     # Better traceroute
tcptraceroute -s 53 google.com     # TCP traceroute
```

### ARP Protocol Mastery
- Maps IP ke MAC address
- ARP cache poisoning untuk MITM attacks
- Gratuitous ARP untuk IP takeover

```bash
arp -a                             # View ARP table
arping -c 1 192.168.1.1           # Send ARP request
```

### Wireshark Filter Examples
```
ip.src == 192.168.1.1               # Source IP
tcp.port == 80                     # Port 80
http.request.method == "POST"      # HTTP POST
tcp.flags.syn == 1 and tcp.flags.ack == 0  # SYN packets
```

## 🌍 Advanced Networking Concepts

### NAT (Network Address Translation)
**Types:**
- **Static NAT:** 1:1 permanent mapping
- **Dynamic NAT:** Pool address auto-assign
- **PAT (Port Address Translation):** Multiple IP ke satu external
- **Destination NAT:** Inbound translation

**Problem statement:** Troubleshooting nat masalah di corporate environment.

### VPN Technologies
- **Site-to-Site VPN:** Connect networks
- **Remote Access VPN:** Individual users
- **SSL VPN:** Web-based VPN
- **IPsec vs SSL VPN:** Differences dan use cases

### Wireless Networks Security
- **WEP:** Weaked, dapat cracked 5 menit
- **WPA2:** Strong encryption AES-CCMP
- **WPA3:** Dragonfly handshake
- **EAP:** Enterprise authentication

```bash
iwlist wlan0 scan                 # Scan wireless APs
aircrack-ng capture.cap -w wordlist  # Crack WEP/WPA
```

### Load Balancing & High Availability
- **DNS Round Robin:** Simple LB
- **Hardware LB:** F5 Networks devices
- **Software LB:** Nginx, HAProxy
- **Anycast:** Single IP multiple locations

## 🆔 VLAN & Network Segmentation

### VLAN Types
- **Untagged VLANs:** Standard 802.1Q
- **Tagged VLANs:** Multiple VLAN dalam satu interface
- **Native VLAN:** Default VLAN on trunk ports

### Trunk vs Access Ports
- **Access Port:** Single VLAN membership
- **Trunk Port:** Multiple VLAN traffic
- **DTP:** Dynamic Trunk Protocol (security risk)

### Inter-VLAN Routing
- Router on a stick: Subinterfaces
- Layer 3 switches: SVI (Switch Virtual Interface)
- Layer 3 routing protocols: OSPF, EIGRP

## 🔐 Network Security Controls

### 802.1X Port Security
- EAP-TLS: Certificate-based
- EAP-PEAP: Password protected
- RADIUS server integration

### DHCP Security
- MAC address reservation
- Rogue DHCP prevention
- DHCP snooping on switches

### Network Monitoring (IDS/IPS)
- **Snort:** Open-source IDS
- **Suricata:** Multi-threaded intrusion detection
- **Zeek:** Network security monitoring

## 🧮 Network Calculations

### MTU & Fragmentation
- Ethernet: 1500 bytes standard MTU
- Jumbo frames: 9000 bytes
- Path MTU Discovery: ICMP

### Throughput Calculations
- **Bandwidth:** Raw capacity (bits/second)
- **Throughput:** Actual data rate
- **Latency:** Round trip time (RTT)

### Quality of Service (QoS)
- **Classification:** Prioritize traffic types
- **Queuing:** Buffer management
- **Scheduling:** When to forward packets

## 💡 Pro Tips Networking

1. **Route Analysis:** `ip route` vs `route` vs `netstat -r`
2. **Interface Details:** `ip addr` vs `ifconfig` vs `ip link`
3. **Socket Statistics:** `ss -tulpn` vs `netstat -tulpn`
4. **Network Speed Test:** `iperf` server/client
5. **BGP Path Discovery:** `bgpstream` untuk route changes
6. **IPv6 Transition:** `SLAAC` vs `DHCPv6`
7. **Multicast Routing:** PIM sparse mode vs dense mode

## ​​🛠 Tools Networking

### Packet Craft
- **Scapy:** Python packet crafting
- **tcpreplay:** Replay captured traffic
- **packETH:** GUI packet builder

### Protocol Analysis
- **DHCP:** `dhcping`, `dhcpstarv`
- **ARP:** `arpoison`, `ettercap`
- **ICMP:** `icmpquery`, custom packets

## 📚 Advanced Resources

- **Books:** "Computer Networking: A Top-Down Approach" Kurose
- **Courses:** NetworkChuck YouTube, Piotr Mikiewicz
- **Labs:** Network Automation, GNS3 for virtual networking
- **Certifications:** CCNA, Network+, Security+

---

**Goal:** Networking bukan tentang rote learning. It's tentang understanding bagaimana information flow dan dimanipulasi. Master networking = understand war untuk fought attacks. 🔒⚡
