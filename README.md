# 🛡️ Full-Stack Security Lab: Infrastructure, Exploitation & Detection

## 📖 Projektübersicht
Dieses Projekt demonstriert den Aufbau und Betrieb eines isolierten Cyber-Security-Labors. Es umfasst die vollständige Pipeline von der sicheren Netzwerkinfrastruktur über benutzerdefinierte Aufklärungstools und manuelle Exploitation bis hin zur Implementierung eines SIEM-Systems zur Bedrohungserkennung.

---

## 🏗️ Phase 1: Infrastructure & Network Segmentation



### 1. VM Konfiguration & Firewall (OPNsense)
Die OPNsense-Firewall dient als Netzwerk-Gateway und Sicherheits-Perimeter für das Labor.
* **Ressourcen:** 2 vCPU, 4GB RAM, 30GB Disk (VirtIO).
* **Installations-Modus:** ZFS (Stripe) auf virtueller Disk (vtbd0). Bietet Integritätsprüfung und Snapshots auf Dateisystemebene (Best Practice für Firewalls).
* **Interface Mapping (Layer 2):**
  * **vtnet0 (WAN):** Verbunden mit `vmbr0` (Bridged to Physical NIC). Bezieht IP via DHCP vom Heimrouter. Simuliert den Internetzugang.
  * **vtnet1 (LAN):** Verbunden mit `vmbr1` (Isolated Linux Bridge). Dient als Gateway für alle Labor-VMs.
* **Sicherheitsaspekt:** Durch die strikte Zuweisung der Interfaces auf Kernel-Ebene ist ein "Ausbrechen" des Traffics von LAN auf WAN ohne Routing-Regel technisch unterbunden.

### 2. IP Address Management (IPAM)
* **Lab Network CIDR:** `192.168.100.0/24`
* **Gateway (OPNsense LAN):** `192.168.100.1`
* **DHCP Scope:** `192.168.100.10 - .200` (für dynamische Clients wie Kali).
* **Static IPs:** Reservierter Bereich `.2` bis `.9` für Infrastruktur (z.B. SIEM Server).
* **NAT:** Outbound NAT ist auf WAN aktiviert, damit Lab-Clients Internetzugriff haben, aber vom Heimnetz aus unsichtbar bleiben.

### 3. Red Team Infrastructure (Kali Linux)
* **OS:** Kali Linux (Rolling Release).
* **Placement:** Verbunden mit VLAN/Bridge `vmbr1`.
* **Sicherheitskonzept (OpSec):** Die Angriffsmaschine ist vom produktiven Heimnetz isoliert. Zugriff auf das Internet erfolgt via NAT durch die OPNsense Firewall. Kein Inbound-Traffic vom Internet möglich.

### 4. Security Policy Implementation (Hardening)
* **Default Behavior:** OPNsense erlaubt initial ausgehenden Traffic.
* **RFC1918 Blocking (Egress Filter):** Erstellung eines Alias für private Adressbereiche (`10.x`, `172.16.x`, `192.168.x`).
* **Regel:** `BLOCK LAN net TO PrivateNetworks`.
* **Ergebnis:** Das Lab ist vollständig isoliert. Malware kann zwar ins Internet funken (C&C Server), aber nicht das lokale Heimnetz scannen (Lateral Movement Prevention).

### 5. VM Migration & Management
* **Challenge:** Integration einer Legacy VMDK (VMware Format) in eine KVM/Proxmox Umgebung für das Target-System (Metasploitable 2).
* **Lösung:** Manueller Transfer via `scp` und Konvertierung mittels Hypervisor-CLI.
* **Command:** `qm importdisk <vmid> <source> <storage>`

---

## 🔍 Phase 2: Custom Python Network Scanner & Service Identification

### Projektziel
Entwicklung eines eigenen Netzwerk-Scanners in Python, um die Funktionsweise von TCP-Handshakes und Socket-Programmierung auf Low-Level-Ebene zu verstehen. Ziel war es, offene Ports zu finden und die dahinterliegenden Dienste durch "Banner Grabbing" zu identifizieren.

### Technologie-Stack
* **Sprache:** Python 3 (`socket`, `sys`, `datetime`)
* **Protokolle:** TCP/IPv4, HTTP

### Implementierungs-Details
* **Phase A (Port Discovery):** Das Skript nutzt `socket.connect_ex()`, um einen vollständigen TCP 3-Way-Handshake (SYN -> SYN-ACK -> ACK) zu simulieren.
* **Phase B (Service Enumeration):** Nach erfolgreicher Verbindung versucht das Skript, Metadaten des Dienstes auszulesen. Da Webserver oft kein initiales Banner senden, sendet das Skript aktiv einen `HEAD / HTTP/1.0` Request, um den Server zu einer Antwort zu zwingen.

### Source Code (`scanner.py`)
```python
import socket
import sys
from datetime import datetime

if len(sys.argv) == 2:
    target = sys.argv[1]
else:
    print("Fehler: Bitte gib eine IP an!")
    print("Beispiel: python3 scanner.py 192.168.100.146")
    sys.exit()

print("-" * 50)
print(f"Scanne Ziel: {target}")
print(f"Startzeit: {datetime.now()}")
print("-" * 50)

try:
    for port in range(20, 100):    
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.5)
        result = s.connect_ex((target, port))
        
        if result == 0:
            print(f"[+] Port {port} ist OFFEN ", end="")             
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((target, port))
                
                # Protokoll-Trigger für HTTP
                if port == 80:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                
                banner = sock.recv(1024).decode().strip()
                if banner:
                    print(f"-> Service: {banner}")
                else:
                    print("")
                sock.close()
            except:
                print("-> (Konnte Service nicht identifizieren)")
        s.close()

except KeyboardInterrupt:
    print("\nScan vom User abgebrochen.")
    sys.exit()
except socket.gaierror:
    print("\nHostname konnte nicht aufgelöst werden.")
    sys.exit()
except socket.error:
    print("\nKeine Verbindung zum Server möglich.")
    sys.exit()

print("-" * 50)
print("Scan beendet.")
