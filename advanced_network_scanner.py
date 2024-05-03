import scapy.all as scapy
import socket

def scan_network(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    live_hosts = []
    for element in answered_list:
        host_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        live_hosts.append(host_dict)

    return live_hosts

def scan_ports(host_ip, ports):
    open_ports = []
    for port in ports:
        response = scapy.sr1(scapy.IP(dst=host_ip) / scapy.TCP(dport=port, flags="S"), timeout=1, verbose=False)
        if response and response.haslayer(scapy.TCP) and response[scapy.TCP].flags == 18:
            open_ports.append(port)
    return open_ports

def detect_arp_spoofing(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    answered_list = scapy.srp(arp_request, timeout=1, verbose=False)[0]

    spoofed_hosts = []
    for packet in answered_list:
        if packet[1].psrc != packet[1].hwsrc:
            spoofed_hosts.append({"ip": packet[1].psrc, "mac": packet[1].hwsrc})

    return spoofed_hosts

def service_version_detection(host_ip, port):
    try:
        service = socket.getservbyport(port)
        banner = ""
        if port == 80:
            banner = get_http_banner(host_ip, port)
        elif port == 21:
            banner = get_ftp_banner(host_ip, port)
        # Add more services and specific banners here as needed
        return f"Service: {service}, Banner: {banner}"
    except:
        return "Service: Unknown"

def get_http_banner(host_ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host_ip, port))
            s.send(b"GET / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode().strip()
        return banner.split('\r\n')[0]
    except:
        return "Unknown"

def get_ftp_banner(host_ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host_ip, port))
            banner = s.recv(1024).decode().strip()
        return banner
    except:
        return "Unknown"

def print_banner():
    print("""
   ___       _ _   _       _     _             
  / _ \     | | | (_)     | |   (_)            
 / /_\ \_ __| | |_ _  __ _| |__  _ _ __   __ _ 
 |  _  | '__| | __| |/ _` | '_ \| | '_ \ / _` |
 | | | | |  | | |_| | (_| | | | | | | | | (_| |
 \_| |_/_|  |_|\__|_|\__, |_| |_|_|_| |_|\__, |
                      __/ |               __/ |
                     |___/               |___/ 
   Welcome to the Advanced Network Tool
   Developed by Cipherkrish69x
   Version 2.0
   [+] This tool provides advanced network scanning capabilities.
   [+] Features:
       - Network discovery and host scanning
       - Port scanning with service version detection
       - ARP spoofing detection
       - Banner grabbing for specific services (HTTP, FTP, etc.)
   """)

def main():
    print_banner()
    ip_range = input("Enter IP range to scan (e.g., 192.168.1.1/24): ")

    print("\n[+] Scanning network for live hosts...")
    live_hosts = scan_network(ip_range)
    if not live_hosts:
        print("No live hosts found in the specified IP range.")
        return

    print("\n[+] Live Hosts:")
    for host in live_hosts:
        print(f"    - IP: {host['ip']}, MAC: {host['mac']}")

    print("\n[+] Detecting ARP spoofing...")
    spoofed_hosts = detect_arp_spoofing(ip_range)
    if spoofed_hosts:
        print("\n[!] Potential ARP Spoofing Detected:")
        for host in spoofed_hosts:
            print(f"    - IP: {host['ip']}, MAC: {host['mac']}")
    else:
        print("\n[+] No ARP spoofing detected.")

    ports_to_scan = [21, 22, 80, 443, 3389]  # Specify ports to scan (add more as needed)
    print("\n[+] Scanning open ports...")
    for host in live_hosts:
        print(f"\n[+] Open ports for {host['ip']}:")
        open_ports = scan_ports(host['ip'], ports_to_scan)
        if open_ports:
            for port in open_ports:
                service_info = service_version_detection(host['ip'], port)
                print(f"    - Port {port}: {service_info}")
        else:
            print(f"    No open ports found for {host['ip']}")

if __name__ == "__main__":
    main()
                 