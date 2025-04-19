# recon/port_scan.py
import nmap
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_tcp_range(target, start, end):
    nm = nmap.PortScanner()
    port_range = f"{start}-{end}"
    # --open flag filters only open ports
    nm.scan(target, arguments=f"-p {port_range} -T4 --open")
    found_ports = []
    if target in nm.all_hosts():
        tcp_data = nm[target].get("tcp", {})
        for port, info in tcp_data.items():
            if info.get("state") == "open":
                # Immediate notification for an open port in this chunk
                print(f"[+] Found open TCP port: {port} in range {port_range}")
                found_ports.append(port)
    return found_ports

def scan_udp_range(target, ports):
    nm = nmap.PortScanner()
    port_str = ",".join(str(p) for p in ports)
    nm.scan(target, arguments=f"-sU -p {port_str} --open")
    found_ports = []
    if target in nm.all_hosts() and 'udp' in nm[target]:
        udp_data = nm[target]["udp"]
        for port, info in udp_data.items():
            if info.get("state") == "open":
                # Immediate notification for UDP port
                print(f"[+] Found open UDP port: {port}")
                found_ports.append(port)
    return found_ports

def scan_tcp(target, chunk_size=1000):
    """
    Splits 1-65535 ports into chunks (default size: 1000) and scans each chunk concurrently.
    """
    open_tcp_ports = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for start in range(1, 65536, chunk_size):
            end = min(start + chunk_size - 1, 65535)
            futures.append(executor.submit(scan_tcp_range, target, start, end))
        for future in as_completed(futures):
            open_tcp_ports.extend(future.result())
    return sorted(open_tcp_ports)

def scan_udp(target, udp_ports_list):
    """
    Splits a list of UDP ports into smaller chunks and scans each concurrently.
    udp_ports_list: list of UDP ports (e.g., common ports). In our demo we may use ports 1 to 1000.
    """
    open_udp_ports = []
    chunk_size = 100
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = []
        for i in range(0, len(udp_ports_list), chunk_size):
            chunk = udp_ports_list[i:i+chunk_size]
            futures.append(executor.submit(scan_udp_range, target, chunk))
        for future in as_completed(futures):
            open_udp_ports.extend(future.result())
    return sorted(open_udp_ports)

def scan_ports(target):
    """
    Runs TCP and UDP scans in parallel.
    """
    print("[*] Starting concurrent TCP and UDP scans with live notifications.")

    top_50_udp_ports = [
        53,    # DNS
        123,   # NTP
        161,   # SNMP
        67,    # DHCP server
        68,    # DHCP client
        69,    # TFTP
        500,   # IKE (IPsec)
        137,   # NetBIOS name service
        138,   # NetBIOS datagram service
        1900,  # SSDP (UPnP)
        520,   # RIP
        162,   # SNMP Trap
        445,   # Microsoft-DS (also TCP)
        514,   # Syslog
        631,   # IPP (Internet Printing Protocol)
        1434,  # MS SQL Monitor
        33434, # Traceroute
        4500,  # IPsec NAT-T
        1701,  # L2TP
        111,   # RPCbind
        2049,  # NFS
        69,    # TFTP
        2000,  # Cisco SCCP
        2222,  # EtherNet/IP or alternative SSH
        5353,  # mDNS (Multicast DNS)
        8888,  # Alternate web/UDP service
        161,   # SNMP
        5004,  # RTP media data
        5005,  # RTP control data
        623,   # IPMI
        1645,  # RADIUS
        1812,  # RADIUS
        1813,  # RADIUS accounting
        4501,  # Cisco IPsec NAT-T
        30000, # Arbitrary common port
        3074,  # Xbox Live
        5351,  # NAT-PMP
        27015, # Steam (Valve games)
        1901,  # SLPv2
        11211, # Memcached
        67,    # DHCP again (dupe to keep top 50 strict)
        3702,  # WS-Discovery
        2223,  # IPsec
        2100,  # War FTP
        7100,  # X Font Server
        8080,  # Web proxy (rare UDP usage)
        750,   # kerberos
        264,   # BGMP
        993,   # IMAPS (some odd implementations)
        1646,  # Old RADIUS accounting
        5355   # LLMNR
    ]


    # Execute both scans concurrently using ThreadPoolExecutor.
    with ThreadPoolExecutor(max_workers=2) as executor:
        tcp_future = executor.submit(scan_tcp, target)
        udp_future = executor.submit(scan_udp, target, top_50_udp_ports)
        open_tcp_ports = tcp_future.result()
        open_udp_ports = udp_future.result()

    return open_tcp_ports, open_udp_ports
