import argparse

from recon import ping, port_scan, service_detection, os_fingerprint
from recon.service_detection import web_enum_threads
from recon.exploit_search import search_exploit

def main():
    parser = argparse.ArgumentParser(description="Python Recon Tool for CTFs")
    parser.add_argument("target", help="Target IP address or hostname")
    args = parser.parse_args()

    target = args.target
    try:
        print(f"[+] Starting recon on {target}...")

        if ping.is_alive(target):
            print(f"[+] {target} is alive.")
        else:
            print(f"[-] {target} is not responding to ping.")
            choice = input("[?] Do you want to continue anyway? (y/N): ").strip().lower()
            if choice != 'y':
                print("[*] Exiting...")
                return

        print("[*] Performing port scan...")
        open_tcp, open_udp = port_scan.scan_ports(target)
        print(f"[+] Open TCP ports: {open_tcp}")
        print(f"[+] Open UDP ports: {open_udp}")

        print("[*] Performing OS fingerprinting...")
        os_info = os_fingerprint.os_fingerprint(target)

        if 'error' in os_info:
            print(f"[-] OS Detection failed: {os_info['error']}")
        else:
            print(f"[+] OS Guess: {os_info['name']} (Accuracy: {os_info['accuracy']}%)")

        print("[*] Running service detection on open TCP ports...")
        services = service_detection.detect_services(target, open_tcp)
        if (len(services) > 0):
            print("[+] Services detected:")
            for port, info in services.items():
                print(f"  - Port {port}: {info['name']} {info['product']} {info['version']} ({info['extrainfo']})")
                if info['product']:
                    query = f"{info['product']} {info['version']}".strip()
                    query = query.lower().replace("apache httpd", "apache").replace("openssh", "ssh")
                    search_exploit(query)

            print("[*] Waiting for all directory enumeration threads to finish...")
            for t in web_enum_threads:
                t.join()
            print("[+] All directory enumerations complete.")
        print("[*] Finished!")

    except KeyboardInterrupt:
        print("\n[!] Exiting...")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


if __name__ == "__main__":
    main()