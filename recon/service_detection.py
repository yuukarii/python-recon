# recon/service_detection.py
import nmap
import webbrowser
import threading
from recon.web_utils import screenshot_website
from recon.web_enum import enumerate_directories_ffuf

web_enum_threads = []

def detect_services(target, ports):
    if (len(ports) == 0):
        print("[-] No TCP port found. Skipping...")
        return []

    port_str = ",".join(str(p) for p in ports)
    nm = nmap.PortScanner()

    print(f"[*] Running service detection on ports: {port_str}")
    nm.scan(target, arguments=f'-sV -p {port_str}')

    services = {}
    if target in nm.all_hosts():
        for port in nm[target]['tcp']:
            info = nm[target]['tcp'][port]
            service_name = info.get('name', '')
            product = info.get('product', '')
            version = info.get('version', '')
            extrainfo = info.get('extrainfo', '')
            services[port] = {
                'name': service_name,
                'product': product,
                'version': version,
                'extrainfo': extrainfo,
            }

            if service_name in ['http', 'https'] or 'http' in product.lower():
                protocol = 'https' if service_name == 'https' or 'https' in product.lower() else 'http'
                url = f"{protocol}://{target}:{port}"
                print(f"[+] Opening browser for web service: {url}")
                try:
                    webbrowser.open_new_tab(url)
                except Exception as e:
                    print(f"[!] Failed to open browser: {e}")

                print(f"[*] Taking screenshot of {url}...")
                screenshot_website(url)

                # 🧵 Start directory enumeration in a new thread
                enum_thread = threading.Thread(
                    target=enumerate_directories_ffuf,
                    args=(url,)
                )
                enum_thread.start()
                web_enum_threads.append(enum_thread)

    return services
