# recon/os_fingerprint.py
import nmap

def os_fingerprint(target):
    nm = nmap.PortScanner()

    print("[*] Running OS detection...")
    try:
        nm.scan(target, arguments='-O')
        if target in nm.all_hosts():
            osmatches = nm[target].get('osmatch', [])
            if osmatches:
                best_guess = osmatches[0]
                return {
                    'name': best_guess['name'],
                    'accuracy': best_guess['accuracy'],
                    'osclass': best_guess.get('osclass', [])
                }
            else:
                return {'error': 'No OS match found.'}
        else:
            return {'error': 'Target not found in scan results.'}
    except Exception as e:
        return {'error': str(e)}
