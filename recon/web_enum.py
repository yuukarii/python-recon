# recon/web_enum.py
import subprocess
import os
import json
from recon.web_utils import screenshot_website

def enumerate_directories_ffuf(url, wordlist_path="/usr/share/seclists/Discovery/Web-Content/big.txt", output_dir="web_enum"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    json_output = os.path.join(output_dir, url.replace("://", "_").replace("/", "_") + ".json")

    print(f"[*] Running ffuf against {url}")

    try:
        command = [
            "ffuf",
            "-u", f"{url}/FUZZ",
            "-w", wordlist_path,
            "-of", "json",
            "-o", json_output,
            "-e", ".php,.html,.txt",
            "-t", "50",
            "-mc", "200,301,302,403"
        ]

        subprocess.run(command, check=True)

        with open(json_output, "r") as f:
            results = json.load(f)
        blacklist = [
            ".htaccess",
            ".htaccess.php",
            ".htaccess.txt",
            ".htaccess.html",
            ".htpasswd",
            ".htpasswd.php",
            ".htpasswd.html",
            ".htpasswd.txt"
        ]

        for res in results.get("results", []):
            if (not res["input"]["FUZZ"] in blacklist):
                dir_url = res["url"]
                print(f"[+] {res['status']} -> {dir_url}")
                # 🖼 Screenshot each discovered directory
                screenshot_website(dir_url)

    except subprocess.CalledProcessError as e:
        print(f"[!] ffuf failed: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
