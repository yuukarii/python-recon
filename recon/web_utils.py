# recon/web_utils.py
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
import os

def screenshot_website(url, output_dir="screenshots"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")

    try:
        driver = webdriver.Chrome(options=options)
        driver.set_window_size(1920, 1080)
        driver.get(url)

        filename = url.replace("://", "_").replace("/", "_")
        path = os.path.join(output_dir, f"{filename}.png")
        driver.save_screenshot(path)
        print(f"[+] Screenshot saved: {path}")

    except Exception as e:
        print(f"[!] Failed to screenshot {url}: {e}")
    finally:
        driver.quit()
