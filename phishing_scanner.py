import requests
import whois
from urllib.parse import urlparse
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import os
import time

def analyze_url(url):
    results = {
        "Suspicious TLD": is_suspicious_tld(url),
        "Contains IP Address": contains_ip_address(url),
        "Long URL": len(url) > 75,
        "Contains @ Symbol": "@" in url,
        "Multiple Subdomains": has_multiple_subdomains(url),
        "Uses HTTP": url.startswith("http://")
    }
    
    score = sum(1 for x in results.values() if x)
    verdict = "Suspicious" if score >= 2 else "Likely Safe"
    
    return results, score, verdict

def vt_scan_url(url):
    API_KEY = "208e5a2024615686d90b5d84e8f89c3c3fb5079bf8f0a821e47d27dc251b5f62"
    try:
        headers = {
            "x-apikey": API_KEY
        }
        response = requests.post(
            "https://www.virustotal.com/vtapi/v2/url/scan",
            data={"url": url},
            headers=headers
        )
        return "URL submitted to VirusTotal for scanning"
    except Exception as e:
        return f"Error scanning URL: {str(e)}"

def get_whois_info(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        return {
            "Domain Name": w.domain_name,
            "Creation Date": w.creation_date,
            "Expiration Date": w.expiration_date,
            "Registrar": w.registrar
        }
    except Exception as e:
        return f"Error getting WHOIS info: {str(e)}"

def capture_screenshot(url):
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        time.sleep(3)  # Wait for page to load
        
        screenshot_path = "website_screenshot.png"
        driver.save_screenshot(screenshot_path)
        driver.quit()
        
        return screenshot_path
    except Exception as e:
        return f"Error capturing screenshot: {str(e)}"

# Helper functions
def is_suspicious_tld(url):
    suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz"}
    return any(url.lower().endswith(tld) for tld in suspicious_tlds)

def contains_ip_address(url):
    ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    return bool(re.search(ip_pattern, url))

def has_multiple_subdomains(url):
    domain = urlparse(url).netloc
    return domain.count(".") > 2