import re
import urllib.parse
import tldextract
import requests
import whois
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

# ------------------- CONFIG -------------------
VIRUSTOTAL_API_KEY = "208e5a2024615686d90b5d84e8f89c3c3fb5079bf8f0a821e47d27dc251b5f62"
SUSPICIOUS_TLDS = {'tk', 'ml', 'ga', 'cf', 'gq'}
SHORTENERS = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'buff.ly', 'adf.ly']
PHISHING_KEYWORDS = ['login', 'verify', 'account', 'update', 'secure', 'webscr', 'ebayisapi', 'banking']
# ------------------------------------------------

def is_ip_address(url):
    return re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', url) is not None

def is_long_url(url, threshold=75):
    return len(url) > threshold

def has_at_symbol(url):
    return '@' in url

def uses_shortener(url):
    netloc = urllib.parse.urlparse(url).netloc
    return any(short in netloc for short in SHORTENERS)

def has_suspicious_keywords(url):
    return any(keyword in url.lower() for keyword in PHISHING_KEYWORDS)

def has_suspicious_tld(url):
    ext = tldextract.extract(url)
    return ext.suffix in SUSPICIOUS_TLDS

def vt_scan_url(url):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    scan_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
    if scan_response.status_code != 200:
        return "Error submitting to VirusTotal"

    url_id = scan_response.json()["data"]["id"]
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
    
    result = requests.get(analysis_url, headers=headers)
    if result.status_code != 200:
        return "Error getting analysis"
    
    stats = result.json()["data"]["attributes"]["stats"]
    return f"VirusTotal Detection: {stats['malicious']} malicious, {stats['suspicious']} suspicious"

def get_whois_info(url):
    try:
        domain = tldextract.extract(url).registered_domain
        w = whois.whois(domain)
        return f"Registrar: {w.registrar}, Created: {w.creation_date}"
    except Exception:
        return "WHOIS lookup failed"

def capture_screenshot(url, filename="screenshot.png"):
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(ChromeDriverManager().install(), options=chrome_options)
        driver.set_window_size(1280, 800)
        driver.get(url)
        driver.save_screenshot(filename)
        driver.quit()
        return filename
    except Exception as e:
        return f"Screenshot Error: {e}"

def analyze_url(url):
    results = {
        'IP Based URL': is_ip_address(url),
        'Long URL': is_long_url(url),
        'Contains @ Symbol': has_at_symbol(url),
        'Uses Shortener': uses_shortener(url),
        'Suspicious Keywords': has_suspicious_keywords(url),
        'Suspicious TLD': has_suspicious_tld(url)
    }

    phishing_score = sum(results.values())
    verdict = "Phishing Likely 🚨" if phishing_score >= 3 else "Probably Safe ✅"
    return results, phishing_score, verdict
