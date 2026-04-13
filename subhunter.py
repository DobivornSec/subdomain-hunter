#!/usr/bin/env python3
import requests
import sys
from urllib.parse import urlparse

def banner():
    print("""
    ╔══════════════════════════════════╗
    ║   Dobivorn Subdomain Hunter      ║
    ║   🐉 Basit Subdomain Bulucu      ║
    ╚══════════════════════════════════╝
    """)

def read_wordlist(file_path):
    try:
        with open(file_path, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        return subdomains
    except FileNotFoundError:
        print(f"[!] Wordlist bulunamadı: {file_path}")
        sys.exit(1)

def check_subdomain(subdomain, domain):
    url = f"https://{subdomain}.{domain}"
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        if response.status_code < 400:
            print(f"[✓] {url} → Durum: {response.status_code}")
            return True
        else:
            print(f"[✗] {url} → Durum: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        # HTTPS çalışmazsa HTTP dene
        try:
            url = f"http://{subdomain}.{domain}"
            response = requests.get(url, timeout=5, allow_redirects=False)
            if response.status_code < 400:
                print(f"[✓] {url} → Durum: {response.status_code}")
                return True
        except:
            pass
    except requests.exceptions.Timeout:
        print(f"[!] {subdomain}.{domain} → Zaman aşımı")
    except Exception as e:
        print(f"[!] {subdomain}.{domain} → Hata: {str(e)[:50]}")
    return False

def main():
    banner()
    
    if len(sys.argv) != 2:
        print("Kullanım: python subhunter.py <domain>")
        print("Örnek: python subhunter.py example.com")
        sys.exit(1)
    
    domain = sys.argv[1].lower()
    print(f"[+] Hedef domain: {domain}\n")
    
    # Wordlist'i oku
    wordlist_file = "wordlists/common.txt"
    subdomains = read_wordlist(wordlist_file)
    print(f"[+] {len(subdomains)} subdomain taranacak...\n")
    
    # Subdomain'leri kontrol et
    found = []
    for sub in subdomains:
        if check_subdomain(sub, domain):
            found.append(f"{sub}.{domain}")
    
    # Özet
    print(f"\n[+] Tarama tamamlandı!")
    print(f"[+] Bulunan subdomain: {len(found)}")
    for f in found:
        print(f"  → {f}")

if __name__ == "__main__":
    main()
