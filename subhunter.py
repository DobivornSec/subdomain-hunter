#!/usr/bin/env python3
"""
Subdomain Hunter v3.0 🐉
3 Başlı Ejderha | Red Team | Purple Team | Blue Team

Özellikler:
- Asenkron DNS sorgulama (bruteforce)
- Çoklu thread desteği (10-100 thread)
- DNS doğrulama (A, CNAME kayıtları)
- HTTP/HTTPS canlılık kontrolü
- Wildcard tespiti
- Passive enumeration (crt.sh)
- Permutation saldırısı
- JSON/CSV raporlama
- Renkli çıktı
"""

import asyncio
import aiohttp
import dns.resolver
import sys
import argparse
import json
import csv
from datetime import datetime
from colorama import init, Fore, Style
import random
import re
from time import perf_counter

# Renkleri başlat
init(autoreset=True)

# Banner
VERSION = "3.0"

BANNER = f"""
{Fore.BLUE}╔══════════════════════════════════════════════════════════════╗
║   🐉 Subdomain Hunter v{VERSION} - 3 Başlı Ejderha                 ║
║   🔴 Red Team | 🟣 Purple Team | 🔵 Blue Team                ║
║   ⚡ Async DNS | crt.sh | Retry | JSON/CSV                   ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

class SubdomainHunter:
    def __init__(
        self,
        domain,
        wordlist,
        threads=50,
        timeout=5,
        output=None,
        format='json',
        dns_only=False,
        retries=2,
        no_passive=False,
        permutations=False
    ):
        self.domain = domain.lower()
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.output = output
        self.format = format
        self.dns_only = dns_only
        self.retries = retries
        self.no_passive = no_passive
        self.permutations = permutations
        
        self.found = []
        self.wildcard_ip = None
        self.semaphore = asyncio.Semaphore(threads)
        self.passive_subs = []
        self.scan_started_at = None
        self.total_targets = 0
        
    def generate_permutations(self, subdomain):
        """Permutation saldırısı (alt alan varyasyonları)"""
        permutations = set()
        
        prefixes = ['dev', 'test', 'stage', 'prod', 'api', 'admin', 'staging', 'backup']
        suffixes = ['-dev', '-test', '-staging', '-backup', '-old', '-new']
        
        for prefix in prefixes:
            permutations.add(f"{prefix}-{subdomain}")
            permutations.add(f"{prefix}.{subdomain}")
            permutations.add(f"{prefix}{subdomain}")
        
        for suffix in suffixes:
            permutations.add(f"{subdomain}{suffix}")
        
        # Sayı eklemeleri
        for num in range(1, 10):
            permutations.add(f"{subdomain}{num}")
        
        return list(permutations)
    
    async def get_crt_subdomains(self):
        """crt.sh'den SSL sertifikalarından subdomain bul"""
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        subdomains = set()
        
        try:
            headers = {"User-Agent": f"subdomain-hunter/{VERSION}"}
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name = entry.get('name_value', '')
                            if name and not name.startswith('*'):
                                for sub in name.split('\n'):
                                    clean_sub = sub.strip().lower()
                                    if self.domain in clean_sub:
                                        if clean_sub.endswith(f".{self.domain}"):
                                            subdomains.add(clean_sub.replace(f".{self.domain}", "").strip("."))
                                        elif clean_sub == self.domain:
                                            pass
                                        else:
                                            subdomains.add(clean_sub)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] crt.sh hatası: {e}{Style.RESET_ALL}")
        
        return list(subdomains)
    
    async def passive_enumeration(self):
        """Pasif subdomain toplama"""
        print(f"{Fore.CYAN}[+] Pasif enumeration başlıyor...{Style.RESET_ALL}")
        
        # crt.sh
        crt_subs = await self.get_crt_subdomains()
        if crt_subs:
            print(f"{Fore.GREEN}[+] crt.sh'den {len(crt_subs)} subdomain bulundu{Style.RESET_ALL}")
            for sub in crt_subs[:10]:
                print(f"  → {sub}")
        else:
            print(f"{Fore.YELLOW}[!] crt.sh'den subdomain bulunamadı{Style.RESET_ALL}")
        
        return crt_subs
    
    def check_wildcard(self):
        """Wildcard DNS tespiti"""
        test_sub = f"wildcard-test-{random.randint(10000, 99999)}.{self.domain}"
        try:
            answers = dns.resolver.resolve(test_sub, 'A')
            if answers:
                self.wildcard_ip = str(answers[0])
                print(f"{Fore.YELLOW}[!] Wildcard DNS tespit edildi! IP: {self.wildcard_ip}{Style.RESET_ALL}")
                return True
        except:
            pass
        return False
    
    async def dns_lookup(self, subdomain):
        """DNS sorgusu yap (A kaydı)"""
        full_domain = f"{subdomain}.{self.domain}"
        loop = asyncio.get_running_loop()
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        for _ in range(self.retries + 1):
            try:
                answers = await loop.run_in_executor(None, lambda: resolver.resolve(full_domain, 'A'))
                ips = [str(answer) for answer in answers]
                return {'subdomain': full_domain, 'ips': ips, 'resolved': True}
            except Exception:
                continue
        return {'subdomain': full_domain, 'resolved': False}
    
    async def http_check(self, subdomain, session):
        """HTTP/HTTPS isteği yap"""
        full_domain = f"{subdomain}.{self.domain}"
        results = []
        
        for scheme in ['https', 'http']:
            url = f"{scheme}://{full_domain}"
            for _ in range(self.retries + 1):
                try:
                    async with session.get(url, timeout=self.timeout, ssl=False, allow_redirects=True) as response:
                        results.append({
                            'url': url,
                            'status': response.status,
                            'title': await self.get_title(response),
                            'server': response.headers.get('Server', 'Unknown')[:30]
                        })
                        break
                except Exception:
                    continue
            if results:
                break
        
        return results
    
    async def get_title(self, response):
        """Sayfa başlığını al"""
        try:
            text = await response.text()
            match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
            if match:
                return " ".join(match.group(1).split())[:60]
        except Exception:
            pass
        return ""
    
    async def check_subdomain(self, subdomain, session, pbar=None):
        """Tek bir subdomain'i kontrol et"""
        async with self.semaphore:
            # DNS sorgusu
            dns_result = await self.dns_lookup(subdomain)
            
            if not dns_result['resolved']:
                if pbar:
                    pbar.update(1)
                return None
            
            # Wildcard filtresi
            if self.wildcard_ip and self.wildcard_ip in dns_result.get('ips', []):
                if pbar:
                    pbar.update(1)
                return None
            
            result = {
                'subdomain': dns_result['subdomain'],
                'ips': dns_result.get('ips', []),
                'resolved': True
            }
            
            # HTTP kontrolü
            if not self.dns_only:
                http_results = await self.http_check(subdomain, session)
                if http_results:
                    result['http'] = http_results[0]
            
            # Konsola yazdır
            self.print_result(result)
            
            if pbar:
                pbar.update(1)
            
            return result
    
    def print_result(self, result):
        """Sonucu konsola yazdır"""
        sub = result['subdomain']
        ips = ', '.join(result.get('ips', [])[:2])
        
        if 'http' in result:
            http = result['http']
            status = http['status']
            if status == 200:
                color = Fore.GREEN
            elif status >= 400:
                color = Fore.YELLOW
            else:
                color = Fore.CYAN
            
            print(f"{color}[✓] {sub} [{ips}] → {status} ({http.get('title', '')[:40]}){Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] {sub} [{ips}]{Style.RESET_ALL}")
    
    async def scan(self):
        """Ana tarama fonksiyonu"""
        self.scan_started_at = datetime.now()
        start_perf = perf_counter()
        print(BANNER)
        print(f"{Fore.YELLOW}[+] Hedef domain: {self.domain}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Wordlist: {len(self.wordlist)} subdomain{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Thread: {self.threads}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Timeout: {self.timeout}s{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Retry: {self.retries}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] DNS Only: {'Evet' if self.dns_only else 'Hayır'}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Başlangıç: {self.scan_started_at}{Style.RESET_ALL}\n")
        
        # Pasif enumeration
        passive_subs = []
        if not self.no_passive:
            passive_subs = await self.passive_enumeration()
            print()
        else:
            print(f"{Fore.YELLOW}[!] Pasif enumeration devre dışı{Style.RESET_ALL}\n")
        
        # Wildcard kontrolü
        self.check_wildcard()
        print()
        
        base_wordlist = list(set(self.wordlist + passive_subs))
        if self.permutations:
            perm_subs = set()
            for sub in base_wordlist:
                perm_subs.update(self.generate_permutations(sub))
            all_subs = list(set(base_wordlist + list(perm_subs)))
        else:
            all_subs = base_wordlist
        self.total_targets = len(all_subs)
        print(f"{Fore.GREEN}[+] Toplam hedef: {len(all_subs)} subdomain ({len(self.wordlist)} aktif + {len(passive_subs)} pasif){Style.RESET_ALL}\n")
        
        # HTTP session
        connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)
        timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj) as session:
            # Progress bar
            try:
                from tqdm import tqdm
                pbar = tqdm(total=len(all_subs), desc="Tarama ilerlemesi", unit="sub")
            except:
                pbar = None
            
            # Asenkron görevler
            tasks = []
            for sub in all_subs:
                task = asyncio.create_task(self.check_subdomain(sub, session, pbar))
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            if pbar:
                pbar.close()
            
            # Başarılı olanları topla
            self.found = [r for r in results if r is not None]
            self.found.sort(key=lambda x: (x.get('http', {}).get('status', 999), x['subdomain']))
        
        # Rapor oluştur
        self.generate_report(perf_counter() - start_perf)
    
    def generate_report(self, elapsed_seconds):
        """Rapor oluştur"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    TARAMA ÖZETİ                                      ║")
        print(f"╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}[+] Hedef: {self.domain}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Taranan: {self.total_targets} toplam subdomain{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Bulunan: {len(self.found)} aktif subdomain{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Süre: {elapsed_seconds:.2f} saniye{Style.RESET_ALL}")
        
        if self.found:
            print(f"\n{Fore.GREEN}Aktif subdomainler:{Style.RESET_ALL}")
            for result in self.found[:20]:
                sub = result['subdomain']
                ips = ', '.join(result.get('ips', [])[:1])
                if 'http' in result:
                    print(f"  → {sub} [{ips}] - {result['http']['status']}")
                else:
                    print(f"  → {sub} [{ips}]")
        
        # Dosyaya kaydet
        if self.output:
            if self.format == 'json':
                with open(self.output, 'w', encoding='utf-8') as f:
                    payload = {
                        "version": VERSION,
                        "target": self.domain,
                        "started_at": self.scan_started_at.isoformat() if self.scan_started_at else None,
                        "total_targets": self.total_targets,
                        "found_count": len(self.found),
                        "results": self.found
                    }
                    json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
                print(f"\n{Fore.GREEN}[+] JSON raporu kaydedildi: {self.output}{Style.RESET_ALL}")
            elif self.format == 'csv':
                with open(self.output, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=['subdomain', 'ips', 'status', 'title'])
                    writer.writeheader()
                    for r in self.found:
                        writer.writerow({
                            'subdomain': r['subdomain'],
                            'ips': ', '.join(r.get('ips', [])),
                            'status': r.get('http', {}).get('status', 'DNS Only'),
                            'title': r.get('http', {}).get('title', '')
                        })
                print(f"{Fore.GREEN}[+] CSV raporu kaydedildi: {self.output}{Style.RESET_ALL}")

def load_wordlist(file_path):
    """Wordlist yükle"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            words = [line.strip() for line in f if line.strip()]
        return words
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Wordlist bulunamadı: {file_path}{Style.RESET_ALL}")
        sys.exit(1)

def validate_domain(domain):
    """Basit domain doğrulama"""
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
    return re.match(pattern, domain) is not None

def main():
    parser = argparse.ArgumentParser(
        description="Subdomain Hunter v3.0 - Alt Alan Adı Bulma Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  python subhunter.py example.com
  python subhunter.py example.com -w wordlist.txt -t 100
  python subhunter.py example.com --dns-only
  python subhunter.py example.com -o sonuc.json
  python subhunter.py example.com -o sonuc.csv --format csv
        """
    )
    
    parser.add_argument("domain", help="Hedef domain (örn: example.com)")
    parser.add_argument("-w", "--wordlist", default="wordlists/common.txt", help="Wordlist dosyası")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Thread sayısı (varsayılan: 50)")
    parser.add_argument("-to", "--timeout", type=int, default=5, help="Zaman aşımı saniye (varsayılan: 5)")
    parser.add_argument("-o", "--output", help="Çıktı dosyası (JSON veya CSV)")
    parser.add_argument("--format", choices=['json', 'csv'], default='json', help="Çıktı formatı (varsayılan: json)")
    parser.add_argument("--dns-only", action="store_true", help="Sadece DNS sorgusu yap (HTTP kontrol yok)")
    parser.add_argument("-r", "--retries", type=int, default=2, help="DNS/HTTP retry sayısı (varsayılan: 2)")
    parser.add_argument("--no-passive", action="store_true", help="Pasif enumeration (crt.sh) devre dışı bırak")
    parser.add_argument("--permutations", action="store_true", help="Wordlist üzerinden permutation üret")
    
    args = parser.parse_args()
    if not validate_domain(args.domain):
        print(f"{Fore.RED}[!] Geçersiz domain formatı: {args.domain}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Wordlist yükle
    wordlist = load_wordlist(args.wordlist)
    
    # Tarama başlat
    hunter = SubdomainHunter(
        domain=args.domain,
        wordlist=wordlist,
        threads=args.threads,
        timeout=args.timeout,
        output=args.output,
        format=args.format,
        dns_only=args.dns_only,
        retries=max(0, args.retries),
        no_passive=args.no_passive,
        permutations=args.permutations
    )
    
    try:
        asyncio.run(hunter.scan())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Kullanıcı tarafından durduruldu!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
