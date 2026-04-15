#!/usr/bin/env python3
"""
Subdomain Hunter v4.0 🐉
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
import dns.exception
import sys
import argparse
import json
import csv
import os
from datetime import datetime
from colorama import init, Fore, Style
import random
import re
from time import perf_counter

# Renkleri başlat
init(autoreset=True)

# Banner
VERSION = "4.0"
SCHEMA_VERSION = "2.0"

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
        permutations=False,
        insecure=False,
        priority_policy=None,
        profile="default",
        min_priority=0,
        top=0,
        verify_rounds=2,
        mode="balanced"
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
        self.insecure = insecure
        self.profile = profile
        self.mode = mode
        self.min_priority = max(0, min(100, min_priority))
        self.top = max(0, top)
        self.verify_rounds = max(1, verify_rounds)
        
        self.found = []
        self.wildcard_dns_values = set()
        self.wildcard_cname_values = set()
        self.semaphore = asyncio.Semaphore(threads)
        self.passive_subs = []
        self.scan_started_at = None
        self.total_targets = 0
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
        self.priority_policy = self.load_priority_policy(priority_policy, profile=self.profile)
        self.apply_mode_defaults()
        self.adaptive_lock = asyncio.Lock()
        self.adaptive_stats = {
            "processed": 0,
            "resolved": 0,
            "http_hits": 0,
            "wildcard_filtered": 0,
            "unstable_filtered": 0,
        }
        self.adaptive_decisions = []
        self.adaptive_last_tuned_at = 0

    def snapshot_runtime_settings(self):
        return {
            "threads": self.threads,
            "retries": self.retries,
            "verify_rounds": self.verify_rounds,
            "min_priority": self.min_priority,
        }

    def log_adaptive_decision(self, trigger, before, after, metrics=None):
        """Adaptive mod karar kayıtlarını tut"""
        if self.mode != "adaptive":
            return
        if before == after:
            return

        record = {
            "trigger": trigger,
            "before": before,
            "after": after,
            "processed": self.adaptive_stats.get("processed", 0),
        }
        if metrics:
            record["metrics"] = metrics
        self.adaptive_decisions.append(record)

    def apply_mode_defaults(self):
        """Mode'a göre hız/doğruluk dengesi ayarları"""
        mode_defaults = {
            "aggressive": {
                "threads": max(self.threads, 80),
                "verify_rounds": max(1, min(self.verify_rounds, 2)),
                "retries": max(self.retries, 1),
                "min_priority": self.min_priority,
            },
            "balanced": {
                "threads": self.threads,
                "verify_rounds": max(2, self.verify_rounds),
                "retries": max(self.retries, 2),
                "min_priority": self.min_priority,
            },
            "strict": {
                "threads": min(self.threads, 40),
                "verify_rounds": max(3, self.verify_rounds),
                "retries": max(self.retries, 3),
                "min_priority": max(50, self.min_priority),
            },
            "adaptive": {
                "threads": self.threads,
                "verify_rounds": max(2, self.verify_rounds),
                "retries": max(self.retries, 2),
                "min_priority": self.min_priority,
            },
        }
        selected = mode_defaults.get(self.mode, mode_defaults["balanced"])
        self.threads = selected["threads"]
        self.verify_rounds = selected["verify_rounds"]
        self.retries = selected["retries"]
        self.min_priority = selected["min_priority"]
        self.semaphore = asyncio.Semaphore(self.threads)

    def adapt_runtime_settings(self, total_targets):
        """Adaptive modda erken sinyallere göre ayarları optimize et"""
        if self.mode != "adaptive":
            return

        before = self.snapshot_runtime_settings()
        wildcard_detected = bool(self.wildcard_dns_values or self.wildcard_cname_values)
        if wildcard_detected:
            # Wildcard görüldüyse false-positive azaltımı için sıkılaş
            self.verify_rounds = max(self.verify_rounds, 3)
            self.min_priority = max(self.min_priority, 45)
            self.threads = max(20, min(self.threads, 40))
            self.retries = max(self.retries, 3)
        elif total_targets > 1500:
            # Hedef çok büyükse throughput artır
            self.threads = min(max(self.threads, 100), 200)
            self.verify_rounds = max(2, min(self.verify_rounds, 2))
            self.retries = max(self.retries, 2)
        else:
            # Dengeli default
            self.threads = max(50, self.threads)
            self.verify_rounds = max(2, self.verify_rounds)

        after = self.snapshot_runtime_settings()
        self.log_adaptive_decision(
            trigger="initial_target_analysis",
            before=before,
            after=after,
            metrics={
                "total_targets": total_targets,
                "wildcard_detected": wildcard_detected,
            },
        )
        self.semaphore = asyncio.Semaphore(self.threads)

    def apply_feedback_from_metrics(self, resolved_rate, http_hit_rate, wildcard_filter_rate):
        """Adaptive mod için metrik tabanlı dinamik tuning"""
        if self.mode != "adaptive":
            return

        before = self.snapshot_runtime_settings()
        if wildcard_filter_rate > 0.35 or resolved_rate < 0.06:
            # Gürültü yüksek: doğruluğu artır
            self.verify_rounds = min(5, max(self.verify_rounds, 3))
            self.min_priority = min(95, max(self.min_priority, 55))
            self.threads = max(20, min(self.threads, 45))
            self.retries = min(5, max(self.retries, 3))
        elif resolved_rate > 0.20 and http_hit_rate > 0.10:
            # Sağlıklı isabet: daha fazla kapsama
            self.threads = min(220, max(self.threads, 110))
            self.verify_rounds = max(2, min(self.verify_rounds, 3))
            self.retries = max(2, min(self.retries, 3))
            self.min_priority = max(20, min(self.min_priority, 45))
        else:
            # Orta seviye davranış
            self.threads = max(40, min(self.threads, 120))
            self.verify_rounds = max(2, min(self.verify_rounds, 4))
            self.retries = max(2, min(self.retries, 4))

        after = self.snapshot_runtime_settings()
        self.log_adaptive_decision(
            trigger="runtime_feedback",
            before=before,
            after=after,
            metrics={
                "resolved_rate": round(resolved_rate, 4),
                "http_hit_rate": round(http_hit_rate, 4),
                "wildcard_filter_rate": round(wildcard_filter_rate, 4),
            },
        )
        self.semaphore = asyncio.Semaphore(self.threads)

    async def record_adaptive_event(self, outcome, has_http=False):
        """Tarama sırasında adaptif metrikleri güncelle ve gerekirse tuning yap"""
        if self.mode != "adaptive":
            return

        async with self.adaptive_lock:
            self.adaptive_stats["processed"] += 1
            if outcome in ("accepted_dns", "accepted_http"):
                self.adaptive_stats["resolved"] += 1
            if outcome == "accepted_http" or has_http:
                self.adaptive_stats["http_hits"] += 1
            if outcome == "wildcard_filtered":
                self.adaptive_stats["wildcard_filtered"] += 1
            if outcome == "unstable_filtered":
                self.adaptive_stats["unstable_filtered"] += 1

            processed = self.adaptive_stats["processed"]
            if processed - self.adaptive_last_tuned_at < 150:
                return

            resolved_rate = self.adaptive_stats["resolved"] / processed
            http_hit_rate = self.adaptive_stats["http_hits"] / processed
            wildcard_rate = (
                self.adaptive_stats["wildcard_filtered"] + self.adaptive_stats["unstable_filtered"]
            ) / processed

            self.apply_feedback_from_metrics(
                resolved_rate=resolved_rate,
                http_hit_rate=http_hit_rate,
                wildcard_filter_rate=wildcard_rate,
            )
            self.adaptive_last_tuned_at = processed
        
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
        passive_results = set()

        crt_subs = await self.get_crt_subdomains()
        if crt_subs:
            passive_results.update(crt_subs)
            print(f"{Fore.GREEN}[+] crt.sh'den {len(crt_subs)} subdomain bulundu{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] crt.sh'den subdomain bulunamadı{Style.RESET_ALL}")

        bufferover_subs = await self.get_bufferover_subdomains()
        if bufferover_subs:
            passive_results.update(bufferover_subs)
            print(f"{Fore.GREEN}[+] BufferOver'dan {len(bufferover_subs)} subdomain bulundu{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] BufferOver'dan subdomain bulunamadı{Style.RESET_ALL}")

        preview = sorted(list(passive_results))[:10]
        for sub in preview:
            print(f"  → {sub}")
        return list(passive_results)

    async def get_bufferover_subdomains(self):
        """BufferOver API'den pasif subdomain toplar"""
        url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
        subdomains = set()
        try:
            headers = {"User-Agent": f"subdomain-hunter/{VERSION}"}
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(url, timeout=12) as response:
                    if response.status != 200:
                        return []
                    data = await response.json(content_type=None)
                    for key in ("FDNS_A", "RDNS"):
                        for entry in data.get(key, []) or []:
                            part = entry.split(",")[-1].strip().lower().rstrip(".")
                            if part.endswith(f".{self.domain}"):
                                subdomains.add(part.replace(f".{self.domain}", "").strip("."))
        except Exception as exc:
            print(f"{Fore.YELLOW}[!] BufferOver hatası: {exc}{Style.RESET_ALL}")
        return [s for s in subdomains if s]
    
    def check_wildcard(self):
        """Wildcard DNS tespiti"""
        detected_values = set()
        detected_cnames = set()
        for _ in range(5):
            test_sub = f"wildcard-test-{random.randint(10000, 99999)}.{self.domain}"
            for record_type in ("A", "AAAA", "CNAME"):
                try:
                    answers = self.resolver.resolve(test_sub, record_type)
                    cleaned = [str(answer).rstrip(".") for answer in answers]
                    if record_type == "CNAME":
                        detected_cnames.update(cleaned)
                    else:
                        detected_values.update(cleaned)
                except Exception:
                    continue

        self.wildcard_dns_values = detected_values
        self.wildcard_cname_values = detected_cnames
        if self.wildcard_dns_values or self.wildcard_cname_values:
            sample_ips = ", ".join(sorted(list(self.wildcard_dns_values))[:2])
            sample_cnames = ", ".join(sorted(list(self.wildcard_cname_values))[:2])
            print(f"{Fore.YELLOW}[!] Wildcard DNS tespit edildi! IP: {sample_ips or '-'} CNAME: {sample_cnames or '-'}{Style.RESET_ALL}")
            return True
        return False

    def is_wildcard_result(self, dns_result):
        """DNS sonucu wildcard kaydıyla eşleşiyor mu"""
        if not self.wildcard_dns_values and not self.wildcard_cname_values:
            return False
        ips = set(dns_result.get("ips", []))
        cnames = set(dns_result.get("cnames", []))
        ip_is_wild = bool(ips) and ips.issubset(self.wildcard_dns_values)
        cname_is_wild = bool(cnames) and cnames.issubset(self.wildcard_cname_values)
        return ip_is_wild or cname_is_wild

    def is_retryable_dns_error(self, error):
        """DNS için yeniden denenebilir hataları belirle"""
        retryable_errors = (
            dns.resolver.Timeout,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        )
        return isinstance(error, retryable_errors)

    def is_retryable_http_error(self, error):
        """HTTP için yeniden denenebilir hataları belirle"""
        retryable_errors = (
            aiohttp.ClientConnectionError,
            aiohttp.ClientPayloadError,
            aiohttp.ServerTimeoutError,
            asyncio.TimeoutError,
            TimeoutError,
        )
        return isinstance(error, retryable_errors)
    
    async def dns_lookup(self, subdomain):
        """DNS sorgusu yap (A kaydı)"""
        full_domain = f"{subdomain}.{self.domain}"
        loop = asyncio.get_running_loop()
        def _resolve_record(record_type):
            return self.resolver.resolve(full_domain, record_type)

        for attempt in range(self.retries + 1):
            try:
                ips = set()
                cnames = set()
                for record_type in ("A", "AAAA", "CNAME"):
                    try:
                        answers = await loop.run_in_executor(None, lambda rt=record_type: _resolve_record(rt))
                        values = [str(answer).rstrip(".") for answer in answers]
                        if record_type == "CNAME":
                            cnames.update(values)
                        else:
                            ips.update(values)
                    except Exception:
                        continue

                if ips or cnames:
                    return {
                        'subdomain': full_domain,
                        'ips': sorted(list(ips)),
                        'cnames': sorted(list(cnames)),
                        'resolved': True
                    }
            except Exception as exc:
                if attempt >= self.retries or not self.is_retryable_dns_error(exc):
                    break
        return {'subdomain': full_domain, 'resolved': False}
    
    async def http_check(self, subdomain, session):
        """HTTP/HTTPS isteği yap"""
        full_domain = f"{subdomain}.{self.domain}"
        results = []
        
        for scheme in ['https', 'http']:
            url = f"{scheme}://{full_domain}"
            ssl_mode = False if (scheme == 'https' and self.insecure) else None
            for attempt in range(self.retries + 1):
                try:
                    started_at = perf_counter()
                    async with session.get(url, timeout=self.timeout, ssl=ssl_mode, allow_redirects=True) as response:
                        results.append({
                            'url': url,
                            'final_url': str(response.url),
                            'status': response.status,
                            'title': await self.get_title(response),
                            'server': response.headers.get('Server', 'Unknown')[:30],
                            'response_time_ms': round((perf_counter() - started_at) * 1000, 2),
                        })
                        break
                except Exception as exc:
                    if attempt >= self.retries or not self.is_retryable_http_error(exc):
                        break
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
                await self.record_adaptive_event("unresolved")
                if pbar:
                    pbar.update(1)
                return None
            
            # Wildcard filtresi
            if self.is_wildcard_result(dns_result):
                await self.record_adaptive_event("wildcard_filtered")
                if pbar:
                    pbar.update(1)
                return None

            if not await self.verify_dns_stability(subdomain, dns_result):
                await self.record_adaptive_event("unstable_filtered")
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

            score, breakdown = self.calculate_priority_score_and_breakdown(result)
            result["priority_score"] = score
            result["score_breakdown"] = breakdown
            
            # Konsola yazdır
            self.print_result(result)
            
            if pbar:
                pbar.update(1)

            await self.record_adaptive_event(
                "accepted_http" if "http" in result else "accepted_dns",
                has_http=("http" in result),
            )
            
            return result

    async def verify_dns_stability(self, subdomain, initial_result):
        """False-positive azaltmak için DNS stabilitesini doğrula"""
        if self.verify_rounds <= 1:
            return True

        initial_ips = set(initial_result.get("ips", []))
        initial_cnames = set(initial_result.get("cnames", []))
        full_domain = initial_result.get("subdomain", f"{subdomain}.{self.domain}")
        loop = asyncio.get_running_loop()

        stable_hits = 0
        for _ in range(self.verify_rounds - 1):
            try:
                ips = set()
                cnames = set()
                for record_type in ("A", "AAAA", "CNAME"):
                    try:
                        answers = await loop.run_in_executor(None, lambda rt=record_type: self.resolver.resolve(full_domain, rt))
                        values = [str(answer).rstrip(".") for answer in answers]
                        if record_type == "CNAME":
                            cnames.update(values)
                        else:
                            ips.update(values)
                    except Exception:
                        continue

                if (initial_ips and ips and bool(initial_ips & ips)) or (initial_cnames and cnames and bool(initial_cnames & cnames)):
                    stable_hits += 1
            except Exception:
                continue

        return stable_hits >= 1

    async def worker(self, queue, session, results, pbar=None):
        """Queue'dan subdomain alıp işleyen worker"""
        while True:
            subdomain = await queue.get()
            if subdomain is None:
                queue.task_done()
                break

            try:
                result = await self.check_subdomain(subdomain, session, pbar)
                if result is not None:
                    results.append(result)
            finally:
                queue.task_done()
    
    def print_result(self, result):
        """Sonucu konsola yazdır"""
        sub = result['subdomain']
        ips = ', '.join(result.get('ips', [])[:2])
        score = result.get("priority_score", 0)
        
        if 'http' in result:
            http = result['http']
            status = http['status']
            if status == 200:
                color = Fore.GREEN
            elif status >= 400:
                color = Fore.YELLOW
            else:
                color = Fore.CYAN
            
            print(f"{color}[✓] {sub} [{ips}] → {status} ({http.get('title', '')[:40]}) [P:{score}]{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] {sub} [{ips}] [P:{score}]{Style.RESET_ALL}")

    def calculate_priority_score_and_breakdown(self, result):
        """Basit risk/öncelik skoru ve açıklama üret"""
        sub = result.get("subdomain", "").lower()
        score = self.priority_policy.get("base_score", 10)
        breakdown = [{"reason": "base_score", "delta": self.priority_policy.get("base_score", 10)}]

        high_signal_tokens = tuple(self.priority_policy.get("high_signal_tokens", []))
        matched_tokens = [token for token in high_signal_tokens if token in sub]
        if matched_tokens:
            high_signal_bonus = self.priority_policy.get("high_signal_bonus", 35)
            score += high_signal_bonus
            breakdown.append({
                "reason": "high_signal_tokens",
                "delta": high_signal_bonus,
                "matched": matched_tokens,
            })

        if "http" in result:
            status = result["http"].get("status", 0)
            if 200 <= status < 300:
                delta = self.priority_policy.get("status_bonus_2xx", 30)
                score += delta
                breakdown.append({"reason": "status_2xx", "delta": delta})
            elif 300 <= status < 400:
                delta = self.priority_policy.get("status_bonus_3xx", 20)
                score += delta
                breakdown.append({"reason": "status_3xx", "delta": delta})
            elif status in (401, 403):
                delta = self.priority_policy.get("status_bonus_auth", 25)
                score += delta
                breakdown.append({"reason": "status_auth", "delta": delta})
            elif status >= 400:
                delta = self.priority_policy.get("status_bonus_4xx_5xx", 10)
                score += delta
                breakdown.append({"reason": "status_4xx_5xx", "delta": delta})
        else:
            delta = self.priority_policy.get("dns_only_bonus", 15)
            score += delta
            breakdown.append({"reason": "dns_only", "delta": delta})

        final_score = min(100, score)
        if final_score != score:
            breakdown.append({"reason": "score_cap", "delta": final_score - score})
        return final_score, breakdown

    def calculate_priority_score(self, result):
        """Geriye dönük uyumluluk için skor üret"""
        return self.calculate_priority_score_and_breakdown(result)[0]

    def get_default_priority_policy(self):
        return {
            "base_score": 10,
            "high_signal_tokens": [
                "admin", "dev", "staging", "test", "api", "vpn", "jenkins", "git", "db"
            ],
            "high_signal_bonus": 35,
            "status_bonus_2xx": 30,
            "status_bonus_3xx": 20,
            "status_bonus_auth": 25,
            "status_bonus_4xx_5xx": 10,
            "dns_only_bonus": 15,
        }

    def get_profile_policies(self):
        return {
            "default": {},
            "redteam": {
                "high_signal_tokens": [
                    "admin", "dev", "staging", "test", "api", "vpn", "jenkins", "git", "db", "internal", "corp"
                ],
                "high_signal_bonus": 40,
                "status_bonus_auth": 35,
            },
            "bugbounty": {
                "high_signal_tokens": [
                    "admin", "api", "auth", "login", "graphql", "staging", "dev"
                ],
                "status_bonus_2xx": 35,
                "status_bonus_3xx": 25,
            },
            "quick": {
                "base_score": 5,
                "high_signal_bonus": 25,
                "dns_only_bonus": 10,
            },
        }

    def validate_priority_policy(self, policy):
        """Policy tiplerini doğrula, geçersizleri sil"""
        schema = {
            "base_score": int,
            "high_signal_tokens": list,
            "high_signal_bonus": int,
            "status_bonus_2xx": int,
            "status_bonus_3xx": int,
            "status_bonus_auth": int,
            "status_bonus_4xx_5xx": int,
            "dns_only_bonus": int,
        }
        validated = {}
        for key, value in policy.items():
            expected_type = schema.get(key)
            if not expected_type:
                continue
            if isinstance(value, expected_type):
                validated[key] = value
            else:
                print(f"{Fore.YELLOW}[!] Policy alanı atlandı ({key}): beklenen {expected_type.__name__}{Style.RESET_ALL}")
        return validated

    def load_priority_policy(self, policy_path, profile="default"):
        policy = self.get_default_priority_policy()
        profile_policies = self.get_profile_policies()
        if profile not in profile_policies:
            print(f"{Fore.YELLOW}[!] Bilinmeyen profil, varsayılan kullanılacak: {profile}{Style.RESET_ALL}")
            profile = "default"

        policy.update(profile_policies[profile])
        if not policy_path:
            return policy

        if not os.path.exists(policy_path):
            print(f"{Fore.YELLOW}[!] Priority policy bulunamadı, varsayılan kullanılacak: {policy_path}{Style.RESET_ALL}")
            return policy

        try:
            with open(policy_path, "r", encoding="utf-8") as f:
                custom_policy = json.load(f)
            if isinstance(custom_policy, dict):
                policy.update(self.validate_priority_policy(custom_policy))
            else:
                print(f"{Fore.YELLOW}[!] Priority policy formatı geçersiz, varsayılan kullanılacak{Style.RESET_ALL}")
        except Exception as exc:
            print(f"{Fore.YELLOW}[!] Priority policy okunamadı ({exc}), varsayılan kullanılacak{Style.RESET_ALL}")
        return policy

    def calculate_stats(self):
        """Bulunan sonuçlar için özet metrikler"""
        status_distribution = {}
        response_times = []

        for item in self.found:
            http = item.get("http")
            if not http:
                continue

            status = str(http.get("status", "unknown"))
            status_distribution[status] = status_distribution.get(status, 0) + 1

            response_time = http.get("response_time_ms")
            if isinstance(response_time, (int, float)):
                response_times.append(response_time)

        avg_response_time = round(sum(response_times) / len(response_times), 2) if response_times else None
        adaptive_decision_summary = self.summarize_adaptive_decisions() if self.mode == "adaptive" else {}
        return {
            "http_count": len([r for r in self.found if "http" in r]),
            "dns_only_count": len([r for r in self.found if "http" not in r]),
            "status_distribution": status_distribution,
            "avg_response_time_ms": avg_response_time,
            "adaptive_stats": self.adaptive_stats if self.mode == "adaptive" else {},
            "adaptive_decisions": self.adaptive_decisions if self.mode == "adaptive" else [],
            "adaptive_decision_summary": adaptive_decision_summary,
        }

    def summarize_adaptive_decisions(self):
        """Adaptive tuning kararlarının özetini üret"""
        if not self.adaptive_decisions:
            return {
                "total_decisions": 0,
                "strict_shifts": 0,
                "throughput_shifts": 0,
                "avg_delta": {
                    "threads": 0.0,
                    "retries": 0.0,
                    "verify_rounds": 0.0,
                    "min_priority": 0.0,
                },
            }

        strict_shifts = 0
        throughput_shifts = 0
        total_delta = {
            "threads": 0.0,
            "retries": 0.0,
            "verify_rounds": 0.0,
            "min_priority": 0.0,
        }

        for decision in self.adaptive_decisions:
            before = decision.get("before", {})
            after = decision.get("after", {})
            d_threads = after.get("threads", 0) - before.get("threads", 0)
            d_retries = after.get("retries", 0) - before.get("retries", 0)
            d_verify = after.get("verify_rounds", 0) - before.get("verify_rounds", 0)
            d_priority = after.get("min_priority", 0) - before.get("min_priority", 0)

            total_delta["threads"] += d_threads
            total_delta["retries"] += d_retries
            total_delta["verify_rounds"] += d_verify
            total_delta["min_priority"] += d_priority

            # Daha sıkı doğrulama yönüne kayma
            if d_threads < 0 or d_verify > 0 or d_priority > 0:
                strict_shifts += 1
            # Daha yüksek throughput yönüne kayma
            if d_threads > 0 and d_verify <= 0:
                throughput_shifts += 1

        count = len(self.adaptive_decisions)
        avg_delta = {
            key: round(value / count, 2)
            for key, value in total_delta.items()
        }
        return {
            "total_decisions": count,
            "strict_shifts": strict_shifts,
            "throughput_shifts": throughput_shifts,
            "avg_delta": avg_delta,
        }

    def get_adaptive_health_badge(self, summary):
        """Adaptive özetine göre kısa health badge üret"""
        strict_shifts = summary.get("strict_shifts", 0)
        throughput_shifts = summary.get("throughput_shifts", 0)
        total_decisions = summary.get("total_decisions", 0)

        if total_decisions == 0:
            return "GOOD"
        if strict_shifts >= throughput_shifts * 2 and strict_shifts >= 2:
            return "NOISY"
        if throughput_shifts > strict_shifts and throughput_shifts >= 2:
            return "AGGRESSIVE"
        return "GOOD"

    def format_adaptive_health_badge(self, badge):
        """Health badge'i renkli formatla"""
        color_map = {
            "GOOD": Fore.GREEN,
            "NOISY": Fore.YELLOW,
            "AGGRESSIVE": Fore.CYAN,
        }
        color = color_map.get(badge, Fore.WHITE)
        return f"{color}{badge}{Style.RESET_ALL}"

    def apply_result_filters(self, results):
        """Priority filtrelerini uygula"""
        filtered = list(results)
        if self.min_priority > 0:
            filtered = [r for r in filtered if r.get("priority_score", 0) >= self.min_priority]
        if self.top > 0:
            filtered.sort(key=lambda x: x.get("priority_score", 0), reverse=True)
            filtered = filtered[:self.top]
        return filtered
    
    async def scan(self):
        """Ana tarama fonksiyonu"""
        self.scan_started_at = datetime.now()
        start_perf = perf_counter()
        print(BANNER)
        print(f"{Fore.YELLOW}[+] Hedef domain: {self.domain}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Wordlist: {len(self.wordlist)} subdomain{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Thread: {self.threads}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Mode: {self.mode}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Timeout: {self.timeout}s{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Retry: {self.retries}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] DNS Only: {'Evet' if self.dns_only else 'Hayır'}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] TLS Doğrulama: {'Kapalı' if self.insecure else 'Açık'}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Priority Profili: {self.profile}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] DNS Doğrulama Turu: {self.verify_rounds}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Min Priority: {self.min_priority}{Style.RESET_ALL}")
        if self.top:
            print(f"{Fore.YELLOW}[+] Top Sonuç Limiti: {self.top}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Başlangıç: {self.scan_started_at}{Style.RESET_ALL}\n")
        if self.insecure:
            print(f"{Fore.YELLOW}[!] Uyarı: TLS doğrulama kapalı, sertifika kontrolleri atlanacak{Style.RESET_ALL}\n")
        
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
        self.adapt_runtime_settings(self.total_targets)
        print(f"{Fore.GREEN}[+] Toplam hedef: {len(all_subs)} subdomain ({len(self.wordlist)} aktif + {len(passive_subs)} pasif){Style.RESET_ALL}\n")
        
        # HTTP session
        connector_limit = max(10, self.threads)
        connector = aiohttp.TCPConnector(limit=connector_limit, ttl_dns_cache=300)
        timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj) as session:
            # Progress bar
            try:
                from tqdm import tqdm
                pbar = tqdm(total=len(all_subs), desc="Tarama ilerlemesi", unit="sub")
            except:
                pbar = None
            
            # Bounded queue + worker modeli
            queue = asyncio.Queue(maxsize=max(100, self.threads * 2))
            worker_count = max(1, min(self.threads, len(all_subs)))
            results = []

            workers = [
                asyncio.create_task(self.worker(queue, session, results, pbar))
                for _ in range(worker_count)
            ]

            for sub in all_subs:
                await queue.put(sub)

            for _ in range(worker_count):
                await queue.put(None)

            await queue.join()
            await asyncio.gather(*workers)
            if pbar:
                pbar.close()
            
            # Başarılı olanları topla
            self.found = results
            self.found.sort(key=lambda x: (x.get('http', {}).get('status', 999), x['subdomain']))
            self.found = self.apply_result_filters(self.found)
        
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

        if self.mode == "adaptive":
            summary = self.summarize_adaptive_decisions()
            badge = self.get_adaptive_health_badge(summary)
            print(f"{Fore.CYAN}[+] Adaptive karar özeti:{Style.RESET_ALL}")
            print(
                f"  → Toplam karar: {summary.get('total_decisions', 0)} | "
                f"Strict shift: {summary.get('strict_shifts', 0)} | "
                f"Throughput shift: {summary.get('throughput_shifts', 0)}"
            )
            print(f"  → Health badge: {self.format_adaptive_health_badge(badge)}")
            avg_delta = summary.get("avg_delta", {})
            print(
                "  → Ortalama delta: "
                f"threads {avg_delta.get('threads', 0)}, "
                f"retries {avg_delta.get('retries', 0)}, "
                f"verify_rounds {avg_delta.get('verify_rounds', 0)}, "
                f"min_priority {avg_delta.get('min_priority', 0)}"
            )
        
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
                        "schema_version": SCHEMA_VERSION,
                        "target": self.domain,
                        "started_at": self.scan_started_at.isoformat() if self.scan_started_at else None,
                        "total_targets": self.total_targets,
                        "found_count": len(self.found),
                        "stats": self.calculate_stats(),
                        "results": self.found
                    }
                    json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
                print(f"\n{Fore.GREEN}[+] JSON raporu kaydedildi: {self.output}{Style.RESET_ALL}")
            elif self.format == 'csv':
                with open(self.output, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(
                        f,
                        fieldnames=[
                            'subdomain',
                            'ips',
                            'cnames',
                            'status',
                            'title',
                            'final_url',
                            'response_time_ms',
                            'priority_score',
                        ]
                    )
                    writer.writeheader()
                    for r in self.found:
                        writer.writerow({
                            'subdomain': r['subdomain'],
                            'ips': ', '.join(r.get('ips', [])),
                            'cnames': ', '.join(r.get('cnames', [])),
                            'status': r.get('http', {}).get('status', 'DNS Only'),
                            'title': r.get('http', {}).get('title', '')
                            ,
                            'final_url': r.get('http', {}).get('final_url', ''),
                            'response_time_ms': r.get('http', {}).get('response_time_ms', ''),
                            'priority_score': r.get('priority_score', 0),
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
        description="Subdomain Hunter v4.0 - Alt Alan Adı Bulma Aracı",
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
    parser.add_argument("--insecure", action="store_true", help="HTTPS kontrollerinde TLS sertifika doğrulamasını kapat")
    parser.add_argument("--priority-policy", help="Priority score policy JSON dosyası")
    parser.add_argument("--profile", choices=["default", "redteam", "bugbounty", "quick"], default="default", help="Hazır priority profili")
    parser.add_argument("--mode", choices=["aggressive", "balanced", "strict", "adaptive"], default="balanced", help="Tarama modu (hız/doğruluk dengesi)")
    parser.add_argument("--min-priority", type=int, default=0, help="Bu skordan düşük sonuçları filtrele (0-100)")
    parser.add_argument("--top", type=int, default=0, help="En yüksek öncelikli ilk N sonucu tut")
    parser.add_argument("--verify-rounds", type=int, default=2, help="False-positive azaltmak için DNS doğrulama turu")
    
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
        permutations=args.permutations,
        insecure=args.insecure,
        priority_policy=args.priority_policy,
        profile=args.profile,
        mode=args.mode,
        min_priority=args.min_priority,
        top=args.top,
        verify_rounds=args.verify_rounds,
    )
    
    try:
        asyncio.run(hunter.scan())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Kullanıcı tarafından durduruldu!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
