# 🐉 Subdomain Hunter v4.0

> **3 Başlı Ejderha** | Red Team | Purple Team | Blue Team

Hedef domain'in alt alanlarını hızlı ve etkili bir şekilde tespit eden **profesyonel** subdomain bulma aracı. Asenkron DNS, pasif enumeration, retry mekanizması ve çoklu eşzamanlı tarama desteği ile donatılmıştır.

---

## ✨ Özellikler

| Özellik | Açıklama |
|---------|----------|
| ⚡ **Asenkron DNS** | 300+ subdomain/saniye hız |
| 🔍 **Wordlist tabanlı** | 150+ yaygın subdomain |
| 🕵️ **Pasif Enumeration** | crt.sh + BufferOver kaynaklarından toplama |
| 🌐 **HTTP/HTTPS Kontrol** | Durum kodu, başlık, server bilgisi |
| 🎯 **Wildcard Tespiti** | Sahte sonuçları filtreleme |
| ✅ **DNS Stabilite Doğrulama** | Çoklu doğrulama turu ile false-positive azaltma |
| 🎛️ **Tarama Modları** | `aggressive`, `balanced`, `strict` presetleri |
| 📈 **Yanıt Süresi Takibi** | HTTP sonuçlarında `response_time_ms` metriği |
| 🚦 **Öncelik Skoru** | Sonuçlarda basit `priority_score` üretimi |
| 🧾 **Skor Açıklaması** | JSON sonuçlarda `score_breakdown` ile puan sebepleri |
| 📊 **DNS Only Mod** | Sadece DNS sorgusu (çok hızlı) |
| 📁 **JSON/CSV Rapor** | Yapılandırılmış çıktı |
| 🎨 **Renkli Çıktı** | Durum kodlarına göre renklendirme |
| ⏱️ **Timeout Ayarları** | Zaman aşımı konfigürasyonu |
| 🔁 **Retry Desteği** | DNS/HTTP hatalarında otomatik yeniden deneme |
| 🧪 **Domain Doğrulama** | Geçersiz domain girişlerini erken engeller |
| 🧬 **Permutation Modu** | Wordlist'ten otomatik varyasyon üretimi |
| 🔒 **Güvenli TLS Varsayılanı** | HTTPS kontrollerinde sertifika doğrulaması varsayılan açık |

---

## 📦 Kurulum

```bash
git clone https://github.com/DobivornSec/subdomain-hunter.git
cd subdomain-hunter
pip install -r requirements.txt
```

**Gereksinimler:**
```bash
pip install aiohttp dnspython colorama tqdm
```

---

## 🚀 Kullanım

### Temel tarama
```bash
python subhunter.py example.com
```

### Özel wordlist ve thread sayısı
```bash
python subhunter.py example.com -w wordlist.txt -t 100
```

### Sadece DNS sorgusu (çok hızlı)
```bash
python subhunter.py example.com --dns-only
```

### JSON rapor kaydetme
```bash
python subhunter.py example.com -o sonuc.json
```

### CSV rapor kaydetme
```bash
python subhunter.py example.com -o sonuc.csv --format csv
```

### Zaman aşımı ayarı
```bash
python subhunter.py example.com -to 10
```

### Retry sayısını artırma
```bash
python subhunter.py example.com -r 4
```

### Pasif enumeration kapatma
```bash
python subhunter.py example.com --no-passive
```

### Permutation modu açma
```bash
python subhunter.py example.com --permutations
```

### TLS doğrulamasını kapatma (sadece test/lab)
```bash
python subhunter.py example.com --insecure
```

### Öncelik skoruna göre filtreleme
```bash
python subhunter.py example.com --min-priority 60 --top 20
```

### Özel priority policy ile tarama
```bash
cp priority-policy.example.json priority-policy.json
python subhunter.py example.com --priority-policy priority-policy.json
```

### Hazır profille tarama
```bash
python subhunter.py example.com --profile redteam
python subhunter.py example.com --profile bugbounty
```

### False-positive azaltma için sıkı doğrulama
```bash
python subhunter.py example.com --mode strict
```

### Daha agresif keşif (daha fazla sonuç)
```bash
python subhunter.py example.com --mode aggressive
```

### Adaptif mod (hedefe göre otomatik optimizasyon)
```bash
python subhunter.py example.com --mode adaptive
```
> Adaptif mod, tarama sırasında `resolved rate`, `HTTP hit rate` ve filtrelenen gürültü oranına göre thread/retry/verify ayarlarını dinamik günceller.
> JSON çıktıda `stats.adaptive_decisions` alanı ile hangi kararın neden alındığını görebilirsin.
> Ayrıca `stats.adaptive_decision_summary` ile kararların özet etkisini (strict/throughput geçiş sayıları ve ortalama delta) alırsın.
> CLI özet ekranında da adaptif karar özeti ve kısa bir health badge (`GOOD`, `NOISY`, `AGGRESSIVE`) gösterilir.

---

## 📊 Örnek Çıktı

```bash
╔══════════════════════════════════════════════════════════════╗
║   🐉 Subdomain Hunter v4.0 - 3 Başlı Ejderha                  ║
║   🔴 Red Team | 🟣 Purple Team | 🔵 Blue Team                ║
║   ⚡ Async DNS | crt.sh | Retry | JSON/CSV                   ║
╚══════════════════════════════════════════════════════════════╝

[+] Hedef domain: google.com
[+] Wordlist: 227 subdomain
[+] Thread: 50
[+] Başlangıç: 2026-04-14 12:49:31

[+] Pasif enumeration başlıyor...
[+] crt.sh'den 15 subdomain bulundu

[✓] www.google.com [142.251.152.119] → 200 (Google)
[✓] mail.google.com [142.251.142.101] → 200 (Gmail)
[✓] admin.google.com [142.251.208.110]
[✓] api.google.com [142.251.208.100] → 404
[✓] cloud.google.com [172.217.20.78] → 200 (Google Cloud)
[✓] docs.google.com [142.251.38.238] → 200 (Google Docs)
[✓] accounts.google.com [142.251.127.84] → 200 (Sign in)
[✓] blog.google.com [172.217.22.233] → 200 (The Keyword)
[✓] support.google.com [172.217.20.78] → 200 (Google Help)

╔══════════════════════════════════════════════════════════════╗
║                    TARAMA ÖZETİ                             ║
╚══════════════════════════════════════════════════════════════╝
[+] Hedef: google.com
[+] Taranan: 227 subdomain
[+] Bulunan: 36 aktif subdomain

Aktif subdomainler:
  → www.google.com [142.251.152.119] - 200
  → mail.google.com [142.251.142.101] - 200
  → admin.google.com [142.251.208.110]
  → cloud.google.com [172.217.20.78] - 200
  → docs.google.com [142.251.38.238] - 200
  → accounts.google.com [142.251.127.84] - 200
  → api.google.com [142.251.208.100] - 404
  → blog.google.com [172.217.22.233] - 200
  → support.google.com [172.217.20.78] - 200
  → shop.google.com [142.251.127.92] - 200
  → firebase.google.com [192.178.24.14] - 200
  → analytics.google.com [216.239.36.181] - 200
  → images.google.com [192.178.24.78] - 200
  → video.google.com [172.217.20.78] - 200
  → ... ve 21 tane daha

[+] JSON raporu kaydedildi: sonuc.json
```

---

## 🔧 Parametreler

| Parametre | Açıklama | Varsayılan |
|-----------|----------|------------|
| `domain` | Hedef domain | Zorunlu |
| `-w, --wordlist` | Wordlist dosyası | `wordlists/common.txt` |
| `-t, --threads` | Eşzamanlı görev sayısı | 50 |
| `-to, --timeout` | Zaman aşımı (saniye) | 5 |
| `-r, --retries` | DNS/HTTP retry sayısı | 2 |
| `-o, --output` | Çıktı dosyası (JSON/CSV) | Yok |
| `--format` | Çıktı formatı (json/csv) | json |
| `--dns-only` | Sadece DNS sorgusu | Kapalı |
| `--no-passive` | crt.sh pasif enumeration kapalı | Kapalı |
| `--permutations` | Wordlist varyasyonları üret | Kapalı |
| `--insecure` | HTTPS TLS sertifika doğrulamasını kapat | Kapalı |
| `--priority-policy` | Priority score policy JSON dosyası | Yok |
| `--profile` | Hazır priority profili (`default`, `redteam`, `bugbounty`, `quick`) | default |
| `--mode` | Tarama modu (`aggressive`, `balanced`, `strict`, `adaptive`) | balanced |
| `--min-priority` | Bu skorun altındaki sonuçları filtrele | 0 |
| `--top` | En yüksek öncelikli ilk N sonucu tut | 0 (kapalı) |
| `--verify-rounds` | DNS doğrulama turu (false-positive azaltma) | 2 |

---

## 🆕 v4.0 Değişiklikleri

- Pasif kaynaklar crt.sh + BufferOver olarak genişletildi (daha fazla sonuç).
- DNS doğrulama `A + AAAA + CNAME` ile güçlendirildi.
- Wildcard tespiti çoklu deneme ve CNAME desteği ile sıkılaştırıldı.
- `--verify-rounds` ile çoklu DNS stabilite kontrolü eklendi (false-positive azaltma).
- JSON şeması `2.0` oldu; çıktı metrikleri ve skor açıklamaları korunuyor.
- `--mode` ile hız/doğruluk için hazır presetler eklendi:
  - `aggressive`: daha hızlı ve geniş kapsam
  - `balanced`: dengeli varsayılan
  - `strict`: false-positive azaltma odaklı
  - `adaptive`: wildcard/hedef hacmine göre otomatik ayar

---

## 📁 Wordlist

Varsayılan wordlist (`wordlists/common.txt`) içeriği:

```
www, mail, ftp, admin, dev, test, api, blog, shop, support, login, 
secure, webmail, cpanel, whm, vpn, ns1, ns2, smtp, pop, imap, remote, 
git, jenkins, jira, confluence, wiki, docs, status, stats, monitor, 
backup, storage, cdn, static, media, assets, img, images, video, 
download, uploads, data, db, database, mysql, postgres, redis, elastic, 
grafana, prometheus, auth, oauth, sso, identity, account, dashboard, 
panel, gateway, proxy, lb, nginx, apache, tomcat, spring, app, apps, 
api-gateway, rest, graphql, socket, mqtt, kafka, spark, hadoop, mongo, 
elasticsearch, kibana, splunk, datadog, newrelic, jenkins, gitlab, 
github, docker, kube, kubernetes, k8s, istio, consul, vault, terraform
```

---

## 🚀 Performans

| Mod | Hız | Açıklama |
|-----|-----|----------|
| **DNS Only** | 300+ subdomain/saniye | Sadece DNS sorgusu |
| **Normal** | 10-50 subdomain/saniye | DNS + HTTP kontrolü |

---

## 🧪 Test ve CI

```bash
pip install pytest
pytest -q
```

Depoda GitHub Actions CI hattı bulunur; `push` ve `pull_request` olaylarında testler otomatik çalışır.

---

## 🛠️ Makefile Komutları

```bash
make install
make lint
make test
make bench
```

`make bench` varsayılan olarak DNS-only kısa bir performans koşusu yapar. Farklı hedef için:

```bash
make bench BENCH_DOMAIN=target.com BENCH_THREADS=80 BENCH_TIMEOUT=5
```

---

## ⚠️ Uyarı

> Bu araç **eğitim ve yetkili testler** için geliştirilmiştir. İzinsiz tarama yapmak yasa dışı olabilir. Sorumluluk kullanıcıya aittir.

## ⭐ Star Atmayı Unutma!

Beğendiysen GitHub'da ⭐ bırakmayı unutma!

---

## 📌 GitHub Paylaşım Notu

Projeyi paylaşmadan önce aşağıdakileri kontrol et:
- Yetkisiz hedeflere karşı kullanılmaması için etik/yasal uyarıyı koru.
- Yeni sürümde değişiklikleri `CHANGELOG.md` dosyasında güncel tut.
- CI (`.github/workflows/ci.yml`) geçtiğinden emin ol.
