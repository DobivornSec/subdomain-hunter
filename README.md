# 🐉 Subdomain Hunter v2.5

> **3 Başlı Ejderha** | Red Team | Purple Team | Blue Team

Hedef domain'in alt alanlarını hızlı ve etkili bir şekilde tespit eden **profesyonel** subdomain bulma aracı. Asenkron DNS, pasif enumeration ve çoklu thread desteği ile donatılmıştır.

---

## ✨ Özellikler

| Özellik | Açıklama |
|---------|----------|
| ⚡ **Asenkron DNS** | 300+ subdomain/saniye hız |
| 🔍 **Wordlist tabanlı** | 150+ yaygın subdomain |
| 🕵️ **Pasif Enumeration** | crt.sh'den SSL sertifikalarıyla subdomain bulma |
| 🌐 **HTTP/HTTPS Kontrol** | Durum kodu, başlık, server bilgisi |
| 🎯 **Wildcard Tespiti** | Sahte sonuçları filtreleme |
| 📊 **DNS Only Mod** | Sadece DNS sorgusu (çok hızlı) |
| 📁 **JSON/CSV Rapor** | Yapılandırılmış çıktı |
| 🎨 **Renkli Çıktı** | Durum kodlarına göre renklendirme |
| ⏱️ **Timeout Ayarları** | Zaman aşımı konfigürasyonu |

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

---

## 📊 Örnek Çıktı

```bash
╔══════════════════════════════════════════════════════════════╗
║   🐉 Subdomain Hunter v2.5 - 3 Başlı Ejderha                  ║
║   🔴 Red Team | 🟣 Purple Team | 🔵 Blue Team                ║
║   ⚡ Async DNS | crt.sh | Permutation | JSON/CSV             ║
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
| `-t, --threads` | Thread sayısı | 50 |
| `-to, --timeout` | Zaman aşımı (saniye) | 5 |
| `-o, --output` | Çıktı dosyası (JSON/CSV) | Yok |
| `--format` | Çıktı formatı (json/csv) | json |
| `--dns-only` | Sadece DNS sorgusu | Kapalı |

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

## ⚠️ Uyarı

> Bu araç **eğitim ve yetkili testler** için geliştirilmiştir. İzinsiz tarama yapmak yasa dışı olabilir. Sorumluluk kullanıcıya aittir.

## ⭐ Star Atmayı Unutma!

Beğendiysen GitHub'da ⭐ bırakmayı unutma!
