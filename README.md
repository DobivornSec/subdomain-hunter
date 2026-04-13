# Dobivorn Subdomain Hunter 🐉

Basit ve hızlı bir subdomain bulma aracı. Hedef domain'in alt alanlarını tespit eder.

## Özellikler

- 🔍 Wordlist tabanlı subdomain taraması
- ⚡ HTTP/HTTPS desteği
- 📊 Durum kodu gösterimi
- 🎯 Basit ve hafif

## Kurulum

git clone https://github.com/DobivornSec/subdomain-hunter.git
cd subdomain-hunter
pip install -r requirements.txt

## Kullanım

python3 subhunter.py example.com

## Ornek Çıktı

[✓] https://www.google.com → Durum: 200
[✓] https://mail.google.com → Durum: 301
[✓] https://admin.google.com → Durum: 302

Yapılacaklar

    Thread desteği (hızlandırma)

    DNS sorgusu ekleme

    Daha büyük wordlist

    JSON/CSV çıktı

Lisans

MIT

