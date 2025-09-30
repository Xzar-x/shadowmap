ShadowMap: Automated Reconnaissance Toolkit

https://raw.githubusercontent.com/Xzar-x/images/refs/heads/main/shadowmap.png

https://img.shields.io/badge/version-1.0.0-blue.svg
https://img.shields.io/badge/license-MIT-green.svg
https://img.shields.io/badge/python-3.8%2B-blue
https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey

ShadowMap to zaawansowany, zautomatyzowany zestaw narzędzi do rekonesansu bezpieczeństwa, który przeprowadza kompleksowe skanowanie celów w pięciu zintegrowanych fazach.

---

📖 Spis Treści

· O Projekcie
· ✨ Kluczowe Funkcjonalności
· 🛠️ Zbudowano przy użyciu
· 🚀 Pierwsze Kroki
  · Wymagania
  · Instalacja
· 💻 Sposób Użycia
  · Podstawowe Użycie
  · Tryb Automatyczny
  · Przykładowe Komendy
· 📊 Fazy Skanowania
· 📁 Struktura Projektu
· 🤝 Kontrybucja
· 📄 Licencja
· 👤 Kontakt i Autor

---

🎯 O Projekcie

ShadowMap powstał z myślą o automatyzacji czasochłonnych procesów rekonesansu bezpieczeństwa. Narzędzie łączy w sobie dziesiątki specjalistycznych narzędzi open-source w spójny, wielofazowy pipeline, który przeprowadza użytkownika od podstawowego zwiadu pasywnego (OSINT) aż do zaawansowanego web crawlingu.

Projekt rozwiązuje problem fragmentacji narzędzi rekonesansu - zamiast uruchamiać dziesiątki oddzielnych skryptów, ShadowMap zarządza całym procesem, agreguje wyniki i generuje szczegółowy, interaktywny raport HTML.

[TUTAJ WSTAW ZRZUT EKRANU LUB GIF PREZENTUJĄCY APLIKACJĘ]

---

✨ Kluczowe Funkcjonalności

· 🔍 Wielofazowy Rekonesans - 5 zintegrowanych faz skanowania (OSINT, subdomeny, porty, katalogi, web crawling)
· 🎯 Inteligentna Detekcja - Automatyczne wykrywanie technologii i dostosowywanie skanowania
· 🛡️ Tryb Bezpieczny - Konfigurowalne ograniczenia prędkości i agresywności skanowania
· 📊 Interaktywne Raporty - Zaawansowane raporty HTML z filtrowaniem i kategoryzacją wyników
· 🔄 Rotacja User-Agent - Automatyczna rotacja nagłówków dla uniknięcia detekcji
· ⚡ Równoległe Przetwarzanie - Wielowątkowe wykonanie narzędzi dla maksymalnej wydajności
· 🎨 Intuicyjny Interfejs - Kolorowy interfejs konsolowy z Rich oraz menu wyboru
· 🤖 Tryb Automatyczny - Pełna automatyzacja bez interakcji użytkownika
· 🕵️ Monitor WAF - Detekcja i monitorowanie systemów ochrony WAF/IPS

---

🛠️ Zbudowano przy użyciu

🐍 Języki Programowania

https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white
https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white

📚 Biblioteki Python

· Rich - 🎨 Zaawansowane formatowanie konsoli
· Typer - ⚡ Nowoczesne CLI framework
· Questionary - ❓ Interaktywne pytania użytkownika
· Requests - 🌐 Żądania HTTP
· WebTech - 🔍 Detekcja technologii web

🛠️ Narzędzia Rekonesansu

· Subfinder/Assetfinder - 🔎 Odkrywanie subdomen
· Naabu/Masscan/Nmap - 🚪 Skanowanie portów
· FFuf/Feroxbuster/Dirsearch - 📁 Bruteforce katalogów
· Katana/Hakrawler - 🕸️ Web crawling
· Httpx - 🌐 Weryfikacja hostów HTTP
· WhatWeb - 🔍 Analiza technologii web

---

🚀 Pierwsze Kroki

Wymagania

Przed instalacją upewnij się, że masz zainstalowane:

· Python 3.8+
· Go 1.19+
· System Linux lub macOS

```bash
# Sprawdzenie wersji Python
python3 --version

# Sprawdzenie wersji Go
go version
```

Instalacja

1. Sklonuj repozytorium

```bash
git clone https://github.com/Xzar-x/shadowmap.git
cd shadowmap
```

1. Uruchom skrypt instalacyjny

```bash
sudo python3 install.py
```

Skrypt instalacyjny automatycznie:

· ✅ Sprawdzi dostępne zależności systemowe
· 📦 Zainstaluje brakujące pakiety (nmap, masscan, whois, whatweb)
· 🔧 Zainstaluje narzędzia Go (subfinder, assetfinder, httpx, naabu, ffuf, itd.)
· 🐍 Zainstaluje pakiety Python (rich, questionary, requests, itp.)
· 📁 Skopiuje pliki do /usr/local/bin/ i /usr/local/share/shadowmap/

1. Weryfikacja instalacji

```bash
shadowmap --help
```

---

💻 Sposób Użycia

Podstawowe Użycie

```bash
# Podstawowe skanowanie pojedynczego celu
shadowmap example.com

# Skanowanie z listy celów
shadowmap -l targets.txt

# Określenie katalogu wyjściowego
shadowmap -o /path/to/reports example.com

# Włączenie trybu bezpiecznego
shadowmap --safe-mode example.com

# Użycie proxy
shadowmap --proxy socks5://127.0.0.1:9050 example.com
```

Tryb Automatyczny

```bash
# Pełna automatyzacja - uruchamia wszystkie fazy bez interakcji
shadowmap -y example.com

# Automatyczne skanowanie listy celów
shadowmap -y -l targets.txt -o reports/
```

Przykładowe Komendy

```bash
# Kompleksowe skanowanie z raportem w custom katalogu
shadowmap -y --safe-mode -o /home/user/scan-reports target-company.com

# Szybkie skanowanie bez trybu bezpiecznego
shadowmap -q --proxy http://proxy:8080 example.org

# Skanowanie z wykluczeniem określonych subdomen
shadowmap -e "dev.example.com" -e "test.example.com" example.com
```

---

📊 Fazy Skanowania

ShadowMap przeprowadza skanowanie w 5 następujących fazach:

🎯 Faza 0: OSINT (Open Source Intelligence)

· WHOIS information gathering
· Detekcja technologii (WhatWeb, WebTech)
· Analiza ASN i CDN
· Wyszukiwanie publicznych exploitów (SearchSploit)
· Zbieranie informacji o IP i infrastrukturze

🔍 Faza 1: Odkrywanie Subdomen

· Subfinder, Assetfinder, Findomain (pasywne)
· Puredns bruteforce (aktywne)
· Weryfikacja hostów HTTP/S (Httpx)
· Filtrowanie i agregacja wyników

🚪 Faza 2: Skanowanie Portów

· Naabu (szybkie odkrywanie portów)
· Masscan (super szybkie skanowanie dużych zakresów)
· Nmap (szczegółowa analiza usług i wersji)
· Agregacja i kategoryzacja otwartych portów

📁 Faza 3: Wyszukiwanie Katalogów

· FFuf, Feroxbuster, Dirsearch, Gobuster
· Inteligentne filtrowanie wyników (rozmiar, status)
· Detekcja odpowiedzi wildcard
· Rekurencyjne przeszukiwanie
· Weryfikacja wyników przez Httpx

🕸️ Faza 4: Web Crawling & Discovery

· Katana (zaawansowany crawler)
· Hakrawler (szybki crawler)
· ParamSpider (odkrywanie parametrów URL)
· LinkFinder (analiza plików JavaScript)
· Gauplus (pasywne zbieranie URL z archiwów)
· Kategoryzacja znalezionych URL (API, parametry, pliki JS, itp.)

---

📁 Struktura Projektu

```
/usr/local/share/shadowmap/
├── shadowmap.py              # Główny skrypt
├── config.py                 # Konfiguracja i stałe
├── utils.py                  # Narzędzia pomocnicze
├── phase0_osint.py           # Faza 0: OSINT
├── phase1_subdomain.py       # Faza 1: Subdomeny
├── phase2_port_scanning.py   # Faza 2: Porty
├── phase3_dirsearch.py       # Faza 3: Katalogi
├── phase4_webcrawling.py     # Faza 4: Web Crawling
├── report_template.html      # Szablon raportu HTML
├── resolvers.txt            # Lista resolverów DNS
├── user_agents.txt          # Lista User-Agentów
└── install.py               # Skrypt instalacyjny
```

---

🤝 Kontrybucja

Contributions są mile widziane! Jeśli chcesz przyczynić się do rozwoju ShadowMap:

1. 🍴 Sforkuj repozytorium
2. 🌿 Stwórz branch dla swojej funkcjonalności (git checkout -b feature/amazing-feature)
3. 💾 Commit swoich zmian (git commit -m 'Add some amazing feature')
4. 📤 Push do brancha (git push origin feature/amazing-feature)
5. 🔄 Otwórz Pull Request

Zgłaszanie błędów:

· Użyj sekcji Issues
· Dołącz szczegółowy opis problemu, kroki reprodukcji i logi błędów

---

📄 Licencja

Ten projekt jest dystrybuowany na licencji MIT. Zobacz plik LICENSE.txt po więcej informacji.

---

👤 Kontakt i Autor

· Autor: Xzar
· GitHub: https://github.com/Xzar-x
· Email: [TWÓJ EMAIL]
· Repozytorium: https://github.com/Xzar-x/shadowmap

---

<div align="center">

ShadowMap - Your Automated Reconnaissance Companion 🔍

</div>