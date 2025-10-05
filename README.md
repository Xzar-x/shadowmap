<div align="center">
<img src="https://www.google.com/search?q=https://raw.githubusercontent.com/Xzar-x/images/main/shadowmap.png" alt="ShadowMap Banner" width="700"/>
</div>
<div align="center">
ShadowMap: Zautomatyzowany Zestaw Narzędzi do Rekonesansu
ShadowMap to zaawansowany, zautomatyzowany zestaw narzędzi do rekonesansu, który przeprowadza kompleksowe skanowanie celów w pięciu zintegrowanych fazach, od pasywnego zwiadu (OSINT) aż po zaawansowany web crawling.
</div>
📖 Spis Treści
 * O Projekcie
 * ✨ Kluczowe Funkcjonalności
 * 🛠️ Użyte Narzędzia
 * 🚀 Pierwsze Kroki
 * 💻 Sposób Użycia
 * 📊 Fazy Skanowania
 * 📄 Raporty
 * 📁 Struktura Projektu
 * 🤝 Kontrybucja
 * 📄 Licencja
 * 👤 Autor
🎯 O Projekcie
ShadowMap powstał z myślą o automatyzacji i integracji czasochłonnych procesów rekonesansu. Narzędzie łączy w sobie potencjał kilkudziesięciu wiodących narzędzi open-source w jeden, spójny pipeline. Zamiast ręcznie uruchamiać i agregować wyniki z wielu skryptów, ShadowMap orkiestruje całym procesem, inteligentnie dostosowuje skanowanie i generuje przejrzysty, interaktywny raport HTML.
✨ Kluczowe Funkcjonalności
 * 🔍 Wielofazowy Rekonesans: 5 zintegrowanych faz (OSINT, Subdomeny, Porty, Katalogi, Web Crawling).
 * 🤖 Pełna Automatyzacja: Tryb -y (--yes) do uruchomienia wszystkich faz bez interakcji.
 * 🛡️ Detekcja i Adaptacja: Automatyczne wykrywanie WAF (wafw00f) z opcją włączenia trybu Safe Mode (wolniejsze, mniej agresywne skanowanie).
 * 📊 Interaktywne Raporty: Nowoczesne raporty HTML z dynamicznym filtrowaniem, kartami wyników, wizualizacją portów i kategoryzacją danych.
 * 💥 Integracja z Searchsploit: Automatyczne wyszukiwanie i ocena publicznych exploitów dla wykrytych technologii.
 * 🧠 Inteligentne Skanowanie: Automatyczny dobór list słów na podstawie wykrytych technologii (np. WordPress, Joomla) oraz detekcja odpowiedzi wildcard.
 * ⚡ Równoległe Przetwarzanie: Wielowątkowe wykonanie narzędzi dla maksymalnej wydajności.
 * 🎨 Intuicyjny Interfejs: Kolorowy, interaktywny interfejs w konsoli zbudowany z rich.
 * ⚙️ Wysoka Konfigurowalność: Zaawansowane menu ustawień dla każdej fazy skanowania (limity prędkości, głębokość rekursji, własne skrypty Nmap itp.).
 * 📤 Podwójny Format Raportów: Generowanie raportów w formacie HTML (dla ludzi) oraz JSON (dla maszyn).
🛠️ Użyte Narzędzia
ShadowMap integruje następujące narzędzia zewnętrzne:
| Kategoria | Narzędzia |
|---|---|
| OSINT | whois, httpx, whatweb, wafw00f, searchsploit |
| Subdomeny | subfinder, assetfinder, findomain, puredns |
| Skanowanie Portów | nmap, naabu, masscan |
| Katalogi i Pliki | ffuf, feroxbuster, dirsearch, gobuster |
| Web Crawling | katana, hakrawler, paramspider, linkfinder, gauplus |
🚀 Pierwsze Kroki
Wymagania
 * System: Linux (zalecany Debian/Ubuntu) lub macOS
 * Python 3.8+ i pip3
 * Go 1.19+
Instalacja
 * Sklonuj repozytorium
   git clone [https://github.com/Xzar-x/shadowmap.git](https://github.com/Xzar-x/shadowmap.git)
cd shadowmap

 * Uruchom skrypt instalacyjny
   Zalecane jest uruchomienie z sudo w celu instalacji globalnej.
   sudo ./install.py

   Skrypt automatycznie:
   * ✅ Sprawdzi i zainstaluje zależności systemowe (apt).
   * 🐹 Zainstaluje narzędzia napisane w Go.
   * 🐍 Zainstaluje narzędzia i biblioteki Python (pip, pipx).
   * 📁 Skopiuje pliki do /usr/local/bin/ i /usr/local/share/shadowmap/.
 * Weryfikacja instalacji
   shadowmap --help

💻 Sposób Użycia
Podstawowe Komendy
# Skanowanie interaktywne pojedynczego celu
shadowmap example.com

# Skanowanie z listy celów w pliku (automatycznie włącza tryb cichy)
shadowmap -l targets.txt

# Zapis raportu do konkretnego katalogu
shadowmap -o /scans/reports/ example.com

# Włączenie trybu bezpiecznego (wolniej, ale ostrożniej)
shadowmap --safe-mode example.com

# Użycie proxy SOCKS5 (np. z Tor)
shadowmap --proxy socks5://127.0.0.1:9050 example.com

Tryb Automatyczny (zalecany)
# Pełna automatyzacja - uruchamia wszystkie fazy bez interakcji
shadowmap -y example.com

# Automatyczne skanowanie listy celów z zapisem do katalogu 'reports'
shadowmap -y -l targets.txt -o reports/

📊 Fazy Skanowania
| Faza | Opis |
|---|---|
| 🎯 Faza 0: OSINT | Zbieranie informacji WHOIS, analiza IP/ASN/CDN, detekcja technologii web (whatweb, httpx), oraz wyszukiwanie publicznych exploitów (searchsploit) dla zidentyfikowanych technologii. |
| 🔍 Faza 1: Odkrywanie Subdomen | Użycie subfinder, assetfinder, findomain (pasywnie) oraz puredns (bruteforce) do enumeracji subdomen. Aktywne hosty są następnie weryfikowane za pomocą httpx. |
| 🚪 Faza 2: Skanowanie Portów | Szybkie odkrywanie otwartych portów za pomocą naabu i masscan, a następnie szczegółowa analiza usług, wersji i podatności za pomocą nmap na znalezionych portach. |
| 📁 Faza 3: Wyszukiwanie Katalogów | Bruteforce katalogów i plików z użyciem ffuf, feroxbuster, dirsearch i gobuster. Wyniki są inteligentnie filtrowane (wildcard detection) i weryfikowane przez httpx. |
| 🕸️ Faza 4: Web Crawling | Głębokie skanowanie aplikacji web za pomocą katana i hakrawler. ParamSpider odkrywa parametry URL, linkfinder analizuje pliki JS, a gauplus zbiera URL z archiwów. |
📄 Raporty
ShadowMap generuje dwa rodzaje raportów w katalogu report_<cel>_<data>:
 * Interaktywny Raport HTML (report.html)
   * Nowoczesny i przejrzysty design.
   * Osobne zakładki dla każdej fazy skanowania.
   * Dynamiczne filtrowanie wyników (np. "pokaż tylko krytyczne").
   * Kategoryzacja URL-i (parametry, API, pliki JS).
   * Wizualne podsumowanie skanowania portów.
   * Szczegółowe wyniki wyszukiwania exploitów wraz z oceną punktową.
   * Kopiowanie wyników do schowka jednym kliknięciem.
 * Raport JSON (report.json)
   * Ustrukturyzowane dane wyjściowe ze wszystkich faz.
   * Idealny do integracji z innymi narzędziami i dalszej automatyzacji.
📁 Struktura Projektu
/usr/local/share/shadowmap/
├── shadowmap.py              # Główny skrypt orkiestrujący
├── config.py                 # Konfiguracja globalna i stałe
├── utils.py                  # Funkcje pomocnicze
├── phase0_osint.py           # Logika Fazy 0: OSINT
├── phase1_subdomain.py       # Logika Fazy 1: Subdomeny
├── phase2_port_scanning.py   # Logika Fazy 2: Porty
├── phase3_dirsearch.py       # Logika Fazy 3: Katalogi
├── phase4_webcrawling.py     # Logika Fazy 4: Web Crawling
├── report_template.html      # Szablon raportu HTML
├── resolvers.txt             # Lista resolverów DNS
├── user_agents.txt           # Lista User-Agentów
└── install.py                # Skrypt instalacyjny

🤝 Kontrybucja
Wszelkie kontrybucje są mile widziane! Jeśli chcesz pomóc w rozwoju ShadowMap:
 * 🍴 Sforkuj repozytorium.
 * 🌿 Stwórz nowy branch (git checkout -b feature/AmazingFeature).
 * 💾 Zapisz swoje zmiany (git commit -m 'Add some AmazingFeature').
 * 📤 Wypchnij zmiany do swojego brancha (git push origin feature/AmazingFeature).
 * 🔄 Otwórz Pull Request.
W przypadku znalezienia błędów, proszę o zgłoszenie ich w sekcji Issues repozytorium.
📄 Licencja
Projekt jest dystrybuowany na licencji MIT. Zobacz plik LICENSE po więcej informacji.
👤 Autor
 * Xzar - GitHub
<br>
<div align="center">
<strong>ShadowMap - Twój Zautomatyzowany Towarzysz Rekonesansu 🗺️</strong>
</div>
