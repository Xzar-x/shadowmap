# /usr/local/share/shadowmap/config.py

import os
from typing import Dict, List, Optional

# --- Ścieżki i stałe ---
SHARE_DIR = "/usr/local/share/shadowmap/"
HTML_TEMPLATE_PATH = os.path.join(SHARE_DIR, "report_template.html")
USER_AGENTS_FILE = os.path.join(SHARE_DIR, "user_agents.txt")

DEFAULT_WORDLIST_PHASE1 = (
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
)
SMALL_WORDLIST_PHASE1 = (
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
)

DEFAULT_WORDLIST_PHASE3 = "/usr/share/dirb/wordlists/common.txt"
SMALL_WORDLIST_PHASE3 = "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt"

WORDPRESS_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt"
JOOMLA_WORDLIST = (
    "/usr/share/seclists/Discovery/Web-Content/CMS/trickest-cms-wordlist/joomla.txt"
)
DRUPAL_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/CMS/Drupal.txt"
TOMCAT_WORDLIST = (
    "/usr/share/seclists/Discovery/Web-Content/CMS/trickest-cms-wordlist/tomcat.txt"
)

DEFAULT_RESOLVERS_FILE = os.path.join(SHARE_DIR, "resolvers.txt")

TECH_SPECIFIC_WORDLISTS: Dict[str, str] = {
    "wordpress": WORDPRESS_WORDLIST,
    "joomla": JOOMLA_WORDLIST,
    "drupal": DRUPAL_WORDLIST,
    "tomcat": TOMCAT_WORDLIST,
    "apache tomcat": TOMCAT_WORDLIST,
}

# Mapa nazw wyświetlanych w menu na nazwy plików wykonywalnych
TOOL_EXECUTABLE_MAP: Dict[str, str] = {
    # Faza 1
    "Subfinder": "subfinder",
    "Assetfinder": "assetfinder",
    "Findomain": "findomain",
    "Puredns (bruteforce)": "puredns",
    # Faza 2
    "Nmap (szczegóły)": "nmap",
    "Naabu (szybkie odkrywanie)": "naabu",
    "Masscan (super szybkie)": "masscan",
    # Faza 3
    "Ffuf": "ffuf",
    "Feroxbuster": "feroxbuster",
    "Dirsearch": "dirsearch",
    "Gobuster": "gobuster",
    # Faza 4
    "Katana (Aktywny crawler)": "katana",
    "Hakrawler (Aktywny crawler)": "hakrawler",
    "ParamSpider (Parametry)": "paramspider",
    "LinkFinder (Analiza JS)": "linkfinder",
    "Gauplus (Pasywne z archiwów)": "gauplus",
}


# --- Globalne zmienne stanu i konfiguracji ---
LOG_FILE: Optional[str] = None
QUIET_MODE: bool = False
AUTO_MODE: bool = False
OUTPUT_BASE_DIR: str = os.getcwd()
REPORT_DIR: str = ""
TEMP_FILES_TO_CLEAN: List[str] = []
SAFE_MODE: bool = False
CUSTOM_HEADER: str = ""  # Tutaj trafi Twój custom User-Agent (np. Xzar-integrity)
PROXY: Optional[str] = None
EXCLUSION_PATTERNS: List[str] = []  # Stara zmienna (kompatybilność)
OUT_OF_SCOPE_ITEMS: List[str] = []  # NOWA: Globalna lista wykluczeń (domeny/pliki)
MISSING_TOOLS: List[str] = []  # Nowa zmienna przechowująca brakujące narzędzia

# --- Filtrowanie OSINT ---
OSINT_TECH_BLOCKLIST: List[str] = [
    "ip",
    "script",
    "title",
    "country",
    "email",
    "httpserver",
    "uncommonheaders",
    "redirectlocation",
    "metagenerator",
    "html5",
]


# --- Stan celu ---
ORIGINAL_TARGET: str = ""
HOSTNAME_TARGET: str = ""
CLEAN_DOMAIN_TARGET: str = ""
TARGET_IS_IP: bool = False

# --- Ustawienia narzędzi ---
THREADS: int = 40
TOOL_TIMEOUT_SECONDS: int = 1800
RECURSION_DEPTH_P3: int = 1
CRAWL_DEPTH_P4: int = 2
AUTO_FORM_FILL: bool = False
WORDLIST_PHASE1: str = DEFAULT_WORDLIST_PHASE1
WORDLIST_PHASE3: str = DEFAULT_WORDLIST_PHASE3
RESOLVERS_FILE: str = DEFAULT_RESOLVERS_FILE

# --- Ustawienia Fazy 1 ---
PUREDNS_RATE_LIMIT: int = 1000
HTTPX_P1_RATE_LIMIT: int = 150

# --- Ustawienia Fazy 2 ---
NMAP_USE_SCRIPTS: bool = False
NMAP_AGGRESSIVE_SCAN: bool = False
NMAP_CUSTOM_SCRIPTS: str = ""
NAABU_SOURCE_PORT: Optional[str] = None
MASSCAN_RATE: int = 300
NAABU_RATE: int = 1000
# Strategia skanowania Nmapa gdy działa sam (bez Naabu/Masscan)
# Opcje: "top1000", "all", "custom"
NMAP_SCAN_STRATEGY: str = "top1000"
NMAP_CUSTOM_PORT_RANGE: str = ""
EXCLUDED_PORTS: List[int] = []

# --- Ustawienia Fazy 3 ---
DIRSEARCH_SMART_FILTER: bool = True
FEROXBUSTER_SMART_FILTER: bool = True
IGNORED_EXTENSIONS: List[str] = [
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "bmp",
    "ico",
    "css",
    "js",
    "map",
    "woff",
    "woff2",
    "ttf",
    "eot",
]


# --- Ustawienia Super Safe Mode ---
USE_HEADLESS_BROWSER: bool = False
WAF_CHECK_ENABLED: bool = True
WAF_CHECK_INTERVAL_MIN_NORMAL: int = 5
WAF_CHECK_INTERVAL_MAX_NORMAL: int = 15
WAF_CHECK_INTERVAL_MIN_SAFE: int = 30
WAF_CHECK_INTERVAL_MAX_SAFE: int = 60


# --- Wybrane narzędzia ---
# Domyślnie wyłączone dla trybu interaktywnego
selected_phase1_tools: List[int] = [0, 0, 0, 0]
selected_phase2_tools: List[int] = [0, 0, 0]
selected_phase3_tools: List[int] = [0, 0, 0, 0]
selected_phase4_tools: List[int] = [0, 0, 0, 0, 0]

# Domyślnie włączone dla trybu cichego/automatycznego (-y)
silent_selected_phase1_tools: List[int] = [1, 1, 1, 1]
silent_selected_phase2_tools: List[int] = [1, 1, 1]
silent_selected_phase3_tools: List[int] = [1, 1, 1, 1]
silent_selected_phase4_tools: List[int] = [1, 1, 1, 1, 1]


# --- Flagi ręcznych zmian przez użytkownika ---
# Jeśli te flagi są True, ignorujemy ustawienia automatyczne/Safe Mode
USER_CUSTOMIZED_WORDLIST_PHASE1: bool = False
USER_CUSTOMIZED_WORDLIST_PHASE3: bool = False
USER_CUSTOMIZED_USER_AGENT: bool = False
USER_CUSTOMIZED_THREADS: bool = False
USER_CUSTOMIZED_TIMEOUT: bool = False
USER_CUSTOMIZED_RECURSION_DEPTH_P3: bool = False
USER_CUSTOMIZED_CRAWL_DEPTH_P4: bool = False
USER_CUSTOMIZED_RESOLVERS: bool = False
USER_CUSTOMIZED_PROXY: bool = False
USER_CUSTOMIZED_AUTO_FORM_FILL: bool = False
USER_CUSTOMIZED_NAABU_SOURCE_PORT: bool = False
USER_CUSTOMIZED_MASSCAN_RATE: bool = False
USER_CUSTOMIZED_NAABU_RATE: bool = False
USER_CUSTOMIZED_NMAP_STRATEGY: bool = False
USER_CUSTOMIZED_NMAP_SCRIPTS: bool = False
USER_CUSTOMIZED_USE_HEADLESS: bool = False
USER_CUSTOMIZED_PUREDNS_RATE_LIMIT: bool = False
USER_CUSTOMIZED_HTTPX_P1_RATE_LIMIT: bool = False
USER_CUSTOMIZED_IGNORED_EXTENSIONS: bool = False
# /usr/local/share/shadowmap/config.py

import os
from typing import Dict, List, Optional

# --- Ścieżki i stałe ---
SHARE_DIR = "/usr/local/share/shadowmap/"
HTML_TEMPLATE_PATH = os.path.join(SHARE_DIR, "report_template.html")
USER_AGENTS_FILE = os.path.join(SHARE_DIR, "user_agents.txt")

DEFAULT_WORDLIST_PHASE1 = (
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
)
SMALL_WORDLIST_PHASE1 = (
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
)

DEFAULT_WORDLIST_PHASE3 = "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
SMALL_WORDLIST_PHASE3 = "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt"

WORDPRESS_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt"
JOOMLA_WORDLIST = (
    "/usr/share/seclists/Discovery/Web-Content/CMS/trickest-cms-wordlist/joomla.txt"
)
DRUPAL_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/CMS/Drupal.txt"
TOMCAT_WORDLIST = (
    "/usr/share/seclists/Discovery/Web-Content/CMS/trickest-cms-wordlist/tomcat.txt"
)

DEFAULT_RESOLVERS_FILE = os.path.join(SHARE_DIR, "resolvers.txt")

TECH_SPECIFIC_WORDLISTS: Dict[str, str] = {
    "wordpress": WORDPRESS_WORDLIST,
    "joomla": JOOMLA_WORDLIST,
    "drupal": DRUPAL_WORDLIST,
    "tomcat": TOMCAT_WORDLIST,
    "apache tomcat": TOMCAT_WORDLIST,
}

# Mapa nazw wyświetlanych w menu na nazwy plików wykonywalnych
TOOL_EXECUTABLE_MAP: Dict[str, str] = {
    # Faza 1
    "Subfinder": "subfinder",
    "Assetfinder": "assetfinder",
    "Findomain": "findomain",
    "Puredns (bruteforce)": "puredns",
    # Faza 2
    "Nmap (szczegóły)": "nmap",
    "Naabu (szybkie odkrywanie)": "naabu",
    "Masscan (super szybkie)": "masscan",
    # Faza 3
    "Ffuf": "ffuf",
    "Feroxbuster": "feroxbuster",
    "Dirsearch": "dirsearch",
    "Gobuster": "gobuster",
    # Faza 4
    "Katana (Aktywny crawler)": "katana",
    "Hakrawler (Aktywny crawler)": "hakrawler",
    "ParamSpider (Parametry)": "paramspider",
    "LinkFinder (Analiza JS)": "linkfinder",
    "Gauplus (Pasywne z archiwów)": "gauplus",
}


# --- Globalne zmienne stanu i konfiguracji ---
LOG_FILE: Optional[str] = None
QUIET_MODE: bool = False
AUTO_MODE: bool = False
OUTPUT_BASE_DIR: str = os.getcwd()
REPORT_DIR: str = ""
TEMP_FILES_TO_CLEAN: List[str] = []
SAFE_MODE: bool = False
CUSTOM_HEADER: str = ""  # Tutaj trafi Twój custom User-Agent (np. Xzar-integrity)
PROXY: Optional[str] = None
EXCLUSION_PATTERNS: List[str] = []  # Stara zmienna (kompatybilność)
OUT_OF_SCOPE_ITEMS: List[str] = []  # NOWA: Globalna lista wykluczeń (domeny/pliki)
MISSING_TOOLS: List[str] = []  # Nowa zmienna przechowująca brakujące narzędzia

# --- Filtrowanie OSINT ---
OSINT_TECH_BLOCKLIST: List[str] = [
    "ip",
    "script",
    "title",
    "country",
    "email",
    "httpserver",
    "uncommonheaders",
    "redirectlocation",
    "metagenerator",
    "html5",
]


# --- Stan celu ---
ORIGINAL_TARGET: str = ""
HOSTNAME_TARGET: str = ""
CLEAN_DOMAIN_TARGET: str = ""
TARGET_IS_IP: bool = False

# --- Ustawienia narzędzi ---
THREADS: int = 40
TOOL_TIMEOUT_SECONDS: int = 1800
RECURSION_DEPTH_P3: int = 1
CRAWL_DEPTH_P4: int = 2
AUTO_FORM_FILL: bool = False
WORDLIST_PHASE1: str = DEFAULT_WORDLIST_PHASE1
WORDLIST_PHASE3: str = DEFAULT_WORDLIST_PHASE3
RESOLVERS_FILE: str = DEFAULT_RESOLVERS_FILE

# --- Ustawienia Fazy 1 ---
PUREDNS_RATE_LIMIT: int = 1000
HTTPX_P1_RATE_LIMIT: int = 150

# --- Ustawienia Fazy 2 ---
NMAP_USE_SCRIPTS: bool = False
NMAP_AGGRESSIVE_SCAN: bool = False
NMAP_CUSTOM_SCRIPTS: str = ""
NAABU_SOURCE_PORT: Optional[str] = None
MASSCAN_RATE: int = 300
NAABU_RATE: int = 1000
# Strategia skanowania Nmapa gdy działa sam (bez Naabu/Masscan)
# Opcje: "top1000", "all", "custom"
NMAP_SCAN_STRATEGY: str = "top1000"
NMAP_CUSTOM_PORT_RANGE: str = ""
EXCLUDED_PORTS: List[int] = []
# --- NOWE: Interfejs dla Masscan ---
MASSCAN_INTERFACE: Optional[str] = None # np. "tun0" dla HTB

# --- Ustawienia Fazy 3 ---
DIRSEARCH_SMART_FILTER: bool = True
FEROXBUSTER_SMART_FILTER: bool = True
IGNORED_EXTENSIONS: List[str] = [
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "bmp",
    "ico",
    "css",
    "js",
    "map",
    "woff",
    "woff2",
    "ttf",
    "eot",
]


# --- Ustawienia Super Safe Mode ---
USE_HEADLESS_BROWSER: bool = False
WAF_CHECK_ENABLED: bool = True
WAF_CHECK_INTERVAL_MIN_NORMAL: int = 5
WAF_CHECK_INTERVAL_MAX_NORMAL: int = 15
WAF_CHECK_INTERVAL_MIN_SAFE: int = 30
WAF_CHECK_INTERVAL_MAX_SAFE: int = 60


# --- Wybrane narzędzia ---
# Domyślnie wyłączone dla trybu interaktywnego
selected_phase1_tools: List[int] = [0, 0, 0, 0]
selected_phase2_tools: List[int] = [0, 0, 0]
selected_phase3_tools: List[int] = [0, 0, 0, 0]
selected_phase4_tools: List[int] = [0, 0, 0, 0, 0]

# Domyślnie włączone dla trybu cichego/automatycznego (-y)
silent_selected_phase1_tools: List[int] = [1, 1, 1, 1]
silent_selected_phase2_tools: List[int] = [1, 1, 1]
silent_selected_phase3_tools: List[int] = [1, 1, 1, 1]
silent_selected_phase4_tools: List[int] = [1, 1, 1, 1, 1]


# --- Flagi ręcznych zmian przez użytkownika ---
# Jeśli te flagi są True, ignorujemy ustawienia automatyczne/Safe Mode
USER_CUSTOMIZED_WORDLIST_PHASE1: bool = False
USER_CUSTOMIZED_WORDLIST_PHASE3: bool = False
USER_CUSTOMIZED_USER_AGENT: bool = False
USER_CUSTOMIZED_THREADS: bool = False
USER_CUSTOMIZED_TIMEOUT: bool = False
USER_CUSTOMIZED_RECURSION_DEPTH_P3: bool = False
USER_CUSTOMIZED_CRAWL_DEPTH_P4: bool = False
USER_CUSTOMIZED_RESOLVERS: bool = False
USER_CUSTOMIZED_PROXY: bool = False
USER_CUSTOMIZED_AUTO_FORM_FILL: bool = False
USER_CUSTOMIZED_NAABU_SOURCE_PORT: bool = False
USER_CUSTOMIZED_MASSCAN_RATE: bool = False
USER_CUSTOMIZED_NAABU_RATE: bool = False
USER_CUSTOMIZED_NMAP_STRATEGY: bool = False
USER_CUSTOMIZED_NMAP_SCRIPTS: bool = False
USER_CUSTOMIZED_USE_HEADLESS: bool = False
USER_CUSTOMIZED_PUREDNS_RATE_LIMIT: bool = False
USER_CUSTOMIZED_HTTPX_P1_RATE_LIMIT: bool = False
USER_CUSTOMIZED_IGNORED_EXTENSIONS: bool = False
USER_CUSTOMIZED_MASSCAN_INTERFACE: bool = False # Nowa flaga
