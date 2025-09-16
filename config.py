# /usr/local/share/shadowmap/config.py

import os
from typing import Optional, List

# --- Ścieżki i stałe ---
SHARE_DIR = "/usr/local/share/shadowmap/"
HTML_TEMPLATE_PATH = os.path.join(SHARE_DIR, "report_template.html")
USER_AGENTS_FILE = os.path.join(SHARE_DIR, "user_agents.txt")

DEFAULT_WORDLIST_PHASE1 = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
SMALL_WORDLIST_PHASE1 = os.path.join(SHARE_DIR, "subdomen_wordlist.txt")

DEFAULT_WORDLIST_PHASE3 = "/usr/share/seclists/Discovery/Web-Content/common.txt"
SMALL_WORDLIST_PHASE3 = os.path.join(SHARE_DIR, "dir_wordlist.txt")

DEFAULT_RESOLVERS_FILE = os.path.join(SHARE_DIR, "resolvers.txt")

# --- Globalne zmienne stanu i konfiguracji ---
LOG_FILE: Optional[str] = None
QUIET_MODE: bool = False
OUTPUT_BASE_DIR: str = os.getcwd()
REPORT_DIR: str = ""
TEMP_FILES_TO_CLEAN: List[str] = []
SAFE_MODE: bool = False
CUSTOM_HEADER: str = ""
PROXY: Optional[str] = None

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

# --- Wybrane narzędzia ---
selected_phase1_tools: List[int] = [0, 0, 0, 0] # Subfinder, Assetfinder, Findomain, Puredns
selected_phase2_tools: List[int] = [0, 0] # Nmap, Naabu
selected_phase3_tools: List[int] = [0, 0, 0, 0] # Ffuf, Feroxbuster, Dirsearch, Gobuster
selected_phase4_tools: List[int] = [0, 0, 0, 0, 0] # Katana, Hakrawler, ParamSpider, LinkFinder, gauplus

# --- Flagi ręcznych zmian przez użytkownika ---
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
