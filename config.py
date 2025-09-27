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
SMALL_WORDLIST_PHASE1 = os.path.join(SHARE_DIR, "subdomen_wordlist.txt")

DEFAULT_WORDLIST_PHASE3 = "/usr/share/seclists/Discovery/Web-Content/common.txt"
SMALL_WORDLIST_PHASE3 = os.path.join(SHARE_DIR, "dir_wordlist.txt")

WORDPRESS_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt"
JOOMLA_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/CMS/joomla.fuzz.txt"
DRUPAL_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/CMS/drupal.fuzz.txt"
TOMCAT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/tomcat.txt"

DEFAULT_RESOLVERS_FILE = os.path.join(SHARE_DIR, "resolvers.txt")

TECH_SPECIFIC_WORDLISTS: Dict[str, str] = {
    "wordpress": WORDPRESS_WORDLIST,
    "joomla": JOOMLA_WORDLIST,
    "drupal": DRUPAL_WORDLIST,
    "tomcat": TOMCAT_WORDLIST,
    "apache tomcat": TOMCAT_WORDLIST,
}


# --- Globalne zmienne stanu i konfiguracji ---
LOG_FILE: Optional[str] = None
QUIET_MODE: bool = False
OUTPUT_BASE_DIR: str = os.getcwd()
REPORT_DIR: str = ""
TEMP_FILES_TO_CLEAN: List[str] = []
SAFE_MODE: bool = False
CUSTOM_HEADER: str = ""
PROXY: Optional[str] = None
EXCLUSION_PATTERNS: List[str] = []

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

# --- Ustawienia Fazy 2 ---
NMAP_USE_SCRIPTS: bool = False
NMAP_AGGRESSIVE_SCAN: bool = False
NAABU_SOURCE_PORT: Optional[str] = None
MASSCAN_RATE: int = 300
NAABU_RATE: int = 1000
NMAP_SOLO_SCAN_MODE: str = "default"

# --- Ustawienia Fazy 3 ---
DIRSEARCH_SMART_FILTER: bool = True
FEROXBUSTER_SMART_FILTER: bool = True

# --- Ustawienia Super Safe Mode ---
USE_HEADLESS_BROWSER: bool = False
WAF_CHECK_ENABLED: bool = True
WAF_CHECK_INTERVAL_MIN_NORMAL: int = 5
WAF_CHECK_INTERVAL_MAX_NORMAL: int = 15
WAF_CHECK_INTERVAL_MIN_SAFE: int = 30
WAF_CHECK_INTERVAL_MAX_SAFE: int = 60


# --- Wybrane narzędzia ---
selected_phase1_tools: List[int] = [0, 0, 0, 0]
selected_phase2_tools: List[int] = [0, 0, 0]
selected_phase3_tools: List[int] = [0, 0, 0, 0]
selected_phase4_tools: List[int] = [0, 0, 0, 0, 0]

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
USER_CUSTOMIZED_NAABU_SOURCE_PORT: bool = False
USER_CUSTOMIZED_MASSCAN_RATE: bool = False
USER_CUSTOMIZED_NAABU_RATE: bool = False
USER_CUSTOMIZED_USE_HEADLESS: bool = False
USER_CUSTOMIZED_PUREDNS_RATE_LIMIT: bool = False

