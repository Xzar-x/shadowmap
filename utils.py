# /usr/local/share/shadowmap/utils.py

import hashlib
import json
import logging
import os
import random
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from rich.align import Align
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text

# NOWOŚĆ: Import 'requests' do monitora WAF
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    requests = None

# Importuj konfigurację centralną
import config

# Konfiguracja Rich i logowania
console = Console()
LOG_COLOR_MAP = {"INFO": "green", "WARN": "yellow", "ERROR": "red", "DEBUG": "blue"}

# --- Globalne zarządzanie procesami ---
managed_processes = []
processes_lock = threading.Lock()

# Import specyficzny dla systemu operacyjnego
if sys.platform != "win32":
    import termios
    import tty

    def get_single_char_input() -> str:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            char = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return char

else:

    def get_single_char_input() -> str:
        import msvcrt

        return msvcrt.getch().decode("utf-8")


# --- NOWOŚĆ: Klasa do rotacji User-Agentów ---
class UserAgentRotator:
    """Zarządza listą User-Agentów i rotuje je co określoną liczbę zapytań."""

    def __init__(self, user_agents_file: str, rotation_interval: int = 50):
        self.user_agents = self._load_user_agents(user_agents_file)
        self.rotation_interval = rotation_interval
        self.call_count = 0
        self.current_user_agent = (
            random.choice(self.user_agents) if self.user_agents else "ShadowMap/1.0"
        )
        self.lock = threading.Lock()

    def _load_user_agents(self, file_path: str) -> List[str]:
        if not os.path.exists(file_path):
            return [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
            ]
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def get(self) -> str:
        """Pobiera User-Agenta, rotując go w razie potrzeby."""
        with self.lock:
            self.call_count += 1
            if self.call_count % self.rotation_interval == 0:
                self.current_user_agent = random.choice(self.user_agents)
            return self.current_user_agent


# Globalna instancja rotatora, dostępna dla wszystkich modułów
user_agent_rotator = UserAgentRotator(config.USER_AGENTS_FILE)


# --- NOWOŚĆ: Klasa monitora WAF ---
class WafHealthMonitor:
    """Monitoruje stan połączenia z celem w tle, aby wykryć blokady WAF."""

    # ZMIANA: Konstruktor przyjmuje interwały jako argumenty
    def __init__(self, target_url: str, interval_min: int, interval_max: int):
        if not requests:
            raise ImportError(
                "Biblioteka 'requests' jest wymagana do monitorowania WAF."
            )
        self.target_url = target_url.rstrip("/")
        self.baseline: Dict[str, Any] = {}
        self.is_blocked_event = threading.Event()
        self.stop_monitor_event = threading.Event()
        self.monitor_thread: Optional[threading.Thread] = None
        # ZMIANA: Przechowywanie interwałów jako atrybutów instancji
        self.interval_min = interval_min
        self.interval_max = interval_max

    def _make_request(self, url: str) -> Optional[requests.Response]:
        try:
            headers = {"User-Agent": user_agent_rotator.get()}
            return requests.get(
                url, headers=headers, timeout=10, verify=False, allow_redirects=False
            )
        except requests.RequestException:
            return None

    def establish_baseline(self) -> bool:
        """Ustala linię bazową dla normalnych i błędnych odpowiedzi."""
        log_and_echo("Health Check: Ustalam linię bazową...", "DEBUG")

        # Test 1: Strona główna (powinna istnieć)
        positive_res = self._make_request(self.target_url + "/")
        if not positive_res:
            log_and_echo(
                "Health Check: Nie udało się połączyć z celem, aby ustalić linię bazową.",
                "WARN",
            )
            return False

        # Test 2: Zasób losowy (nie powinien istnieć)
        random_path = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=12))
        negative_res = self._make_request(f"{self.target_url}/{random_path}")
        if not negative_res:
            log_and_echo(
                "Health Check: Nie udało się wykonać drugiego zapytania do linii bazowej.",
                "WARN",
            )
            return False

        self.baseline = {
            "positive": {
                "status": positive_res.status_code,
                "hash": hashlib.md5(positive_res.content).hexdigest(),
            },
            "negative": {
                "status": negative_res.status_code,
                "hash": hashlib.md5(negative_res.content).hexdigest(),
            },
        }
        log_and_echo(f"Health Check: Linia bazowa ustalona: {self.baseline}", "DEBUG")
        return True

    def _check_against_baseline(self):
        """Porównuje aktualne odpowiedzi z linią bazową."""
        current_positive = self._make_request(self.target_url + "/")
        if not current_positive:
            return

        random_path = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=12))
        current_negative = self._make_request(f"{self.target_url}/{random_path}")
        if not current_negative:
            return

        # Prosta logika detekcji: jeśli kod statusu dla strony głównej się zmienił, to jest to sygnał
        if current_positive.status_code != self.baseline["positive"]["status"]:
            log_and_echo(
                f"Health Check: WYKRYTO BLOKADĘ! Status strony głównej zmienił się z {self.baseline['positive']['status']} na {current_positive.status_code}",
                "WARN",
            )
            self.is_blocked_event.set()

        # Bardziej zaawansowane: hash się zmienił, ale status jest ten sam (np. 200 OK ze stroną blokady)
        elif (
            hashlib.md5(current_positive.content).hexdigest()
            != self.baseline["positive"]["hash"]
        ):
            log_and_echo(
                f"Health Check: WYKRYTO BLOKADĘ! Hash strony głównej uległ zmianie przy statusie {current_positive.status_code}",
                "WARN",
            )
            self.is_blocked_event.set()

    def run_monitor(self):
        """Pętla główna wątku monitorującego."""
        while not self.stop_monitor_event.is_set():
            self._check_against_baseline()
            if self.is_blocked_event.is_set():
                break

            # ZMIANA: Użycie jittera na podstawie interwałów przekazanych do instancji
            sleep_time = random.uniform(
                self.interval_min, self.interval_max
            )
            time.sleep(sleep_time)

    def start(self):
        """Uruchamia monitor w tle."""
        if self.establish_baseline():
            self.monitor_thread = threading.Thread(target=self.run_monitor, daemon=True)
            self.monitor_thread.start()

    def stop(self):
        """Zatrzymuje monitor."""
        self.stop_monitor_event.set()
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)


def is_tor_active() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect(("127.0.0.1", 9050))
        return True
    except (socket.timeout, ConnectionRefusedError):
        return False
    except Exception as e:
        log_and_echo(f"Błąd podczas sprawdzania portu Tora: {e}", "DEBUG")
        return False


def handle_safe_mode_tor_check():
    if not config.SAFE_MODE:
        if (
            not config.USER_CUSTOMIZED_PROXY
            and config.PROXY == "socks5://127.0.0.1:9050"
        ):
            config.PROXY = None
        return

    if is_tor_active():
        console.print(
            Align.center(
                Panel(
                    Text(
                        "✓ Usługa Tor jest aktywna. Proxy zostanie automatycznie skonfigurowane dla wspieranych narzędzi.",
                        justify="center",
                    ),
                    title="[bold green]Tor Aktywny[/bold green]",
                    border_style="green",
                )
            )
        )
        if not config.USER_CUSTOMIZED_PROXY:
            config.PROXY = "socks5://127.0.0.1:9050"
    else:
        console.print(
            Align.center(
                Panel(
                    Text(
                        "! Usługa Tor NIE JEST AKTYWNA.\nTryb Bezpieczny będzie kontynuowany BEZ Tora, co może zmniejszyć anonimowość.",
                        justify="center",
                    ),
                    title="[bold red]Ostrzeżenie: Tor Nieaktywny[/bold red]",
                    border_style="red",
                )
            )
        )
        console.print(
            Align.center(
                Text.from_markup(
                    "\n[dim]Naciśnij dowolny klawisz, aby kontynuować...[/dim]"
                )
            )
        )
        get_single_char_input()

        if (
            not config.USER_CUSTOMIZED_PROXY
            and config.PROXY == "socks5://127.0.0.1:9050"
        ):
            config.PROXY = None
    time.sleep(0.5)


def log_and_echo(message: str, level: str = "INFO"):
    log_level = getattr(logging, level.upper(), logging.INFO)
    color = LOG_COLOR_MAP.get(level.upper(), "white")
    if level == "ERROR":
        console.print(escape(message), style=f"bold {color}")
    if config.LOG_FILE:
        logging.log(log_level, message)


def filter_critical_urls(urls: List[str]) -> List[str]:
    critical_keywords = [
        "admin",
        "login",
        "logon",
        "signin",
        "auth",
        "panel",
        "dashboard",
        "config",
        "backup",
        "dump",
        "sql",
        "db",
        "database",
        "api",
        "graphql",
        "debug",
        "trace",
        "test",
        "dev",
        "staging",
        ".git",
        ".env",
        ".docker",
        "credentials",
        "password",
        "secret",
        "token",
        "key",
        "jwt",
        "oauth",
        "phpinfo",
        "status",
        "metrics",
    ]
    return [
        url
        for url in urls
        if any(keyword in url.lower() for keyword in critical_keywords)
    ]


def apply_exclusions(domains: List[str], exclusions: List[str]) -> List[str]:
    if not exclusions:
        return domains
    filtered_domains = []
    for domain in domains:
        is_excluded = False
        for pattern in exclusions:
            if pattern.startswith("*."):
                if domain.endswith(pattern[2:]):
                    is_excluded = True
                    break
            else:
                if domain == pattern:
                    is_excluded = True
                    break
        if not is_excluded:
            filtered_domains.append(domain)
    return filtered_domains


def get_single_char_input_with_prompt(
    prompt_text: Text,
    choices: Optional[List[str]] = None,
    default: Optional[str] = None,
) -> str:
    console.print(Align.center(prompt_text), end="")
    sys.stdout.flush()
    choice = get_single_char_input()
    console.print(f" [bold cyan]{choice}[/bold cyan]")
    if choices and default and (choice == "\r" or choice == "\n"):
        return default
    return choice


def ask_user_decision(question: str, choices: List[str], default: str) -> str:
    panel = Panel(
        Text.from_markup(question, justify="center"),
        border_style="yellow",
        title="[yellow]Pytanie[/yellow]",
        expand=False,
    )
    console.print(Align.center(panel))
    choice_str = "/".join(f"[bold]{c.upper()}[/bold]" for c in choices)
    prompt_str = f"\n[cyan]Wybierz opcję ({choice_str})[/cyan] [dim]({default.upper()}=Enter)[/dim]: "
    console.print(Align.center(prompt_str), end="")
    sys.stdout.flush()
    while True:
        choice = get_single_char_input().lower()
        if choice in ["\r", "\n"]:
            console.print(f"[bold cyan]{default.upper()}[/bold cyan]")
            return default
        if choice in choices:
            console.print(f"[bold cyan]{choice.upper()}[/bold cyan]")
            return choice


def get_random_user_agent_header() -> str:
    """Zastąpione przez globalny rotator. Ta funkcja pozostaje dla kompatybilności."""
    return user_agent_rotator.get()


def shuffle_wordlist(input_path: str, report_dir: str) -> Optional[str]:
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            lines = [line for line in f if line.strip()]
        random.shuffle(lines)
        temp_file = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=report_dir,
            prefix="shuffled_wordlist_",
            suffix=".txt",
        )
        temp_file.writelines(lines)
        temp_file.close()
        return temp_file.name
    except Exception as e:
        log_and_echo(f"Nie udało się potasować listy słów '{input_path}': {e}", "ERROR")
        return None


def get_random_browser_headers() -> List[str]:
    ACCEPT_HEADERS = ["text/html", "application/json", "text/plain", "*/*"]
    ACCEPT_LANGUAGE_HEADERS = ["en-US", "en-GB", "de", "pl"]
    REFERER_HEADERS = [
        "https://www.google.com/",
        "https://www.bing.com/",
        "https://duckduckgo.com/",
        "",
    ]
    headers = [
        f"Accept: {random.choice(ACCEPT_HEADERS)}",
        f"Accept-Language: {random.choice(ACCEPT_LANGUAGE_HEADERS)}",
        f"Referer: {random.choice(REFERER_HEADERS)}",
        "Upgrade-Insecure-Requests: 1",
        "DNT: 1",
        "Cache-Control: max-age=0",
        f"Cookie: sessionid={''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))}",
    ]
    return headers
