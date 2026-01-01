# /usr/local/share/shadowmap/utils.py

import hashlib
import logging
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional

import urllib3
from rich.align import Align
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.text import Text
from urllib3.exceptions import InsecureRequestWarning

try:
    import requests

    urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    requests = None  # type: ignore

import config

# Konfiguracja Rich i logowania
console = Console()
LOG_COLOR_MAP = {
    "INFO": "green",
    "WARN": "yellow",
    "ERROR": "red",
    "DEBUG": "blue",
}

# --- Globalne zarządzanie procesami ---
managed_processes: List[subprocess.Popen] = []
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


# --- Centralna funkcja do uruchamiania narzędzi ---
def execute_tool_command(
    tool_name: str, command_parts: List[str], output_file: str, timeout: int
) -> Optional[str]:
    """
    Uruchamia zewnętrzne narzędzie, przechwytuje jego output i obsługuje błędy.

    Args:
        tool_name: Nazwa narzędzia (do logowania).
        command_parts: Lista argumentów polecenia.
        output_file: Ścieżka do pliku, gdzie zapisać stdout.
        timeout: Czas w sekundach, po którym proces zostanie przerwany.

    Returns:
        Ścieżka do pliku wyjściowego w przypadku sukcesu, None w przypadku błędu.
    """
    cmd_str = " ".join(command_parts)
    if not config.QUIET_MODE:
        console.print(
            f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] "
            f"[dim white]{cmd_str}[/dim white]"
        )
    try:
        process = subprocess.run(
            command_parts,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            check=False,
            encoding="utf-8",
            errors="ignore",
        )

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(process.stdout)

        if process.stderr:
            log_and_echo(
                f"Komunikaty z STDERR dla '{tool_name}':\n" f"{process.stderr.strip()}",
                "DEBUG",
            )

        if process.returncode == 0:
            if not config.QUIET_MODE:
                console.print(
                    f"[bold green]✅ {tool_name} zakończył skanowanie.[/bold green]"
                )
        else:
            log_and_echo(
                f"Narzędzie {tool_name} zakończyło z błędem "
                f"({process.returncode}).",
                "WARN",
            )
        return output_file

    except Exception as e:
        log_and_echo(f"BŁĄD: Ogólny błąd wykonania '{cmd_str}': {e}", "ERROR")
        if not config.QUIET_MODE:
            console.print(
                Align.center(f"[bold red]❌ BŁĄD: {tool_name}: {e}[/bold red]")
            )
        return None


# --- Klasa do rotacji User-Agentów ---
class UserAgentRotator:
    """Zarządza listą User-Agentów i rotuje je lub zwraca stały UA."""

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
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/115.0.0.0 Safari/537.36"
            ]
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def get(self) -> str:
        """Pobiera User-Agenta. Jeśli ustawiono custom UA, zawsze zwraca ten sam."""
        # PRIORYTET DLA USTAWIENIA UŻYTKOWNIKA
        if config.USER_CUSTOMIZED_USER_AGENT and config.CUSTOM_HEADER:
            return config.CUSTOM_HEADER

        with self.lock:
            self.call_count += 1
            if self.call_count % self.rotation_interval == 0:
                self.current_user_agent = random.choice(self.user_agents)
            return self.current_user_agent


# Globalna instancja rotatora, dostępna dla wszystkich modułów
user_agent_rotator = UserAgentRotator(config.USER_AGENTS_FILE)


# --- Zarządzanie Zakresem (Scope) ---


def is_target_in_scope(target: str) -> bool:
    """
    Sprawdza, czy cel mieści się w zakresie, weryfikując go z globalną
    listą wykluczeń (config.OUT_OF_SCOPE_ITEMS).

    Obsługuje:
    - Dokładne dopasowania (np. "admin.google.com")
    - Wildcardy subdomen (np. "*.google.com" wyklucza "mail.google.com")
    - Wildcardy jako prefiks (np. w configu user podał "*.domena", a sprawdzamy "sub.domena")
    """
    if not config.OUT_OF_SCOPE_ITEMS:
        return True

    # Normalizacja celu (usuń http/s i ścieżkę)
    clean_target = (
        target.replace("https://", "").replace("http://", "").split("/")[0].lower()
    )

    for excluded in config.OUT_OF_SCOPE_ITEMS:
        excluded = excluded.strip().lower()
        if not excluded:
            continue

        # Normalizacja wykluczenia
        clean_excluded = (
            excluded.replace("https://", "").replace("http://", "").split("/")[0]
        )

        # 1. Obsługa wildcard (np. *.google.com)
        if clean_excluded.startswith("*."):
            root_excluded = clean_excluded[2:]
            # Jeśli cel to root_excluded lub kończy się na .root_excluded
            if clean_target == root_excluded or clean_target.endswith(
                "." + root_excluded
            ):
                return False

        # 2. Dokładne dopasowanie lub bycie subdomeną wykluczonej domeny
        else:
            if clean_target == clean_excluded:
                return False
            if clean_target.endswith("." + clean_excluded):
                return False

    return True


def filter_targets_scope(targets: List[str]) -> List[str]:
    """Filtruje listę celów, usuwając te znajdujące się poza zakresem (out-of-scope)."""
    filtered = [t for t in targets if is_target_in_scope(t)]
    excluded_count = len(targets) - len(filtered)
    if excluded_count > 0:
        log_and_echo(f"Odsiano {excluded_count} celów (Out of Scope).", "INFO")
    return filtered


def apply_exclusions(
    domains: List[str], exclusions: Optional[List[str]] = None
) -> List[str]:
    """
    Wrapper dla kompatybilności wstecznej, używa nowej logiki scope.
    """
    # Jeśli przekazano lokalne wykluczenia, dodaj je tymczasowo do logiki (opcjonalnie)
    # W nowym modelu polegamy głównie na config.OUT_OF_SCOPE_ITEMS
    return filter_targets_scope(domains)


# --- Klasa monitora WAF ---
class WafHealthMonitor:
    """Monitoruje stan połączenia z celem, aby wykryć blokady WAF."""

    def __init__(self, target_url: str, interval_min: int, interval_max: int):
        if not requests:
            raise ImportError("Biblioteka 'requests' jest wymagana.")
        self.target_url = target_url.rstrip("/")
        self.baseline: Dict[str, Any] = {}
        self.is_blocked_event = threading.Event()
        self.stop_monitor_event = threading.Event()
        self.monitor_thread: Optional[threading.Thread] = None
        self.interval_min = interval_min
        self.interval_max = interval_max

    def _make_request(self, url: str) -> Optional[requests.Response]:
        try:
            headers = {"User-Agent": user_agent_rotator.get()}
            return requests.get(
                url,
                headers=headers,
                timeout=10,
                verify=False,
                allow_redirects=False,
            )
        except requests.RequestException:
            return None

    def establish_baseline(self) -> bool:
        """Ustala linię bazową dla normalnych i błędnych odpowiedzi."""
        log_and_echo("Health Check: Ustalam linię bazową...", "DEBUG")

        positive_res = self._make_request(self.target_url + "/")
        if not positive_res:
            log_and_echo("Health Check: Nie udało się połączyć.", "WARN")
            return False

        random_path = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=12))
        negative_res = self._make_request(f"{self.target_url}/{random_path}")
        if not negative_res:
            log_and_echo("Health Check: Drugie zapytanie nie powiodło się.", "WARN")
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
        log_and_echo(f"Health Check: Linia bazowa: {self.baseline}", "DEBUG")
        return True

    def _check_against_baseline(self):
        """Porównuje aktualne odpowiedzi z linią bazową."""
        current_positive = self._make_request(self.target_url + "/")
        if not current_positive:
            return

        if current_positive.status_code != self.baseline["positive"]["status"]:
            log_and_echo(
                "Health Check: WYKRYTO BLOKADĘ! Zmiana statusu: "
                f"{self.baseline['positive']['status']} -> "
                f"{current_positive.status_code}",
                "WARN",
            )
            self.is_blocked_event.set()
        elif (
            hashlib.md5(current_positive.content).hexdigest()
            != self.baseline["positive"]["hash"]
        ):
            log_and_echo(
                "Health Check: WYKRYTO BLOKADĘ! Zmiana hash-a "
                f"przy statusie {current_positive.status_code}",
                "WARN",
            )
            self.is_blocked_event.set()

    def run_monitor(self):
        """Pętla główna wątku monitorującego."""
        while not self.stop_monitor_event.is_set():
            self._check_against_baseline()
            if self.is_blocked_event.is_set():
                break

            sleep_time = random.uniform(self.interval_min, self.interval_max)
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
    # Sprawdzenie, czy użytkownik wymusił Proxy - jeśli tak, to ma priorytet nad Safe Mode
    if config.USER_CUSTOMIZED_PROXY:
        return

    if not config.SAFE_MODE:
        if config.PROXY == "socks5://127.0.0.1:9050":
            config.PROXY = None
        return

    if is_tor_active():
        panel_text = (
            "✓ Usługa Tor jest aktywna. Proxy zostanie automatycznie "
            "skonfigurowane dla wspieranych narzędzi."
        )
        panel = Panel(
            Text(panel_text, justify="center"),
            title="[bold green]Tor Aktywny[/bold green]",
            border_style="green",
        )
        console.print(Align.center(panel))
        config.PROXY = "socks5://127.0.0.1:9050"
    else:
        panel_text = (
            "! Usługa Tor NIE JEST AKTYWNA.\nTryb Bezpieczny będzie "
            "kontynuowany BEZ Tora, co może zmniejszyć anonimowość."
        )
        panel = Panel(
            Text(panel_text, justify="center"),
            title="[bold red]Ostrzeżenie: Tor Nieaktywny[/bold red]",
            border_style="red",
        )
        console.print(Align.center(panel))
        console.print(
            Align.center(Text.from_markup("\n[dim]Naciśnij dowolny klawisz...[/dim]"))
        )
        get_single_char_input()

        if config.PROXY == "socks5://127.0.0.1:9050":
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
    # ZMIANA: Dodano obsługę trybu auto
    if config.AUTO_MODE:
        if not config.QUIET_MODE:
            console.print(
                f"[yellow]Tryb Auto:[/yellow] Domyślna odpowiedź '{default.upper()}' na pytanie: '{question.splitlines()[0]}...'"
            )
        return default

    panel = Panel(
        Text.from_markup(question, justify="center"),
        border_style="yellow",
        title="[yellow]Pytanie[/yellow]",
        expand=False,
    )
    console.print(Align.center(panel))
    choice_str = "/".join(f"[bold]{c.upper()}[/bold]" for c in choices)
    prompt_str = (
        f"\n[cyan]Wybierz opcję ({choice_str})[/cyan] "
        f"[dim]({default.upper()}=Enter)[/dim]: "
    )
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
    """Zastąpione przez globalny rotator. Pozostaje dla kompatybilności."""
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
        log_and_echo(f"Nie udało się potasować '{input_path}': {e}", "ERROR")
        return None


def get_random_browser_headers() -> List[str]:
    accept = ["text/html", "application/json", "text/plain", "*/*"]
    languages = ["en-US", "en-GB", "de", "pl"]
    referers = [
        "https://www.google.com/",
        "https://www.bing.com/",
        "https://duckduckgo.com/",
        "",
    ]
    session_id = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=32))
    headers = [
        f"Accept: {random.choice(accept)}",
        f"Accept-Language: {random.choice(languages)}",
        f"Referer: {random.choice(referers)}",
        "Upgrade-Insecure-Requests: 1",
        "DNT: 1",
        "Cache-Control: max-age=0",
        f"Cookie: sessionid={session_id}",
    ]
    return headers


def check_required_tools() -> List[str]:
    """
    Sprawdza, czy wszystkie wymagane narzędzia CLI są zainstalowane.

    Returns:
        Lista brakujących narzędzi.
    """
    required_tools = [
        "whois",
        "whatweb",
        "nmap",
        "masscan",
        "wafw00f",
        "subfinder",
        "assetfinder",
        "puredns",
        "httpx",
        "naabu",
        "ffuf",
        "feroxbuster",
        "dirsearch",
        "gobuster",
        "katana",
        "hakrawler",
        "paramspider",
        "linkfinder",
        "gauplus",
    ]

    missing_tools = [tool for tool in required_tools if not shutil.which(tool)]
    return missing_tools
