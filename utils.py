# /usr/local/share/shadowmap/utils.py

import sys
import os
import logging
import random
import time
import json
import re
import tempfile
from typing import Optional, List

from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.prompt import Prompt

# Importuj konfigurację centralną
import config

# Konfiguracja Rich i logowania
console = Console()
LOG_COLOR_MAP = {"INFO": "green", "WARN": "yellow", "ERROR": "red", "DEBUG": "blue"}

# Import specyficzny dla systemu operacyjnego
if sys.platform != "win32":
    import tty
    import termios
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
        return msvcrt.getch().decode('utf-8')

def log_and_echo(message: str, level: str = "INFO"):
    log_level = getattr(logging, level.upper(), logging.INFO)
    color = LOG_COLOR_MAP.get(level.upper(), "white")
    if level == "ERROR":
        console.print(message, style=f"bold {color}")
    if config.LOG_FILE:
        logging.log(log_level, message)

def filter_critical_urls(urls: List[str]) -> List[str]:
    critical_keywords = [
        'admin', 'login', 'logon', 'signin', 'auth', 'panel', 'dashboard', 'config', 'backup', 'dump', 'sql', 'db',
        'database', 'api', 'graphql', 'debug', 'trace', 'test', 'dev', 'staging', '.git', '.env', '.docker',
        'credentials', 'password', 'secret', 'token', 'key', 'jwt', 'oauth', 'phpinfo', 'status', 'metrics'
    ]
    return [url for url in urls if any(keyword in url.lower() for keyword in critical_keywords)]

def get_single_char_input_with_prompt(prompt_text: Text, choices: Optional[List[str]] = None, default: Optional[str] = None) -> str:
    console.print(Align.center(prompt_text), end="")
    sys.stdout.flush()
    choice = get_single_char_input()
    console.print(f" [bold cyan]{choice}[/bold cyan]")
    if choices and default and (choice == '\r' or choice == '\n'):
        return default
    return choice

def ask_user_decision(question: str, choices: List[str], default: str) -> str:
    """Displays a question and captures a single keystroke without needing Enter."""
    panel = Panel(Text.from_markup(question, justify="center"), border_style="yellow", title="[yellow]Pytanie[/yellow]", expand=False)
    console.print(Align.center(panel))

    choice_str = '/'.join(f"[bold]{c.upper()}[/bold]" for c in choices)
    prompt_str = f"\n[cyan]Wybierz opcję ({choice_str})[/cyan] [dim]({default.upper()}=Enter)[/dim]: "
    console.print(Align.center(prompt_str), end="")
    sys.stdout.flush()

    while True:
        choice = get_single_char_input().lower()
        if choice in ['\r', '\n']:
            console.print(f"[bold cyan]{default.upper()}[/bold cyan]")
            return default
        if choice in choices:
            console.print(f"[bold cyan]{choice.upper()}[/bold cyan]")
            return choice
        # Ignoruj inne klawisze

def get_random_user_agent_header() -> str:
    """Reads a random User-Agent from a file."""
    if config.USER_AGENTS_FILE and os.path.exists(config.USER_AGENTS_FILE):
        try:
            with open(config.USER_AGENTS_FILE, 'r', encoding='utf-8') as f:
                user_agents = [line.strip() for line in f if line.strip()]
            if user_agents:
                return random.choice(user_agents)
        except Exception as e:
            msg = f"Błąd odczytu pliku User-Agenta '{config.USER_AGENTS_FILE}': {e}. Używam domyślnego."
            console.print(Align.center(f"[bold yellow]OSTRZEŻENIE: {msg}[/bold yellow]"))
    else:
        msg = f"Plik User-Agenta '{config.USER_AGENTS_FILE}' nie znaleziony. Używam domyślnego."
        console.print(Align.center(f"[bold yellow]OSTRZEŻENIE: {msg}[/bold yellow]"))

    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"

def shuffle_wordlist(input_path: str, report_dir: str) -> Optional[str]:
    """Shuffles a wordlist and saves it to a temporary file in the report directory."""
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            lines = [line for line in f if line.strip()]

        random.shuffle(lines)

        temp_file = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, dir=report_dir, prefix='shuffled_wordlist_', suffix='.txt')
        temp_file.writelines(lines)
        temp_file.close()

        return temp_file.name
    except Exception as e:
        log_and_echo(f"Nie udało się potasować listy słów '{input_path}': {e}", "ERROR")
        return None

def get_random_browser_headers() -> List[str]:
    """Generates a list of random browser-like headers to bypass WAF."""
    ACCEPT_HEADERS = ["text/html", "application/json", "text/plain", "*/*"]
    ACCEPT_LANGUAGE_HEADERS = ["en-US", "en-GB", "de", "pl"]
    REFERER_HEADERS = ["https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/", ""]
    
    headers = [
        f"Accept: {random.choice(ACCEPT_HEADERS)}",
        f"Accept-Language: {random.choice(ACCEPT_LANGUAGE_HEADERS)}",
        f"Referer: {random.choice(REFERER_HEADERS)}",
        "Upgrade-Insecure-Requests: 1",
        "DNT: 1",
        "Cache-Control: max-age=0",
        f"Cookie: sessionid={''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))}"
    ]
    return headers
