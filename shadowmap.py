#!/usr/bin/env python3

import os
import sys
import re
import logging
import datetime
import time
import shutil
import subprocess
import random
import typer
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn, TimeElapsedColumn, TaskProgressColumn, TaskID, MofNCompleteColumn
from rich.prompt import Prompt
from rich.align import Align # Importowanie Align dla wyśrodkowania
from rich.text import Text # Importowanie Text dla manipulacji tekstem
from rich.table import Table # Importowanie Table dla lepszego formatowania menu
from pyfiglet import Figlet
from typing import Optional, List, Dict
from pathlib import Path

# --- Dodaj katalog phase2_dirsearch.py do ścieżki systemowej Pythona ---
SHARE_DIR = "/usr/local/share/shadowmap/" 
if SHARE_DIR not in sys.path:
    sys.path.insert(0, SHARE_DIR)

# --- Importowanie logiki Fazy 2 bezpośrednio z phase2_dirsearch.py ---
try:
    from phase2_dirsearch import (
        start_dir_search as phase2_start_dir_search,
        RICH_AVAILABLE as PHASE2_RICH_AVAILABLE,
        get_random_user_agent_header as phase2_get_random_user_agent_header,
        log_and_echo as phase2_log_and_echo,
        get_random_browser_headers as phase2_get_random_browser_headers, 
        shuffle_wordlist as phase2_shuffle_wordlist 
    )
except ImportError:
    print(f"BŁĄD: Nie można zaimportować phase2_dirsearch.py z {SHARE_DIR}. Upewnij się, że plik istnieje i ma prawidłowe uprawnienia.", file=sys.stderr)
    sys.exit(1)


# Modules for single character input on Unix/Linux
if sys.platform != "win32":
    import tty
    import termios
    def get_single_char_input() -> str:
        """Reads a single character from stdin without requiring Enter for Unix-like systems."""
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
        """Fallback for single char input, will require Enter on non-Unix systems."""
        return input("")


# Rich configuration - console for direct output
console = Console() # Główna konsola ShadowMap

# --- Global Variables ---
LOG_FILE = ""
QUIET_MODE = False
OUTPUT_BASE_DIR = os.getcwd()
REPORT_DIR = ""
TEMP_FILES_TO_CLEAN = []
SAFE_MODE = False
CUSTOM_HEADER = ""
SCAN_ONLY_CRITICAL = False # NEW: Flag for scanning only critical results
selected_phase1_tools = [0, 0, 0, 0] # 0 = disabled, 1 = enabled for Subfinder, Assetfinder, Findomain, Puredns
selected_phase2_tools = [0, 0, 0, 0] # Ffuf, Feroxbuster, Dirsearch, Gobuster (0=disabled, 1=enabled)
TARGET_IS_IP = False
ORIGINAL_TARGET = ""
CLEAN_DOMAIN_TARGET = "" 

# Domyślne wartości dla ustawień
DEFAULT_WORDLIST_PHASE1 = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
SMALL_WORDLIST_PHASE1 = "/home/xzar/Desktop/shadowmap_python/subdomen_wordlist.txt"
WORDLIST_PHASE1 = DEFAULT_WORDLIST_PHASE1

DEFAULT_WORDLIST_PHASE2 = "/usr/share/seclists/Discovery/Web-Content/common.txt"
SMALL_WORDLIST_PHASE2 = "/home/xzar/Desktop/shadowmap_python/dir_wordlist.txt"
WORDLIST_PHASE2 = DEFAULT_WORDLIST_PHASE2

DEFAULT_THREADS = 40
THREADS = DEFAULT_THREADS

DEFAULT_TOOL_TIMEOUT_SECONDS = 1200
TOOL_TIMEOUT_SECONDS = DEFAULT_TOOL_TIMEOUT_SECONDS

DEFAULT_RESOLVERS_FILE = "/usr/local/share/shadowmap/resolvers.txt"
RESOLVERS_FILE = DEFAULT_RESOLVERS_FILE

# Flagi do śledzenia, czy użytkownik ręcznie zmienił ustawienia
USER_CUSTOMIZED_WORDLIST_PHASE1 = False
USER_CUSTOMIZED_WORDLIST_PHASE2 = False
USER_CUSTOMIZED_USER_AGENT = False
USER_CUSTOMIZED_THREADS = False
USER_CUSTOMIZED_TIMEOUT = False
USER_CUSTOMIZED_RESOLVERS = False
USER_CUSTOMIZED_SCAN_CRITICAL = False # NEW: Flag to track if user customized critical scan setting

# Path to the HTML report template
HTML_TEMPLATE_PATH = "/usr/local/share/shadowmap/report_template.html"
USER_AGENTS_FILE = "/usr/local/share/shadowmap/user_agents.txt" 


# --- Log color map ---
LOG_COLOR_MAP = {
    "INFO": "green", 
    "WARN": "yellow", 
    "ERROR": "red", 
    "DEBUG": "blue", 
    "GRAY": "dim white" 
}

def log_and_echo(message: str, level: str = "INFO"):
    """
    Displays ERROR messages in the console with colors.
    Other levels are only logged to file if LOG_FILE is set.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    color = LOG_COLOR_MAP.get(level.upper(), "white")
    
    if level == "ERROR":
        console.print(message, style=f"bold {color}")
    
    if LOG_FILE:
        logging.log(log_level, message)


def display_banner():
    """Displays the ASCII banner centered."""
    f = Figlet(font='slant')
    banner_text = f.renderText('ShadowMap')
    console.print(Align.center(Text(banner_text, style="bold cyan")))
    console.print(Align.center("--- Automated Reconnaissance Toolkit ---", style="bold yellow"))
    console.print(Align.center("[dim white]Made by Xzar[/dim white]\n"))

# --- NEW: Function to filter for critical URLs ---
def filter_critical_urls(urls: List[str]) -> List[str]:
    """
    Filters a list of URLs, returning only those that are considered 'critical'
    based on keywords.
    """
    critical_keywords = [
        'admin', 'login', 'logon', 'signin', 'auth', 'panel', 'dashboard',
        'config', 'backup', 'dump', 'sql', 'db', 'database',
        'api', 'graphql', 'debug', 'trace', 'test', 'dev', 'staging',
        '.git', '.env', '.docker', 'credentials', 'password', 'secret',
        'token', 'key', 'jwt', 'oauth', 'phpinfo', 'status', 'metrics'
    ]
    critical_urls = []
    for url in urls:
        # Check if any keyword is present in the URL path or query
        if any(keyword in url.lower() for keyword in critical_keywords):
            critical_urls.append(url)
    return critical_urls

# --- Interactive Menu Functions ---

def get_single_char_input_with_prompt(prompt_text: Text, choices: Optional[List[str]] = None, default: Optional[str] = None) -> str:
    """Displays a prompt and reads a single character without requiring Enter for Unix-like systems."""
    console.print(Align.center(prompt_text), end="")
    choice = get_single_char_input()
    console.print(choice) # Echo input for user feedback
    
    if choices and default and choice.strip() == '':
        return default
    
    return choice

def display_phase1_tool_selection_menu():
    global selected_phase1_tools, SAFE_MODE
    while True:
        console.clear()
        display_banner()
        console.print(Align.center(Panel.fit("[bold magenta]Faza 1: Odkrywanie Subdomen[/bold magenta]")))
        console.print(Align.center(f"Obecny cel: [bold green]{ORIGINAL_TARGET}[/bold green]"))
        console.print(Align.center(f"Tryb bezpieczny: {'[bold green]WŁĄCZONY[/bold green]' if SAFE_MODE else '[bold red]WYŁĄCZONY'}"))
        
        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        table.add_column("Key", style="bold blue", justify="center", min_width=5)
        table.add_column("Description", style="white", justify="left")

        tool_names = ["Subfinder (pasywna enumeracja)", "Assetfinder (pasywna enumeracja)", "Findomain (pasywna enumeracja)", "Puredns (bruteforce subdomen)"]
        
        for i, tool_name in enumerate(tool_names):
            status_char = "[bold green]✓[/bold green]" if selected_phase1_tools[i] == 1 else "[bold red]✗[/bold red]"
            if TARGET_IS_IP and i < 3:
                table.add_row(f"[{i+1}]", f"[dim]{status_char}[/dim] [dim]{tool_name} (pominięto dla IP)[/dim]")
            else:
                table.add_row(f"[{i+1}]", f"{status_char} {tool_name}")

        table.add_section()
        table.add_row("[5]", "[bold magenta]Zmień ustawienia Fazy 1[/bold magenta]")
        
        table.add_row("[\fb]", "Powrót do menu głównego")
        table.add_row("[\fq]", "Wyjdź")
        
        console.print(Align.center(table))

        choice = get_single_char_input_with_prompt(Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center"))
        
        if choice.isdigit() and 1 <= int(choice) <= 4:
            idx = int(choice) - 1
            if TARGET_IS_IP and idx < 3:
                log_and_echo("Nie można włączyć narzędzi pasywnych dla celu IP.", "WARN")
                console.print(Align.center("[bold yellow]Nie można włączyć narzędzi pasywnych dla celu IP.[/bold yellow]"))
            else:
                selected_phase1_tools[idx] = 1 - selected_phase1_tools[idx]
        elif choice == '5':
            display_phase1_settings_menu()
        elif choice.lower() == 'q':
            sys.exit(0)
        elif choice.lower() == 'b':
            return False
        elif choice == '\r':
            if any(selected_phase1_tools):
                 return True
            else:
                 console.print(Align.center("[bold yellow]Proszę wybrać co najmniej jedno narzędzie lub wrócić/wyjść.[/bold yellow]"))
        else:
            log_and_echo("Nieprawidłowa opcja. Spróbuj ponownie.", "WARN")
            console.print(Align.center("[bold yellow]Nieprawidłowa opcja. Spróbuj ponownie.[/bold yellow]"))
        time.sleep(0.1)

def display_phase1_settings_menu():
    global WORDLIST_PHASE1, THREADS, TOOL_TIMEOUT_SECONDS, SAFE_MODE, CUSTOM_HEADER, RESOLVERS_FILE
    global USER_CUSTOMIZED_WORDLIST_PHASE1, USER_CUSTOMIZED_USER_AGENT, USER_CUSTOMIZED_THREADS, USER_CUSTOMIZED_TIMEOUT, USER_CUSTOMIZED_RESOLVERS

    while True:
        console.clear()
        display_banner()
        console.print(Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 1[/bold cyan]")))
        
        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        table.add_column("Key", style="bold blue", justify="center", min_width=5)
        table.add_column("Description", style="white", justify="left")

        table.add_row("[1]", f"[{'[bold green]✓[/bold green]' if SAFE_MODE else '[bold red]✗[/bold red]'}] Tryb bezpieczny: {'[bold green]WŁĄCZONY[/bold green]' if SAFE_MODE else '[bold red]WYŁĄCZONY'}")
        
        wordlist_display = f"[dim]{WORDLIST_PHASE1}[/dim]"
        if USER_CUSTOMIZED_WORDLIST_PHASE1:
            wordlist_display = f"[bold green]{WORDLIST_PHASE1} (Użytkownika)[/bold green]"
        elif SAFE_MODE:
            wordlist_display = f"[bold yellow]{SMALL_WORDLIST_PHASE1} (Safe Mode)[/bold yellow]"

        user_agent_display = f"[dim white]'{CUSTOM_HEADER}'[/dim white]"
        if USER_CUSTOMIZED_USER_AGENT and CUSTOM_HEADER:
            user_agent_display = f"[bold green]'{CUSTOM_HEADER}' (Użytkownika)[/bold green]"
        elif SAFE_MODE and not USER_CUSTOMIZED_USER_AGENT:
             user_agent_display = f"[bold yellow]Losowy + Dodatkowe (Safe Mode)[/bold yellow]"
        elif not CUSTOM_HEADER:
            user_agent_display = f"[dim white]Domyślny[/dim white]"

        threads_display = f"[bold yellow]{THREADS}[/bold yellow]"
        if USER_CUSTOMIZED_THREADS:
            threads_display = f"[bold green]{THREADS} (Użytkownika)[/bold green]"

        timeout_display = f"[bold yellow]{TOOL_TIMEOUT_SECONDS}[/bold yellow]s"
        if USER_CUSTOMIZED_TIMEOUT:
            timeout_display = f"[bold green]{TOOL_TIMEOUT_SECONDS}s (Użytkownika)[/bold green]"

        resolvers_display = f"[dim]{RESOLVERS_FILE}[/dim]"
        if USER_CUSTOMIZED_RESOLVERS:
            resolvers_display = f"[bold green]{RESOLVERS_FILE} (Użytkownika)[/bold green]"

        table.add_row("[2]", f"Lista słów (Faza 1) (aktualna: {wordlist_display})")
        table.add_row("[3]", f"User-Agent (aktualny: {user_agent_display})")
        table.add_row("[4]", f"Liczba wątków (aktualna: {threads_display})")
        table.add_row("[5]", f"Limit czasu narzędzia (aktualny: {timeout_display})")
        table.add_row("[6]", f"Plik resolverów dla Puredns (aktualny: {resolvers_display})")
        
        table.add_section()
        table.add_row("[\fb]", "Powrót do menu Fazy 1")
        table.add_row("[\fq]", "Wyjdź")

        console.print(Align.center(table))

        choice = get_single_char_input_with_prompt(Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center"))
        
        if choice == '1':
            SAFE_MODE = not SAFE_MODE
            console.print(Align.center(f"[bold green]Tryb bezpieczny zmieniono na: {'WŁĄCZONY' if SAFE_MODE else 'WYŁĄCZONY'}[/bold green]"))
            if SAFE_MODE and not USER_CUSTOMIZED_WORDLIST_PHASE1:
                WORDLIST_PHASE1 = SMALL_WORDLIST_PHASE1
            elif not SAFE_MODE and not USER_CUSTOMIZED_WORDLIST_PHASE1:
                WORDLIST_PHASE1 = DEFAULT_WORDLIST_PHASE1
            if SAFE_MODE and not USER_CUSTOMIZED_USER_AGENT and not CUSTOM_HEADER:
                 CUSTOM_HEADER = phase2_get_random_user_agent_header(user_agents_file=USER_AGENTS_FILE, console_obj=console)
            elif not SAFE_MODE and not USER_CUSTOMIZED_USER_AGENT and CUSTOM_HEADER:
                 CUSTOM_HEADER = ""
        elif choice == '2':
            console.print(Align.center("[bold cyan]Wpisz nową ścieżkę do listy słów (Faza 1)[/bold cyan] (pozostaw puste dla domyślnej)"))
            new_path = Prompt.ask("")
            if not new_path:
                WORDLIST_PHASE1 = DEFAULT_WORDLIST_PHASE1
                USER_CUSTOMIZED_WORDLIST_PHASE1 = False
                console.print(Align.center(f"[bold green]Lista słów (Faza 1) zresetowana do domyślnej: {WORDLIST_PHASE1}[/bold green]"))
            elif os.path.isfile(new_path) and os.access(new_path, os.R_OK):
                WORDLIST_PHASE1 = new_path
                USER_CUSTOMIZED_WORDLIST_PHASE1 = True
                console.print(Align.center(f"[bold green]Lista słów (Faza 1) ustawiona na: {WORDLIST_PHASE1}[/bold green]"))
            else:
                log_and_echo("Podana ścieżka do listy słów (Faza 1) jest nieprawidłowa lub plik nie istnieje/nie jest czytelny.", "ERROR")
                console.print(Align.center("[bold red]Podana ścieżka do listy słów (Faza 1) jest nieprawidłowa lub plik nie istnieje/nie jest czytelny.[/bold red]"))
        elif choice == '3':
            console.print(Align.center("[bold cyan]Wpisz nowy User-Agent[/bold cyan] (pozostaw puste, aby wyczyścić i użyć losowego/domyślnego)"))
            new_ua = Prompt.ask("")
            CUSTOM_HEADER = new_ua
            if CUSTOM_HEADER:
                USER_CUSTOMIZED_USER_AGENT = True
                console.print(Align.center(f"[bold green]User-Agent ustawiony na: '{CUSTOM_HEADER}'[/bold green]"))
            else:
                USER_CUSTOMIZED_USER_AGENT = False
                console.print(Align(Align.center("[bold green]User-Agent wyczyszczony. Zostanie użyty losowy/domyślny.[/bold green]")))
        elif choice == '4':
            console.print(Align.center("[bold cyan]Wpisz nową liczbę wątków[/bold cyan] (tylko cyfry)"))
            new_threads_str = Prompt.ask("")
            if new_threads_str.isdigit() and int(new_threads_str) > 0:
                THREADS = int(new_threads_str)
                USER_CUSTOMIZED_THREADS = True
                console.print(Align.center(f"[bold green]Liczba wątków ustawiona na: {THREADS}[/bold green]"))
            else:
                log_and_echo("Nieprawidłowa liczba wątków. Musi być liczbą całkowitą większą od 0.", "ERROR")
                console.print(Align.center("[bold red]Nieprawidłowa liczba wątków. Musi być liczbą całkowitą większą od 0.[/bold red]"))
        elif choice == '5':
            console.print(Align.center("[bold cyan]Wpisz nowy limit czasu w sekundach[/bold cyan] (tylko cyfry)"))
            new_timeout_str = Prompt.ask("")
            if new_timeout_str.isdigit() and int(new_timeout_str) > 0:
                TOOL_TIMEOUT_SECONDS = int(new_timeout_str)
                USER_CUSTOMIZED_TIMEOUT = True
                console.print(Align.center(f"[bold green]Limit czasu narzędzia ustawiony na: {TOOL_TIMEOUT_SECONDS}s[/bold green]"))
            else:
                log_and_echo("Nieprawidłowy limit czasu. Musi być liczbą całkowitą większą od 0.", "ERROR")
                console.print(Align.center("[bold red]Nieprawidłowy limit czasu. Musi być liczbą całkowitą większą od 0.[/bold red]"))
        elif choice == '6':
            console.print(Align.center("[bold cyan]Wpisz nową ścieżkę do pliku resolverów dla Puredns[/bold cyan] (pozostaw puste dla domyślnej)"))
            new_path = Prompt.ask("")
            if not new_path:
                RESOLVERS_FILE = DEFAULT_RESOLVERS_FILE
                USER_CUSTOMIZED_RESOLVERS = False
                console.print(Align.center(f"[bold green]Plik resolverów zresetowany do domyślnego: {RESOLVERS_FILE}[/bold green]"))
            elif os.path.isfile(new_path) and os.access(new_path, os.R_OK):
                RESOLVERS_FILE = new_path
                USER_CUSTOMIZED_RESOLVERS = True
                console.print(Align.center(f"[bold green]Plik resolverów ustawiony na: {RESOLVERS_FILE}[/bold green]"))
            else:
                log_and_echo("Podana ścieżka do pliku resolverów jest nieprawidłowa lub plik nie istnieje/nie jest czytelny.", "ERROR")
                console.print(Align.center("[bold red]Podana ścieżka do pliku resolverów jest nieprawidłowa lub plik nie istnieje/nie jest czytelny.[/bold red]"))
        elif choice.lower() == 'b':
            break
        elif choice.lower() == 'q':
            sys.exit(0)
        else:
            log_and_echo("Nieprawidłowa opcja. Spróbuj ponownie.", "WARN")
            console.print(Align.center("[bold yellow]Nieprawidłowa opcja. Spróbuj ponownie.[/bold yellow]"))
        time.sleep(0.1)

def display_phase2_tool_selection_menu():
    global selected_phase2_tools, SAFE_MODE
    while True:
        console.clear()
        display_banner()
        console.print(Align.center(Panel.fit("[bold magenta]Faza 2: Wyszukiwanie Katalogów[/bold magenta]")))
        console.print(Align.center(f"Obecny cel: [bold green]{ORIGINAL_TARGET}[/bold green]"))
        console.print(Align.center(f"Tryb bezpieczny: {'[bold green]WŁĄCZONY[/bold green]' if SAFE_MODE else '[bold red]WYŁĄCZONY'}"))

        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        table.add_column("Key", style="bold blue", justify="center", min_width=5)
        table.add_column("Description", style="white", justify="left")

        tool_names = ["FFuf", "Feroxbuster", "Dirsearch", "Gobuster"]
        
        for i, tool_name in enumerate(tool_names):
            status_char = "[bold green]✓[/bold green]" if selected_phase2_tools[i] == 1 else "[bold red]✗[/bold red]"
            table.add_row(f"[{i+1}]", f"{status_char} {tool_name}")

        table.add_section()
        table.add_row("[5]", "[bold magenta]Zmień ustawienia Fazy 2[/bold magenta]")

        table.add_row("[\fb]", "Powrót do menu głównego")
        table.add_row("[\fq]", "Wyjdź")
        
        console.print(Align.center(table))

        choice = get_single_char_input_with_prompt(Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center"))
        
        if choice.isdigit() and 1 <= int(choice) <= 4:
            idx = int(choice) - 1
            selected_phase2_tools[idx] = 1 - selected_phase2_tools[idx]
        elif choice == '5':
            display_phase2_settings_menu()
        elif choice.lower() == 'q':
            sys.exit(0)
        elif choice.lower() == 'b':
            return False
        elif choice == '\r':
            if any(selected_phase2_tools):
                 return True
            else:
                 console.print(Align.center("[bold yellow]Proszę wybrać co najmniej jedno narzędzie lub wrócić/wyjść.[/bold yellow]"))
        else:
            log_and_echo("Nieprawidłowa opcja. Spróbuj ponownie.", "WARN")
            console.print(Align.center("[bold yellow]Nieprawidłowa opcja. Spróbuj ponownie.[/bold yellow]"))
        time.sleep(0.1)

def display_phase2_settings_menu():
    global WORDLIST_PHASE2, THREADS, TOOL_TIMEOUT_SECONDS, SAFE_MODE, CUSTOM_HEADER, SCAN_ONLY_CRITICAL
    global USER_CUSTOMIZED_WORDLIST_PHASE2, USER_CUSTOMIZED_USER_AGENT, USER_CUSTOMIZED_THREADS, USER_CUSTOMIZED_TIMEOUT, USER_CUSTOMIZED_SCAN_CRITICAL

    while True:
        console.clear()
        display_banner()
        console.print(Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 2[/bold cyan]")))
        
        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        table.add_column("Key", style="bold blue", justify="center", min_width=5)
        table.add_column("Description", style="white", justify="left")
        
        table.add_row("[1]", f"[{'[bold green]✓[/bold green]' if SAFE_MODE else '[bold red]✗[/bold red]'}] Tryb bezpieczny: {'[bold green]WŁĄCZONY[/bold green]' if SAFE_MODE else '[bold red]WYŁĄCZONY'}")

        wordlist_display = f"[dim]{WORDLIST_PHASE2}[/dim]"
        if USER_CUSTOMIZED_WORDLIST_PHASE2:
            wordlist_display = f"[bold green]{WORDLIST_PHASE2} (Użytkownika)[/bold green]"
        elif SAFE_MODE:
            wordlist_display = f"[bold yellow]{SMALL_WORDLIST_PHASE2} (Safe Mode)[/bold yellow]"
        
        user_agent_display = f"[dim white]'{CUSTOM_HEADER}'[/dim white]"
        if USER_CUSTOMIZED_USER_AGENT and CUSTOM_HEADER:
            user_agent_display = f"[bold green]'{CUSTOM_HEADER}' (Użytkownika)[/bold green]"
        elif SAFE_MODE and not USER_CUSTOMIZED_USER_AGENT:
             user_agent_display = f"[bold yellow]Losowy + Dodatkowe (Safe Mode)[/bold yellow]"
        elif not CUSTOM_HEADER:
            user_agent_display = f"[dim white]Domyślny[/dim white]"

        threads_display = f"[bold yellow]{THREADS}[/bold yellow]"
        if USER_CUSTOMIZED_THREADS:
            threads_display = f"[bold green]{THREADS} (Użytkownika)[/bold green]"

        timeout_display = f"[bold yellow]{TOOL_TIMEOUT_SECONDS}[/bold yellow]s"
        if USER_CUSTOMIZED_TIMEOUT:
            timeout_display = f"[bold green]{TOOL_TIMEOUT_SECONDS}s (Użytkownika)[/bold green]"

        table.add_row("[2]", f"Lista słów (Faza 2) (aktualna: {wordlist_display})")
        table.add_row("[3]", f"User-Agent (aktualny: {user_agent_display})")
        table.add_row("[4]", f"Liczba wątków (aktualna: {threads_display})")
        table.add_row("[5]", f"Limit czasu narzędzia (aktualny: {timeout_display})")
        # NEW: Critical scan option
        table.add_row("[6]", f"[{'[bold green]✓[/bold green]' if SCAN_ONLY_CRITICAL else '[bold red]✗[/bold red]'}] Skanuj tylko wyniki krytyczne: {'[bold green]WŁĄCZONY[/bold green]' if SCAN_ONLY_CRITICAL else '[bold red]WYŁĄCZONY'}")
        
        table.add_section()
        table.add_row("[\fb]", "Powrót do menu Fazy 2")
        table.add_row("[\fq]", "Wyjdź")

        console.print(Align.center(table))

        choice = get_single_char_input_with_prompt(Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center"))
        
        if choice == '1':
            SAFE_MODE = not SAFE_MODE
            console.print(Align.center(f"[bold green]Tryb bezpieczny zmieniono na: {'WŁĄCZONY' if SAFE_MODE else 'WYŁĄCZONY'}[/bold green]"))
            if SAFE_MODE and not USER_CUSTOMIZED_WORDLIST_PHASE2:
                WORDLIST_PHASE2 = SMALL_WORDLIST_PHASE2
            elif not SAFE_MODE and not USER_CUSTOMIZED_WORDLIST_PHASE2:
                WORDLIST_PHASE2 = DEFAULT_WORDLIST_PHASE2
            if SAFE_MODE and not USER_CUSTOMIZED_USER_AGENT and not CUSTOM_HEADER:
                 CUSTOM_HEADER = phase2_get_random_user_agent_header(user_agents_file=USER_AGENTS_FILE, console_obj=console)
            elif not SAFE_MODE and not USER_CUSTOMIZED_USER_AGENT and CUSTOM_HEADER:
                 CUSTOM_HEADER = ""
        elif choice == '2':
            console.print(Align.center("[bold cyan]Wpisz nową ścieżkę do listy słów (Faza 2)[/bold cyan] (pozostaw puste dla domyślnej)"))
            new_path = Prompt.ask("")
            if not new_path:
                WORDLIST_PHASE2 = DEFAULT_WORDLIST_PHASE2
                USER_CUSTOMIZED_WORDLIST_PHASE2 = False
                console.print(Align.center(f"[bold green]Lista słów (Faza 2) zresetowana do domyślnej: {WORDLIST_PHASE2}[/bold green]"))
            elif os.path.isfile(new_path) and os.access(new_path, os.R_OK):
                WORDLIST_PHASE2 = new_path
                USER_CUSTOMIZED_WORDLIST_PHASE2 = True
                console.print(Align.center(f"[bold green]Lista słów (Faza 2) ustawiona na: {WORDLIST_PHASE2}[/bold green]"))
            else:
                log_and_echo("Podana ścieżka do listy słów (Faza 2) jest nieprawidłowa lub plik nie istnieje/nie jest czytelny.", "ERROR")
                console.print(Align.center("[bold red]Podana ścieżka do listy słów (Faza 2) jest nieprawidłowa lub plik nie istnieje/nie jest czytelny.[/bold red]"))
        elif choice == '3':
            console.print(Align.center("[bold cyan]Wpisz nowy User-Agent[/bold cyan] (pozostaw puste, aby wyczyścić i użyć losowego/domyślnego)"))
            new_ua = Prompt.ask("")
            CUSTOM_HEADER = new_ua
            if CUSTOM_HEADER:
                USER_CUSTOMIZED_USER_AGENT = True
                console.print(Align.center(f"[bold green]User-Agent ustawiony na: '{CUSTOM_HEADER}'[/bold green]"))
            else:
                USER_CUSTOMIZED_USER_AGENT = False
                console.print(Align.center("[bold green]User-Agent wyczyszczony. Zostanie użyty losowy/domyślny.[/bold green]"))
        elif choice == '4':
            console.print(Align.center("[bold cyan]Wpisz nową liczbę wątków[/bold cyan] (tylko cyfry)"))
            new_threads_str = Prompt.ask("")
            if new_threads_str.isdigit() and int(new_threads_str) > 0:
                THREADS = int(new_threads_str)
                USER_CUSTOMIZED_THREADS = True
                console.print(Align.center(f"[bold green]Liczba wątków ustawiona na: {THREADS}[/bold green]"))
            else:
                log_and_echo("Nieprawidłowa liczba wątków. Musi być liczbą całkowitą większą od 0.", "ERROR")
                console.print(Align.center("[bold red]Nieprawidłowa liczba wątków. Musi być liczbą całkowitą większą od 0.[/bold red]"))
        elif choice == '5':
            console.print(Align.center("[bold cyan]Wpisz nowy limit czasu w sekundach[/bold cyan] (tylko cyfry)"))
            new_timeout_str = Prompt.ask("")
            if new_timeout_str.isdigit() and int(new_timeout_str) > 0:
                TOOL_TIMEOUT_SECONDS = int(new_timeout_str)
                USER_CUSTOMIZED_TIMEOUT = True
                console.print(Align.center(f"[bold green]Limit czasu narzędzia ustawiony na: {TOOL_TIMEOUT_SECONDS}s[/bold green]"))
            else:
                log_and_echo("Nieprawidłowy limit czasu. Musi być liczbą całkowitą większą od 0.", "ERROR")
                console.print(Align.center("[bold red]Nieprawidłowy limit czasu. Musi być liczbą całkowitą większą od 0.[/bold red]"))
        elif choice == '6': # NEW: Handle critical scan toggle
            SCAN_ONLY_CRITICAL = not SCAN_ONLY_CRITICAL
            USER_CUSTOMIZED_SCAN_CRITICAL = True
            console.print(Align.center(f"[bold green]Skanowanie tylko wyników krytycznych: {'WŁĄCZONO' if SCAN_ONLY_CRITICAL else 'WYŁĄCZONO'}[/bold green]"))
        elif choice.lower() == 'b':
            break
        elif choice.lower() == 'q':
            sys.exit(0)
        else:
            log_and_echo("Nieprawidłowa opcja. Spróbuj ponownie.", "WARN")
            console.print(Align.center("[bold yellow]Nieprawidłowa opcja. Spróbuj ponownie.[/bold yellow]"))
        time.sleep(0.1)


def display_main_menu():
    console.clear()
    display_banner()
    
    main_panel = Panel.fit("[bold cyan]ShadowMap Main Menu[/bold cyan]")
    console.print(Align.center(main_panel))
    console.print()
    
    console.print(Align.center(f"Obecny cel: [bold green]{ORIGINAL_TARGET}[/bold green]"))
    console.print()
    
    table = Table(show_header=False, show_edge=False, padding=(0, 2))
    table.add_column("Key", style="bold blue", justify="center", min_width=5)
    table.add_column("Description", style="white", justify="left")
    
    table.add_row("[1]", "Faza 1: Odkrywanie Subdomen")
    table.add_row("[2]", "Faza 2: Wyszukiwanie Katalogów") 
    table.add_row("[\fq]", "Wyjdź")
    
    console.print(Align.center(table))
    console.print()
    
    return get_single_char_input_with_prompt(Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center"))


# --- Utility Functions ---
def parse_target_input(target_input: str):
    """Parses the target input, checks if it's an IP or a domain, and cleans the domain for directory naming."""
    global ORIGINAL_TARGET, TARGET_IS_IP, CLEAN_DOMAIN_TARGET
    ORIGINAL_TARGET = target_input
    
    clean_target = re.sub(r'^(http|https)://', '', target_input)
    clean_target = re.sub(r'^www\.', '', clean_target).strip('/')
    CLEAN_DOMAIN_TARGET = clean_target
    
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_target):
        TARGET_IS_IP = True
        console.print(Align.center(f"[bold green]Cel wykryto jako adres IP: {clean_target}[/bold green]"))
    else:
        TARGET_IS_IP = False
        console.print(Align.center(f"[bold green]Cel wykryto jako domenę: {clean_target}[/bold green]"))

def check_dependencies():
    """Checks the availability of required tools."""
    global RESOLVERS_FILE, WORDLIST_PHASE1, WORDLIST_PHASE2
    required_tools_phase1 = {
        "Subfinder": "subfinder",
        "Assetfinder": "assetfinder",
        "Findomain": "findomain",
        "Puredns": "puredns",
        "Httpx": "httpx",
        "Wafw00f": "wafw00f"
    }
    
    missing_tools = []
    
    console.print(Align.center("Sprawdzanie zależności ShadowMap...", style="bold green"))
    
    for name, cmd in required_tools_phase1.items():
        if shutil.which(cmd) is None:
            missing_tools.append(name)
            log_and_echo(f"Narzędzie '{name}' ({cmd}) nie zostało znalezione.", "ERROR")
            console.print(Align.center(f"[bold red]BŁĄD: Narzędzie '{name}' ({cmd}) nie zostało znalezione.[/bold red]"))
    
    if missing_tools:
        console.print(Align.center(f"\n[bold red]Błąd: Brakuje następujących wymaganych narzędzi: {', '.join(missing_tools)}.[/bold red]"))
        console.print(Align.center("[bold red]Zainstaluj je i upewnij się, że są w Twojej ścieżce PATH.[/bold red]"))
        sys.exit(1)
    
    if not os.path.isfile(WORDLIST_PHASE1) or not os.access(WORDLIST_PHASE1, os.R_OK):
        log_and_echo(f"BŁĄD: Domyślna lista słów (Faza 1) '{WORDLIST_PHASE1}' nie istnieje lub nie jest czytelna.", "ERROR")
        console.print(Align.center(f"[bold red]BŁĄD: Domyślna lista słowa (Faza 1) '{WORDLIST_PHASE1}' nie istnieje lub nie jest czytelna.[/bold red]"))
        sys.exit(1)
    if not os.path.isfile(WORDLIST_PHASE2) or not os.access(WORDLIST_PHASE2, os.R_OK):
        log_and_echo(f"BŁĄD: Domyślna lista słów (Faza 2) '{WORDLIST_PHASE2}' nie istnieje lub nie jest czytelna.", "ERROR")
        console.print(Align.center(f"[bold red]BŁĄD: Domyślna lista słowa (Faza 2) '{WORDLIST_PHASE2}' nie istnieje lub nie jest czytelna.[/bold red]"))
        sys.exit(1)
    if not os.path.isfile(RESOLVERS_FILE) or not os.access(RESOLVERS_FILE, os.R_OK):
        log_and_echo(f"BŁĄD: Domyślny plik resolverów '{RESOLVERS_FILE}' nie istnieje lub nie jest czytelny. Puredns może działać nieprawidłowo.", "ERROR")
        console.print(Align.center(f"[bold red]BŁĄD: Domyślny plik resolverów '{RESOLVERS_FILE}' nie istnieje lub nie jest czytelny. Puredns może działać nieprawidłowo.[/bold red]"))
    
    console.print(Align.center("Wszystkie zależności wydają się być OK.", style="bold green"))

def _execute_tool_command(tool_name: str, command_parts: List[str], output_file: str, timeout: int, progress_obj: Progress, task_id: TaskID):
    """
    Executes a single tool command for Phase 1 and saves its output to a file.
    """
    cmd_str = ' '.join(command_parts)
    progress_obj.console.print(f"[bold cyan]Uruchamiam: {tool_name}:[/bold cyan] [dim white]{cmd_str}[/dim white]")
    log_and_echo(f"Uruchamiam: {tool_name}: {cmd_str}", level="DEBUG")

    try:
        process = subprocess.run(
            command_parts,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            check=False
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(process.stdout)

        if process.returncode == 0:
            log_and_echo(f"{tool_name} zakończono pomyślnie. Wyniki w '{output_file}'", "INFO")
            progress_obj.console.print(f"[bold green]✅ {tool_name} zakończył skanowanie.[/bold green]")
            if process.stderr:
                 log_and_echo(f"STDERR (DEBUG) {tool_name}: {process.stderr}", "DEBUG")
            return output_file
        else:
            log_and_echo(f"Błąd wykonania {tool_name} (kod: {process.returncode}).", "ERROR")
            if process.stderr:
                log_and_echo(f"STDERR {tool_name}: {process.stderr}", "ERROR")
                progress_obj.console.print(Align.center(f"[bold red]BŁĄD: STDERR (narzędzie) {tool_name}: {process.stderr}[/bold red]"))
            progress_obj.console.print(Align.center(f"[bold red]BŁĄD: Błąd wykonania {tool_name} (kod: {process.returncode}). Sprawdź STDERR powyżej.[/bold red]"))
            return None
    except subprocess.TimeoutExpired:
        log_and_echo(f"OSTRZEŻENIE: Komenda '{cmd_str}' przekroczyła limit czasu ({timeout}s).", "WARN")
        progress_obj.console.print(Align.center(f"[bold yellow]⚠️ OSTRZEŻENIE: Komenda '{tool_name}' przekroczyła limit czasu ({timeout}s).[/bold yellow]"))
        return None
    except FileNotFoundError:
        log_and_echo(f"BŁĄD: Narzędzie '{command_parts[0]}' nie zostało znalezione (sprawdź PATH).", "ERROR")
        progress_obj.console.print(Align.center(f"[bold red]❌ BŁĄD: Narzędzie '{command_parts[0]}' nie zostało znalezione (sprawdź PATH).[/bold red]"))
        return None
    except Exception as e:
        log_and_echo(f"BŁĄD: Ogólny błąd wykonania komendy '{cmd_str}': {e}", "ERROR")
        progress_obj.console.print(Align.center(f"[bold red]❌ BŁĄD: Ogólny błąd wykonania komendy '{tool_name}': {e}[/bold red]"))
        return None

def detect_waf_and_propose_safe_mode():
    """Detects WAF using wafw00f and proposes Safe Mode."""
    global SAFE_MODE, WORDLIST_PHASE1, WORDLIST_PHASE2, CUSTOM_HEADER, ORIGINAL_TARGET
    global USER_CUSTOMIZED_WORDLIST_PHASE1, USER_CUSTOMIZED_WORDLIST_PHASE2, USER_CUSTOMIZED_USER_AGENT
    
    if TARGET_IS_IP:
        return

    console.print(Align.center("Sprawdzam ochronę WAF...", style="bold green"))
    
    target_for_waf = ORIGINAL_TARGET 
    wafw00f_command = ["wafw00f", "-a", target_for_waf]
    waf_detected_name = None

    try:
        process = subprocess.run(
            wafw00f_command,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
            check=False
        )
        
        output_lines = process.stdout.strip().splitlines()
        for line in output_lines:
            if "WAF detected" in line or "is behind" in line:
                match = re.search(r'is behind\s+([^(\n]+)', line)
                if not match:
                    match = re.search(r'WAF detected by\s+([^(\n]+)', line)
                
                if match:
                    ansi_escape_pattern = re.compile(r'\x1b\[([0-9]{1,2}(;[0-9]{1,2})*)?[m|K]')
                    waf_detected_name = ansi_escape_pattern.sub('', match.group(1).strip())
                else:
                    waf_detected_name = "Nieznany WAF"
                break
        
    except subprocess.TimeoutExpired:
        log_and_echo(f"wafw00f przekroczył limit czasu dla {target_for_waf}.", "WARN")
        console.print(Align.center(f"[bold yellow]OSTRZEŻENIE: wafw00f przekroczył limit czasu dla {target_for_waf}.[/bold yellow]"))
        return
    except FileNotFoundError:
        log_and_echo("Komenda wafw00f nie została znaleziona. Upewnij się, że jest zainstalowana i w PATH.", "ERROR")
        console.print(Align.center("[bold red]BŁĄD: Komenda wafw00f nie została znaleziona. Upewnij się, że jest zainstalowana i w PATH.[/bold red]"))
        return
    except Exception as e:
        log_and_echo(f"Błąd podczas uruchamiania wafw00f na {target_for_waf}: {e}", "ERROR")
        console.print(Align.center(f"[bold red]BŁĄD: Błąd podczas uruchamiania wafw00f na {target_for_waf}: {e}[/bold red]"))
        return
        
    if waf_detected_name:
        console.print(Align.center(f"[bold yellow]Wykryto WAF: {waf_detected_name} na {ORIGINAL_TARGET}! Zalecany tryb bezpieczny.[/bold yellow]"))
        if not QUIET_MODE:
            response = get_single_char_input_with_prompt(Text.from_markup("[bold yellow]Czy chcesz włączyć Tryb Bezpieczny? (y/n)[/bold yellow]", justify="center"), choices=['y', 'n'], default='n')
            if response.lower() == 'y':
                SAFE_MODE = True
                if not USER_CUSTOMIZED_WORDLIST_PHASE1:
                    WORDLIST_PHASE1 = SMALL_WORDLIST_PHASE1
                if not USER_CUSTOMIZED_WORDLIST_PHASE2:
                    WORDLIST_PHASE2 = SMALL_WORDLIST_PHASE2
                
                if not USER_CUSTOMIZED_USER_AGENT and not CUSTOM_HEADER:
                    CUSTOM_HEADER = phase2_get_random_user_agent_header(user_agents_file=USER_AGENTS_FILE, console_obj=console)
                    console.print(Align.center(f"[bold green]Używam losowego User-Agenta dla Trybu Bezpiecznego: '{CUSTOM_HEADER}'[/bold green]"))
                
                console.print(Align.center("Tryb Bezpieczny WŁĄCZONY. Narzędzia będą działać ze zmniejszoną agresywnością.", style="bold green"))
            else:
                console.print(Align.center("Tryb Bezpieczny pozostaje WYŁĄCZONY.", style="bold green"))
        else:
            SAFE_MODE = True
            if not USER_CUSTOMIZED_WORDLIST_PHASE1:
                WORDLIST_PHASE1 = SMALL_WORDLIST_PHASE1
            if not USER_CUSTOMIZED_WORDLIST_PHASE2:
                WORDLIST_PHASE2 = SMALL_WORDLIST_PHASE2
            if not USER_CUSTOMIZED_USER_AGENT and not CUSTOM_HEADER:
                CUSTOM_HEADER = phase2_get_random_user_agent_header(user_agents_file=USER_AGENTS_FILE, console_obj=console)
            console.print(Align.center("Wykryto WAF. Automatycznie włączam Tryb Bezpieczny w trybie cichym.", style="bold green"))
    else:
        console.print(Align.center("Nie wykryto WAF lub sprawdzanie było niejednoznaczne.", style="bold green"))


def start_phase1_scan(global_progress: Progress, global_task: TaskID):
    """Starts the actual scanning in Phase 1: Subdomain Discovery using ThreadPoolExecutor."""
    global REPORT_DIR, selected_phase1_tools, ORIGINAL_TARGET, THREADS, TOOL_TIMEOUT_SECONDS, WORDLIST_PHASE1, SAFE_MODE, CUSTOM_HEADER, RESOLVERS_FILE, CLEAN_DOMAIN_TARGET

    REPORT_DIR = os.path.join(OUTPUT_BASE_DIR, f"report_{CLEAN_DOMAIN_TARGET}")
    os.makedirs(REPORT_DIR, exist_ok=True)
    global_progress.console.print(Align.center(f"[bold green]Katalog raportów i wyników: {REPORT_DIR}[/bold green]"))

    current_wordlist_p1 = WORDLIST_PHASE1
    shuffled_wordlist_p1_path = None

    if SAFE_MODE:
        global_progress.console.print(Align.center("[bold yellow]Tryb Bezpieczny WŁĄCZONY.[/bold yellow] Dostosowuję parametry narzędzi.", style="bold yellow"))
        if not USER_CUSTOMIZED_WORDLIST_PHASE1:
            current_wordlist_p1 = SMALL_WORDLIST_PHASE1
        if not USER_CUSTOMIZED_USER_AGENT and not CUSTOM_HEADER:
            CUSTOM_HEADER = phase2_get_random_user_agent_header(user_agents_file=USER_AGENTS_FILE, console_obj=console)
            global_progress.console.print(Align.center(f"[bold green]Używam losowego User-Agenta dla Trybu Bezpiecznego: '{CUSTOM_HEADER}'[/bold green]"))
        
        global_progress.console.print(Align.center("Tryb Bezpieczny: tasuję listę słów dla Puredns...", style="bold green"))
        shuffled_wordlist_p1_path = phase2_shuffle_wordlist(current_wordlist_p1, REPORT_DIR)
        if shuffled_wordlist_p1_path:
            current_wordlist_p1 = shuffled_wordlist_p1_path
            TEMP_FILES_TO_CLEAN.append(shuffled_wordlist_p1_path)
        else:
            global_progress.console.print(Align.center(f"[bold yellow]OSTRZEŻENIE: Nie udało się stasować listy słów dla Fazy 1, używam oryginalnej: {current_wordlist_p1}[/bold yellow]"))
    else:
        if not USER_CUSTOMIZED_USER_AGENT and CUSTOM_HEADER:
            CUSTOM_HEADER = ""
        if not USER_CUSTOMIZED_WORDLIST_PHASE1:
            current_wordlist_p1 = DEFAULT_WORDLIST_PHASE1

    global_progress.console.print(Align.center(f"[bold green]Rozpoczynam Fazę 1 - Odkrywanie Subdomen dla {ORIGINAL_TARGET}...[/bold green]"))
    
    puredns_base_cmd = ["puredns", "bruteforce", current_wordlist_p1, CLEAN_DOMAIN_TARGET]
    if os.path.isfile(RESOLVERS_FILE) and os.access(RESOLVERS_FILE, os.R_OK):
        puredns_base_cmd.extend(["--resolvers", RESOLVERS_FILE])
    else:
        log_and_echo(f"OSTRZEŻENIE: Plik resolverów '{RESOLVERS_FILE}' nie znaleziony lub nie jest czytelny.", "WARN")
        global_progress.console.print(Align.center(f"[bold yellow]OSTRZEŻENIE: Plik resolverów '{RESOLVERS_FILE}' nie znaleziony. Puredns użyje domyślnych.[/bold yellow]"))

    tool_configurations = [
        {"name": "Subfinder", "cmd_template": ["subfinder", "-d", CLEAN_DOMAIN_TARGET, "-silent"], "output_filename": "subfinder_results.txt"},
        {"name": "Assetfinder", "cmd_template": ["assetfinder", "--subs-only", CLEAN_DOMAIN_TARGET], "output_filename": "assetfinder_results.txt"},
        {"name": "Findomain", "cmd_template": ["findomain", "--target", CLEAN_DOMAIN_TARGET, "-q"], "output_filename": "findomain_results.txt"},
        {"name": "Puredns", "cmd_template": puredns_base_cmd + ["--rate-limit", "1000", "-q"], "output_filename": "puredns_results.txt"}
    ]
    
    if SAFE_MODE:
        for config in tool_configurations:
            if config["name"] == "Puredns":
                config["cmd_template"] = [arg for arg in puredns_base_cmd if not (arg == "--rate-limit" or arg == "1000")] + ["--rate-limit", "50", "-q"]
                global_progress.console.print(Align.center(f"[bold green]Puredns użyje listy słów: {current_wordlist_p1} i limitu prędkości 50 (Tryb Bezpieczny).[/bold green]"))
                break 

    tasks_to_run = []
    
    for i, config in enumerate(tool_configurations):
        if selected_phase1_tools[i] == 1:
            if TARGET_IS_IP and config["name"] in ["Subfinder", "Assetfinder", "Findomain"]:
                global_progress.console.print(Align.center(f"[bold yellow]Pominięto {config['name']} dla celu IP.[/bold yellow]"))
                continue
            
            output_path = os.path.join(REPORT_DIR, config["output_filename"])
            tasks_to_run.append((config["name"], config["cmd_template"], output_path))
            TEMP_FILES_TO_CLEAN.append(output_path)

    if not tasks_to_run:
        global_progress.console.print(Align.center("Nie wybrano aktywnych narzędzi do odkrywania subdomen. Pomijam fazę.", style="bold yellow"))
        time.sleep(1)
        return {}, {}
    
    futures = []
    output_files_collected = {}
    
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        for tool_name, cmd_template, output_file in tasks_to_run:
            future = executor.submit(_execute_tool_command, tool_name, cmd_template, output_file, TOOL_TIMEOUT_SECONDS, global_progress, global_task)
            futures.append((tool_name, future))

        for tool_name, future in futures:
            result_file = future.result()
            if result_file:
                output_files_collected[tool_name] = result_file
            global_progress.update(global_task, advance=1)

    global_progress.console.print(Align.center("Integracja wyników odkrywania subdomen...", style="bold green"))
    combined_subdomains_file = os.path.join(REPORT_DIR, "all_subdomains_raw.txt")
    unique_subdomains_file = os.path.join(REPORT_DIR, "all_subdomains_unique.txt")
    TEMP_FILES_TO_CLEAN.append(combined_subdomains_file)
    TEMP_FILES_TO_CLEAN.append(unique_subdomains_file)

    all_lines = []
    for tool_name, f_path in output_files_collected.items():
        try:
            with open(f_path, 'r', encoding='utf-8') as f:
                all_lines.extend(f.readlines())
        except FileNotFoundError:
            log_and_echo(f"OSTRZEŻENIE: Plik wyników nie znaleziony dla {tool_name}: {f_path}", "WARN")
            global_progress.console.print(Align.center(f"[bold yellow]OSTRZEŻENIE: Plik wyników nie znaleziony dla {tool_name}: {f_path}[/bold yellow]"))
        except Exception as e:
            log_and_echo(f"BŁĄD: Błąd odczytu pliku {f_path}: {e}", "ERROR")
            global_progress.console.print(Align.center(f"[bold red]BŁĄD: Błąd odczytu pliku {f_path}: {e}[/bold red]"))

    with open(combined_subdomains_file, 'w', encoding='utf-8') as f:
        for line in all_lines:
            f.write(line.strip() + '\n')
    
    safe_sort_unique(combined_subdomains_file, unique_subdomains_file)
    global_progress.update(global_task, advance=1)

    global_progress.console.print(Align.center("Uruchamiam HTTPX na unikalnych subdomenach...", style="bold green"))
    httpx_output_file = os.path.join(REPORT_DIR, "httpx_results.txt")
    TEMP_FILES_TO_CLEAN.append(httpx_output_file)
    
    httpx_command = ["httpx", "-l", unique_subdomains_file, "-silent", "-fc", "404", "-json"]
    if SAFE_MODE:
        httpx_command.extend(["-p", "80,443,8000,8080,8443"])
        httpx_command.extend(["-rate-limit", "10"])
        extra_headers = phase2_get_random_browser_headers()
        for header in extra_headers:
            httpx_command.extend(["-H", header])
        if CUSTOM_HEADER: 
             httpx_command.extend(["-H", f"User-Agent: {CUSTOM_HEADER}"])
        else: 
             httpx_command.extend(["-H", f"User-Agent: {phase2_get_random_user_agent_header(USER_AGENTS_FILE)}"])

    elif CUSTOM_HEADER:
        httpx_command.extend(["-H", f"User-Agent: {CUSTOM_HEADER}"])

    active_urls = []
    if not os.path.exists(unique_subdomains_file) or os.path.getsize(unique_subdomains_file) == 0:
        log_and_echo(f"OSTRZEŻENIE: Plik unikalnych subdomen pusty: {unique_subdomains_file}. Pomijam HTTPX.", "WARN")
        global_progress.console.print(Align.center(f"[bold yellow]OSTRZEŻENIE: Plik unikalnych subdomen pusty. Pomijam HTTPX.[/bold yellow]"))
    else:
        httpx_result_file = _execute_tool_command("Httpx", httpx_command, httpx_output_file, TOOL_TIMEOUT_SECONDS, global_progress, global_task)
        if httpx_result_file:
            output_files_collected["Httpx"] = httpx_result_file
            with open(httpx_result_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        json_line = json.loads(line)
                        url = json_line.get("url")
                        status_code = json_line.get("status_code")
                        if url and status_code and 200 <= int(status_code) < 400:
                            active_urls.append(url)
                    except (json.JSONDecodeError, TypeError):
                        match = re.search(r'^(https?:\/\/[^\s\[]+).*?\[(\d{3})\]', line)
                        if match:
                            url, code = match.group(1), int(match.group(2))
                            if 200 <= code < 400:
                                active_urls.append(url)
                        else:
                            match = re.search(r'^(https?:\/\/[^\s]+)', line)
                            if match:
                                active_urls.append(match.group(1))

    global_progress.update(global_task, advance=1)
    
    global_progress.console.print(Align.center("Faza 1 - Odkrywanie Subdomen zakończone.", style="bold green"))
    
    return output_files_collected, sorted(list(set(active_urls)))


def start_phase2_scan(httpx_results_urls: List[str], global_progress: Progress, global_task: TaskID):
    """Starts Phase 2: Directory Searching by calling the integrated phase2_dirsearch.py function."""
    global REPORT_DIR, SAFE_MODE, CUSTOM_HEADER, WORDLIST_PHASE2, SMALL_WORDLIST_PHASE2, THREADS, TOOL_TIMEOUT_SECONDS, LOG_FILE, USER_AGENTS_FILE, selected_phase2_tools

    if not httpx_results_urls:
        console.print(Align.center("[bold yellow]Brak URL-i do skanowania w Fazie 2.[/bold yellow]"))
        return {}

    console.print(Align.center(f"\n[bold green]Rozpoczynam Fazę 2 - Wyszukiwanie Katalogów dla {len(httpx_results_urls)} aktywnych URL-i...[/bold green]"))

    phase2_all_results = {}
    try:
        phase2_all_results = phase2_start_dir_search(
            urls=httpx_results_urls,
            report_dir=REPORT_DIR,
            safe_mode=SAFE_MODE,
            custom_header=CUSTOM_HEADER,
            wordlist_path=WORDLIST_PHASE2,
            small_wordlist_path=SMALL_WORDLIST_PHASE2,
            threads=THREADS,
            tool_timeout=TOOL_TIMEOUT_SECONDS,
            log_file=LOG_FILE,
            user_agents_file=USER_AGENTS_FILE,
            selected_tools_config=selected_phase2_tools,
            console_obj=console,
            progress_obj=global_progress,
            main_task_id=global_task
        )
    except Exception as e:
        log_and_echo(f"BŁĄD: Nieoczekiwany błąd podczas uruchamiania Fazy 2 (integracja): {e}", "ERROR")
        console.print(Align.center(f"[bold red]BŁĄD: Nieoczekiwany błąd podczas uruchamiania Fazy 2 (integracja): {e}[/bold red]"))
    
    console.print(Align.center("[bold green]Faza 2 - Wyszukiwanie Katalogów zakończona.[/bold green]"))
    return phase2_all_results


def open_html_report(report_path: str):
    """Opens the generated HTML report in the default web browser."""
    if not os.path.exists(report_path):
        log_and_echo(f"BŁĄD: Plik raportu nie znaleziony: {report_path}", "ERROR")
        console.print(Align.center(f"[bold red]BŁĄD: Plik raportu nie znaleziony: {report_path}[/bold red]"))
        return

    if sys.platform == "win32":
        os.startfile(report_path)
    elif sys.platform == "darwin":
        subprocess.run(["open", report_path])
    else:
        try:
            subprocess.run(["xdg-open", report_path])
        except FileNotFoundError:
            log_and_echo("xdg-open nie znaleziono. Otwórz raport ręcznie.", "WARN")
            console.print(Align.center("[bold yellow]OSTRZEŻENIE: xdg-open nie znaleziono. Otwórz raport ręcznie.[/bold yellow]"))
        except Exception as e:
            log_and_echo(f"Błąd otwierania raportu: {e}", "ERROR")
            console.print(Align.center(f"[bold red]BŁĄD: Błąd otwierania raportu: {e}[/bold red]"))


    console.print(Align.center(f"[bold green]Otwarto raport HTML w przeglądarce: {report_path}[/bold green]"))


def safe_sort_unique(input_path: str, output_path: str):
    console.print(Align.center(f"Sortowanie i deduplikacja '{os.path.basename(input_path)}' do '{os.path.basename(output_path)}'...", style="bold green"))
    try:
        with open(input_path, 'r', encoding='utf-8') as infile:
            lines = infile.readlines()
        
        unique_lines = sorted(list(set(line.strip() for line in lines if line.strip())))
        
        with open(output_path, 'w', encoding='utf-8') as outfile:
            for line in unique_lines:
                outfile.write(line + '\n')
        
        console.print(Align.center("Sortowanie i deduplikacja zakończone pomyślnie.", style="bold green"))
        return True
    except FileNotFoundError:
        log_and_echo(f"Plik wejściowy '{input_path}' nie istnieje. Tworzę pusty plik wyjściowy.", "WARN")
        console.print(Align.center(f"[bold yellow]OSTRZEŻENIE: Plik wejściowy '{os.path.basename(input_path)}' nie istnieje.[/bold yellow]"))
        open(output_path, 'w', encoding='utf-8').close()
        return False
    except Exception as e:
        log_and_echo(f"Błąd sortowania/deduplikacji pliku '{input_path}': {e}", "ERROR")
        console.print(Align.center(f"[bold red]BŁĄD: Błąd sortowania/deduplikacji pliku '{os.path.basename(input_path)}': {e}[/bold red]"))
        return False

def generate_html_report(phase1_raw_output_files: Dict[str, str], phase2_results: Dict[str, List[str]]):
    """Generates an HTML report from scan results using a template."""
    global REPORT_DIR, ORIGINAL_TARGET, HTML_TEMPLATE_PATH, CLEAN_DOMAIN_TARGET
    
    report_path = os.path.join(REPORT_DIR, "report.html")
    
    try:
        with open(HTML_TEMPLATE_PATH, 'r', encoding='utf-8') as f:
            html_template = f.read()
    except FileNotFoundError:
        log_and_echo(f"Plik szablonu HTML nie znaleziony w '{HTML_TEMPLATE_PATH}'.", "ERROR")
        console.print(Align.center(f"[bold red]BŁĄD: Plik szablonu HTML nie znaleziony w '{HTML_TEMPLATE_PATH}'.[/bold red]"))
        return
    except Exception as e:
  
        log_and_echo(f"Błąd odczytu szablonu HTML: {e}", "ERROR")
        console.print(Align.center(f"[bold red]BŁĄD: Błąd odczytu szablonu HTML: {e}[/bold red]"))
        return

    unique_subdomains_file = os.path.join(REPORT_DIR, "all_subdomains_unique.txt")
    unique_subdomains = []
    try:
        with open(unique_subdomains_file, 'r', encoding='utf-8') as f:
            unique_subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        log_and_echo(f"Plik unikalnych subdomen nie znaleziony: {unique_subdomains_file}", "WARN")
        console.print(Align.center(f"[bold yellow]OSTRZEŻENIE: Plik unikalnych subdomen nie znaleziony.[/bold yellow]"))

    all_dirsearch_results_formatted = "<br>".join(phase2_results.get("all_dirsearch_results", [])) if phase2_results.get("all_dirsearch_results") else "Brak wyników"
    dirsearch_specific_results_formatted = "<br>".join(phase2_results.get("dirsearch", [])) if phase2_results.get("dirsearch") else "Brak wyników"
    ffuf_specific_results_formatted = "<br>".join(phase2_results.get("ffuf", [])) if phase2_results.get("ffuf") else "Brak wyników"
    feroxbuster_specific_results_formatted = "<br>".join(phase2_results.get("feroxbuster", [])) if phase2_results.get("feroxbuster") else "Brak wyników"
    gobuster_specific_results_formatted = "<br>".join(phase2_results.get("gobuster", [])) if phase2_results.get("gobuster") else "Brak wyników"

    replacements = {
        "{{DOMAIN}}": ORIGINAL_TARGET,
        "{{COUNT_ALL_SUBDOMAINS}}": str(len(unique_subdomains)),
        "{{ALL_SUBDOMAINS_OUTPUT}}": "<br>".join(unique_subdomains) if unique_subdomains else "Brak wyników",
        "{{COUNT_HTTPX}}": "0", 
        "{{HTTPX_OUTPUT_RAW_FOR_JS}}": "", 

        "{{COUNT_SUBFINDER}}": "0",
        "{{SUBFINDER_OUTPUT}}": "Brak wyników",
        "{{COUNT_ASSETFINDER}}": "0",
        "{{ASSETFINDER_OUTPUT}}": "Brak wyników",
        "{{COUNT_FINDOMAIN}}": "0",
        "{{FINDOMAIN_OUTPUT}}": "Brak wyników",
        "{{COUNT_PUREDNS}}": "0",
        "{{PUREDNS_OUTPUT}}": "Brak wyników",
        
        "{{COUNT_DIR_SEARCH}}": str(len(phase2_results.get("all_dirsearch_results", []))),
        "{{DIR_SEARCH_OUTPUT}}": all_dirsearch_results_formatted,
        "{{DIRSEARCH_SPECIFIC_OUTPUT}}": dirsearch_specific_results_formatted,
        "{{FFUF_SPECIFIC_OUTPUT}}": ffuf_specific_results_formatted,
        "{{FEROXBUSTER_SPECIFIC_OUTPUT}}": feroxbuster_specific_results_formatted,
        "{{GOBUSTER_SPECIFIC_OUTPUT}}": gobuster_specific_results_formatted,

        "{{COUNT_ALL_URLS}}": "0",
        "{{ALL_URLS_OUTPUT}}": "Brak wyników",
        "{{COUNT_PARAMETERS}}": "0",
        "{{PARAMETERS_OUTPUT}}": "Brak wyników",
        "{{COUNT_JS_FILES}}": "0",
        "{{JS_FILES_OUTPUT}}": "Brak wyników",
        "{{COUNT_API_ENDPOINTS}}": "0",
        "{{API_ENDPOINTS}}": "Brak wyników",
        "{{COUNT_INTERESTING_FILES}}": "0",
        "{{INTERESTING_FILES}}": "Brak wyników",
        "{{COUNT_SENSITIVE_PATHS}}": "0",
        "{{SENSITIVE_PATHS}}": "Brak wyników",
    }

    for tool_name, file_path in phase1_raw_output_files.items():
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                output_content = f.read().strip()
                lines = output_content.split('\n')
                count = len([line for line in lines if line.strip()])
                
                html_output_br = "<br>".join(lines) if lines else "Brak wyników"

                if tool_name == "Subfinder":
                    replacements["{{SUBFINDER_OUTPUT}}"] = html_output_br
                    replacements["{{COUNT_SUBFINDER}}"] = str(count)
                elif tool_name == "Assetfinder":
                    replacements["{{ASSETFINDER_OUTPUT}}"] = html_output_br
                    replacements["{{COUNT_ASSETFINDER}}"] = str(count)
                elif tool_name == "Findomain":
                    replacements["{{FINDOMAIN_OUTPUT}}"] = html_output_br
                    replacements["{{COUNT_FINDOMAIN}}"] = str(count)
                elif tool_name == "Puredns":
                    replacements["{{PUREDNS_OUTPUT}}"] = html_output_br
                    replacements["{{COUNT_PUREDNS}}"] = str(count)
                elif tool_name == "Httpx":
                    replacements["{{HTTPX_OUTPUT_RAW_FOR_JS}}"] = output_content
                    
                    active_httpx_count = 0
                    for line in lines:
                        try:
                            json_line = json.loads(line)
                            status_code = json_line.get("status_code")
                            if status_code and 200 <= int(status_code) < 400:
                                active_httpx_count += 1
                        except (json.JSONDecodeError, TypeError):
                            match = re.search(r'\[(\d{3})\]', line)
                            if match and 200 <= int(match.group(1)) < 400:
                                active_httpx_count += 1
                            
                    replacements["{{COUNT_HTTPX}}"] = str(active_httpx_count)

        except FileNotFoundError:
            log_and_echo(f"Plik surowych danych nie znaleziony dla {tool_name}: {file_path}", "WARN")
            console.print(Align.center(f"[bold yellow]OSTRZEŻENIE: Plik surowych danych nie znaleziony dla {tool_name}: {file_path}[/bold yellow]"))
        except Exception as e:
            log_and_echo(f"Błąd przetwarzania danych dla {tool_name} z {file_path}: {e}", "ERROR")
            console.print(Align.center(f"[bold red]BŁĄD: Błąd przetwarzania danych dla {tool_name} z {file_path}: {e}[/bold red]"))

    final_html_content = html_template
    for placeholder, value in replacements.items():
        final_html_content = re.sub(re.escape(placeholder), value, final_html_content)

    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(final_html_content)
        console.print(Align.center(f"[bold green]Wygenerowano raport HTML: {report_path}[/bold green]"))
    except Exception as e:
        log_and_echo(f"Nie można wygenerować raportu HTML: {e}", "ERROR")
        console.print(Align.center(f"[bold red]BŁĄD: Nie można wygenerować raportu HTML: {e}[/bold red]"))


def cleanup_temp_files():
    console.print(Align.center("Czyszczę pliki tymczasowe...", style="bold green"))
    for f_path in TEMP_FILES_TO_CLEAN:
        if os.path.exists(f_path):
            try:
                if os.path.isdir(f_path):
                    shutil.rmtree(f_path)
                else:
                    os.remove(f_path)
            except Exception as e:
                log_and_echo(f"Nie można usunąć pliku/katalogu tymczasowego '{f_path}': {e}", "WARN")
                console.print(Align.center(f"[bold yellow]OSTRZEŻENIE: Nie można usunąć '{os.path.basename(f_path)}': {e}[/bold red]"))


def main(
    target: str = typer.Argument(..., help="Domain or IP address to scan."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Runs the scan in quiet mode (non-interactive)"),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Output directory for the report"),
    assume_yes: bool = typer.Option(False, "--yes", "-y", help="Automatically accept all interactive prompts."),
    no_report: bool = typer.Option(False, "--no-report", help="Skips HTML report generation."),
    log_file: Optional[Path] = typer.Option(None, "--log-file", "-l", help="Saves logs to a file."),
    phase2_only: bool = typer.Option(False, "--phase2-only", help="Run only Phase 2 (Dir searching)."),
):
    global QUIET_MODE, LOG_FILE, OUTPUT_BASE_DIR, REPORT_DIR, selected_phase1_tools, selected_phase2_tools, \
           WORDLIST_PHASE1, WORDLIST_PHASE2, SAFE_MODE, CUSTOM_HEADER, SCAN_ONLY_CRITICAL, \
           USER_CUSTOMIZED_WORDLIST_PHASE1, USER_CUSTOMIZED_WORDLIST_PHASE2, USER_CUSTOMIZED_USER_AGENT, \
           DEFAULT_WORDLIST_PHASE1, DEFAULT_WORDLIST_PHASE2, DEFAULT_THREADS, DEFAULT_TOOL_TIMEOUT_SECONDS, \
           DEFAULT_RESOLVERS_FILE, THREADS, TOOL_TIMEOUT_SECONDS, RESOLVERS_FILE


    QUIET_MODE = quiet
    LOG_FILE = log_file

    if output_dir:
        OUTPUT_BASE_DIR = output_dir

    if LOG_FILE:
        try:
            logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        except Exception as e:
            console.print(Align.center(f"[bold red]Błąd: Nie można otworzyć pliku logu '{LOG_FILE}': {e}[/bold red]"))

    parse_target_input(target)
    check_dependencies()
    
    phase1_output_files = {} 
    httpx_active_urls = []   
    phase2_all_results = {}  

    scan_initiated = False

    global_progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        "•",
        TimeElapsedColumn(),
        console=console,
        transient=True
    )
    global_task = None

    try:
        scan_active = False
        
        if phase2_only:
            scan_active = True
            selected_phase2_tools = [1, 1, 1, 1]
            total_steps = sum(selected_phase2_tools) * 1
            global_task = global_progress.add_task("[bold green]Całkowity postęp[/bold green]", total=total_steps)
            
        elif not QUIET_MODE:
            choice = ""
            while not scan_active and choice.lower() != 'q':
                choice = display_main_menu()
                if choice == '1':
                    if display_phase1_tool_selection_menu():
                        scan_active = True
                elif choice == '2':
                     if display_phase2_tool_selection_menu():
                        scan_active = True
                        phase2_only = True 
        else: # quiet mode
            scan_active = True
            selected_phase1_tools = [1, 1, 1, 1]
            selected_phase2_tools = [1, 1, 1, 1]

        if scan_active:
            with global_progress:
                if phase2_only:
                    console.print(Align.center("[bold cyan]Uruchamiam tylko Fazę 2 - Wyszukiwanie Katalogów.[/bold cyan]"))
                    httpx_active_urls.append(ORIGINAL_TARGET) 
                    if not SAFE_MODE: detect_waf_and_propose_safe_mode()
                    REPORT_DIR = os.path.join(OUTPUT_BASE_DIR, f"report_{CLEAN_DOMAIN_TARGET}")
                    os.makedirs(REPORT_DIR, exist_ok=True)
                    urls_to_scan_phase2 = filter_critical_urls(httpx_active_urls) if SCAN_ONLY_CRITICAL else httpx_active_urls
                    if urls_to_scan_phase2:
                        phase2_steps = len(urls_to_scan_phase2) * sum(selected_phase2_tools)
                        if phase2_steps > 0:
                            global_task = global_progress.add_task("[bold green]Postęp Fazy 2[/bold green]", total=phase2_steps)
                            phase2_all_results = start_phase2_scan(urls_to_scan_phase2, global_progress, global_task)
                    scan_initiated = True

                else:
                    if not SAFE_MODE: detect_waf_and_propose_safe_mode()
                    if TARGET_IS_IP and not any(selected_phase1_tools): selected_phase1_tools = [0, 0, 0, 1]
                    elif not any(selected_phase1_tools): selected_phase1_tools = [1, 1, 1, 1]

                    phase1_steps = sum(1 for i, t in enumerate(selected_phase1_tools) if t and not (TARGET_IS_IP and i < 3)) + 2
                    if global_task is None: global_task = global_progress.add_task("[bold green]Postęp Fazy 1[/bold green]", total=phase1_steps)
                    
                    phase1_output_files, httpx_active_urls = start_phase1_scan(global_progress, global_task)
                    scan_initiated = True

                    if httpx_active_urls:
                        critical_urls = filter_critical_urls(httpx_active_urls)
                        console.print(Panel(f"Znaleziono [bold cyan]{len(httpx_active_urls)}[/bold cyan] aktywnych subdomen, w tym [bold red]{len(critical_urls)}[/bold red] krytycznych.", 
                                            title="[bold green]Podsumowanie Fazy 1[/bold green]", expand=False))
                        
                        continue_to_phase2 = get_single_char_input_with_prompt(
                            Text.from_markup("[bold cyan]Czy chcesz kontynuować i uruchomić Fazę 2 (Wyszukiwanie katalogów)? (y/n)[/bold cyan]", justify="center"),
                            choices=['y', 'n'], default='y'
                        )

                        if continue_to_phase2.lower() == 'y':
                            if display_phase2_tool_selection_menu():
                                scan_mode_choice = get_single_char_input_with_prompt(
                                    Text.from_markup("[bold cyan]Skanować wszystkie URL-e ([/bold cyan]a[bold cyan]) czy tylko krytyczne ([/bold cyan]c[bold cyan])? (a/c)[/bold cyan]", justify="center"),
                                    choices=['a', 'c'], default='a'
                                )
                                
                                urls_to_scan_phase2 = critical_urls if scan_mode_choice.lower() == 'c' else httpx_active_urls

                                if urls_to_scan_phase2:
                                    phase2_steps = len(urls_to_scan_phase2) * sum(selected_phase2_tools)
                                    if phase2_steps > 0:
                                        global_task = global_progress.add_task("[bold green]Postęp Fazy 2[/bold green]", total=phase2_steps)
                                        phase2_all_results = start_phase2_scan(urls_to_scan_phase2, global_progress, global_task)
                                    else:
                                        console.print(Align.center("[bold yellow]Nie wybrano narzędzi dla Fazy 2. Pomijam.[/bold yellow]"))
    
    except Exception as e:
        log_and_echo(f"Wystąpił nieoczekiwany błąd w głównym procesie: {e}", "ERROR")
        console.print(Align.center(f"[bold red]BŁĄD: Wystąpił nieoczekiwany błąd w głównym procesie: {e}[/bold red]"))
    finally:
        pass

    if scan_initiated:
        console.print(Align.center(f"\n[bold green]Skanowanie zakończono dla: {ORIGINAL_TARGET}[/bold green]"))
        if not no_report:
            generate_html_report(phase1_output_files, phase2_all_results)
            report_full_path = os.path.join(REPORT_DIR, "report.html")
            if REPORT_DIR and os.path.exists(report_full_path):
                console.print(Align.center(f"[bold green]Raport HTML i wyniki w katalogu: {REPORT_DIR}[/bold green]"))
                open_html_report(report_full_path) 
            else:
                console.print(Align.center("[bold yellow]OSTRZEŻENIE: Raport HTML nie został wygenerowany lub jest pusty.[/bold yellow]"))
    else:
        console.print(Align.center(f"\n[bold green]Zakończono. Skanowanie nie zostało uruchomione.[/bold green]"))

    cleanup_temp_files()

if __name__ == "__main__":
    typer.run(main)
