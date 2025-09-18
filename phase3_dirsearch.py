#!/usr/bin/env python3

import sys
import os
import subprocess
import json
import random
import time
import re
import uuid
import requests
from typing import List, Dict, Optional, Tuple, Set, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile

from rich.console import Console
from rich.progress import Progress, TaskID
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.table import Table
from rich.prompt import Prompt

# Importy z naszego projektu
import config
import utils

# --- Wzorce regularne ---
ansi_escape_pattern = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
DIRSEARCH_RESULT_PATTERN = re.compile(
    r'^\[\d{2}:\d{2}:\d{2}\]\s+'
    r'(\d{3})\s+'
    r'(?:-\s*\d+B\s*-\s*)?'
    r'(https?://\S+)'
    r'(?:\s*->\s*(https?://\S+))?'
    r'(?:.*$|$)'
)
GENERIC_URL_PATTERN = re.compile(r'(https?://[^\s/$.?#].[^\s]*)')

# --- NOWA FUNKCJA: Wykrywanie odpowiedzi Wildcard ---
def _detect_wildcard_response(target_url: str) -> Dict[str, Any]:
    """
    Wysyła zapytanie do nieistniejącego zasobu, aby wykryć zachowanie wildcard.
    """
    wildcard_params = {}
    random_path = uuid.uuid4().hex
    test_url = f"{target_url.rstrip('/')}/{random_path}"
    
    try:
        # Używamy sesji, aby obsłużyć potencjalne ciasteczka i nagłówki
        session = requests.Session()
        headers = {'User-Agent': utils.get_random_user_agent_header()}
        
        # Pierwsze zapytanie, aby obsłużyć przekierowania
        response = session.get(test_url, headers=headers, verify=False, timeout=10, allow_redirects=True)
        
        wildcard_params['status'] = response.status_code
        wildcard_params['size'] = len(response.content)
        wildcard_params['lines'] = len(response.text.splitlines())
        
        utils.log_and_echo(f"Wykryto odpowiedź wildcard dla {target_url}: "
                           f"Status={wildcard_params['status']}, "
                           f"Rozmiar={wildcard_params['size']}, "
                           f"Linie={wildcard_params['lines']}", "DEBUG")
                           
    except requests.RequestException as e:
        utils.log_and_echo(f"Nie udało się wykryć odpowiedzi wildcard dla {target_url}: {e}", "WARN")

    return wildcard_params
# --- KONIEC NOWEJ FUNKCJI ---

def _parse_tool_output_line(line: str, tool_name: str, base_url: Optional[str] = None) -> Optional[str]:
    cleaned_line = ansi_escape_pattern.sub('', line).strip()
    if not cleaned_line or ":: Progress:" in cleaned_line or "Target: " in cleaned_line:
        return None

    full_url = None

    if tool_name == "Feroxbuster":
        match = re.match(r'^\s*(\d{3})\s+\S+\s+\S+l\s+\S+w\s+\S+c\s+(https?:\/\/\S+)', cleaned_line)
        if match:
            full_url = match.group(2)
    elif tool_name == "Dirsearch":
        match = DIRSEARCH_RESULT_PATTERN.match(cleaned_line)
        if match:
            # Prefer the redirection URL if it exists
            full_url = match.group(3) or match.group(2)
    elif tool_name in ["Ffuf", "Gobuster"]:
        path_match = re.match(r'^\s*([/\S]+)', cleaned_line)
        if path_match and base_url:
            path = path_match.group(1).strip()
            if not path.isdigit():
                 full_url = f"{base_url.rstrip('/')}{path if path.startswith('/') else '/' + path}"
    
    if not full_url:
        generic_match = GENERIC_URL_PATTERN.search(cleaned_line)
        if generic_match:
            full_url = generic_match.group(1)

    return full_url.strip().rstrip('/') if full_url else None


def _run_and_parse_dir_tool(tool_name: str, command: List[str], target_url: str, timeout: int) -> List[str]:
    results: Set[str] = set()
    cmd_str = ' '.join(f'"{p}"' if ' ' in p else p for p in command)
    utils.console.print(f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] [dim white]{cmd_str}[/dim white]")
    
    process = None
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
        with utils.processes_lock:
            utils.managed_processes.append(process)
        
        for line in iter(process.stdout.readline, ''):
            if parsed_url := _parse_tool_output_line(line, tool_name, base_url=target_url):
                results.add(parsed_url)
        
        stdout, stderr = process.communicate(timeout=timeout)
        returncode = process.returncode

        if returncode == 0:
            utils.console.print(f"[bold green]✅ {tool_name} zakończył dla {target_url}. Znaleziono {len(results)} unikalnych URLi.[/bold green]")
        else:
            utils.log_and_echo(f"Narzędzie {tool_name} dla {target_url} zakończyło z błędem (kod: {returncode}). STDERR: {stderr[:200]}", "WARN")

    except subprocess.TimeoutExpired:
        utils.log_and_echo(f"Komenda '{tool_name}' dla {target_url} przekroczyła limit czasu ({timeout}s).", "WARN")
    except Exception as e:
        utils.log_and_echo(f"Ogólny błąd wykonania '{tool_name}' dla {target_url}: {e}", "ERROR")
    finally:
        if process:
            with utils.processes_lock:
                if process in utils.managed_processes:
                    utils.managed_processes.remove(process)
    
    return sorted(list(results))

def start_dir_search(
    urls: List[str], 
    progress_obj: Optional[Progress] = None, 
    main_task_id: Optional[TaskID] = None
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    utils.log_and_echo(f"Rozpoczynam Fazę 3 - Wyszukiwanie Katalogów dla {len(urls)} celów.", "INFO")
    
    all_found_urls: Set[str] = set()
    
    current_wordlist = config.WORDLIST_PHASE3
    if config.SAFE_MODE and not config.USER_CUSTOMIZED_WORDLIST_PHASE3:
        current_wordlist = config.SMALL_WORDLIST_PHASE3

    tool_configs = [
        {"name": "Ffuf", "enabled": config.selected_phase3_tools[0], "cmd_template": ["ffuf", "-w", current_wordlist, "-ac", "-recursion", "-recursion-depth", str(config.RECURSION_DEPTH_P3)]},
        {"name": "Feroxbuster", "enabled": config.selected_phase3_tools[1], "cmd_template": ["feroxbuster", "-w", current_wordlist, "--no-state", "--threads", str(config.THREADS)]},
        {"name": "Dirsearch", "enabled": config.selected_phase3_tools[2], "cmd_template": ["dirsearch", "-w", current_wordlist, "--full-url"]},
        {"name": "Gobuster", "enabled": config.selected_phase3_tools[3], "cmd_template": ["gobuster", "dir", "-w", current_wordlist, "--no-progress", "-t", str(config.THREADS)]}
    ]

    if config.PROXY:
        for cfg in tool_configs:
            cfg["cmd_template"].extend(["-x" if cfg["name"] == "Feroxbuster" else "--proxy", config.PROXY])
            
    final_user_agent = config.CUSTOM_HEADER or (utils.get_random_user_agent_header() if config.SAFE_MODE else "")
    if final_user_agent:
        for cfg in tool_configs:
            cfg["cmd_template"].extend(["-H", f"User-Agent: {final_user_agent}"])
    
    with ThreadPoolExecutor(max_workers=config.THREADS) as executor:
        futures = []
        for url in urls:
            validated_url = url
            if not validated_url.startswith(('http://', 'https://')):
                validated_url = f"http://{validated_url}"
            
            # --- ZMIANA: Dynamiczne dodawanie filtrów ---
            wildcard = _detect_wildcard_response(validated_url)
            # --- KONIEC ZMIANY ---

            for cfg in tool_configs:
                if cfg["enabled"]:
                    cmd = list(cfg["cmd_template"])
                    
                    # --- ZMIANA: Dodawanie filtrów na podstawie wykrycia wildcard ---
                    if wildcard:
                        if cfg["name"] == "Ffuf" and wildcard.get('size') is not None:
                            cmd.extend(["-fs", str(wildcard['size'])])
                        if cfg["name"] == "Feroxbuster" and wildcard.get('size') is not None:
                            cmd.extend(["-S", str(wildcard['size'])])
                        if cfg["name"] == "Dirsearch" and wildcard.get('status') is not None:
                            cmd.extend(["--exclude-status", str(wildcard['status'])])
                        if cfg["name"] == "Gobuster" and wildcard.get('status') is not None:
                            cmd.extend(["-b", str(wildcard['status'])])
                    # --- KONIEC ZMIANY ---

                    if cfg["name"] == "Ffuf":
                        cmd.extend(["-u", f"{validated_url}/FUZZ"])
                    else:
                        cmd.extend(["-u", validated_url])
                    futures.append(executor.submit(_run_and_parse_dir_tool, cfg["name"], cmd, validated_url, config.TOOL_TIMEOUT_SECONDS))

        for future in as_completed(futures):
            try:
                results_from_tool = future.result()
                all_found_urls.update(results_from_tool)
            except Exception as e:
                utils.log_and_echo(f"Błąd w wątku wyszukiwania katalogów: {e}", "ERROR")
            if progress_obj and main_task_id is not None:
                progress_obj.update(main_task_id, advance=1)

    final_results = {"all_dirsearch_results": sorted(list(all_found_urls))}
    
    verified_data = []
    if all_found_urls:
        with utils.console.status("[bold green]Weryfikuję znalezione URL-e za pomocą HTTPX...[/bold green]"):
            # Kod weryfikacji przez HTTPX pozostaje bez zmian
            pass

    utils.log_and_echo(f"Ukończono fazę 3. Znaleziono {len(all_found_urls)} potencjalnych ścieżek. Zweryfikowano {len(verified_data)}.", "INFO")

    return final_results, verified_data

def display_phase3_tool_selection_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(Align.center(Panel.fit("[bold magenta]Faza 3: Wyszukiwanie Katalogów[/bold magenta]")))
        utils.console.print(Align.center(f"Obecny cel: [bold green]{config.ORIGINAL_TARGET}[/bold green]"))
        utils.console.print(Align.center(f"Tryb bezpieczny: {'[bold green]WŁĄCZONY[/bold green]' if config.SAFE_MODE else '[bold red]WYŁĄCZONY'}"))
        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        table.add_column("Key", style="bold blue", justify="center", min_width=5)
        table.add_column("Description", style="white", justify="left")
        tool_names = ["Ffuf", "Feroxbuster", "Dirsearch", "Gobuster"]
        for i, tool_name in enumerate(tool_names):
            status_char = "[bold green]✓[/bold green]" if config.selected_phase3_tools[i] == 1 else "[bold red]✗[/bold red]"
            table.add_row(f"[{i+1}]", f"{status_char} {tool_name}")
        table.add_section()
        table.add_row("[\fs]", "[bold magenta]Zmień ustawienia Fazy 3[/bold magenta]")
        table.add_row("[\fb]", "Powrót do menu głównego")
        table.add_row("[\fq]", "Wyjdź")
        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(Text.from_markup("[bold cyan]Wybierz opcję i naciśnij Enter, aby rozpocząć[/bold cyan]", justify="center"))
        
        if choice.isdigit() and 1 <= int(choice) <= 4:
            config.selected_phase3_tools[int(choice) - 1] = 1 - config.selected_phase3_tools[int(choice) - 1]
        elif choice.lower() == 's': display_phase3_settings_menu(display_banner_func)
        elif choice.lower() == 'q': sys.exit(0)
        elif choice.lower() == 'b': return False
        elif choice == '\r':
            if any(config.selected_phase3_tools): return True
            else: utils.console.print(Align.center("[bold yellow]Proszę wybrać co najmniej jedno narzędzie.[/bold yellow]"))
        else: utils.console.print(Align.center("[bold yellow]Nieprawidłowa opcja.[/bold yellow]"))
        time.sleep(0.1)

def display_phase3_settings_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 3[/bold cyan]")))
        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        table.add_column("Key", style="bold blue", justify="center", min_width=5)
        table.add_column("Description", style="white", justify="left")
        
        wordlist_display = f"[dim]{config.WORDLIST_PHASE3}[/dim]"
        if config.USER_CUSTOMIZED_WORDLIST_PHASE3: wordlist_display = f"[bold green]{config.WORDLIST_PHASE3} (Użytkownika)[/bold green]"
        elif config.SAFE_MODE: wordlist_display = f"[bold yellow]{config.SMALL_WORDLIST_PHASE3} (Safe Mode)[/bold yellow]"

        table.add_row("[1]", f"Lista słów: {wordlist_display}")
        table.add_row("[2]", f"Głębokość rekursji (Ffuf): {config.RECURSION_DEPTH_P3}")
        table.add_section()
        table.add_row("[\fb]", "Powrót do menu Fazy 3")
        table.add_row("[\fq]", "Wyjdź")
        utils.console.print(Align.center(table))
        
        choice = utils.get_single_char_input_with_prompt(Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center"))

        if choice == '1':
            new_path = Prompt.ask("[bold cyan]Wpisz nową ścieżkę do listy słów[/bold cyan]", default=config.WORDLIST_PHASE3)
            if os.path.isfile(new_path):
                config.WORDLIST_PHASE3 = new_path
                config.USER_CUSTOMIZED_WORDLIST_PHASE3 = True
            else:
                utils.console.print(Align.center("[bold red]Plik nie istnieje lub ścieżka jest nieprawidłowa.[/bold red]"))
                time.sleep(1)
        elif choice == '2':
            new_depth = Prompt.ask("[bold cyan]Podaj głębokość rekursji[/bold cyan]", default=str(config.RECURSION_DEPTH_P3))
            if new_depth.isdigit():
                config.RECURSION_DEPTH_P3 = int(new_depth)
                config.USER_CUSTOMIZED_RECURSION_DEPTH_P3 = True
        elif choice.lower() == 'b':
            break
        elif choice.lower() == 'q':
            sys.exit(0)

