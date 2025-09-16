#!/usr/bin/env python3

import sys
import os
import subprocess
import json
import random
import time
import re
from typing import List, Dict, Optional, Tuple, Set
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

def _parse_tool_output_line(line: str, tool_name: str, base_url: Optional[str] = None) -> Optional[str]:
    cleaned_line = ansi_escape_pattern.sub('', line).strip()
    if not cleaned_line or ":: Progress:" in cleaned_line or "Target: " in cleaned_line:
        return None

    full_url = None

    if tool_name == "Feroxbuster":
        match = re.match(r'^\s*(\d{3})\s+\S+\s+\S+l\s+\S+w\s+\S+c\s+(https?:\/\/\S+)', cleaned_line)
        if match: full_url = match.group(2)
    elif tool_name == "Dirsearch":
        match = DIRSEARCH_RESULT_PATTERN.match(cleaned_line)
        if match: full_url = match.group(3) or match.group(2)
    elif tool_name in ["Ffuf", "Gobuster"]:
        path = cleaned_line.split()[0]
        if not path.startswith("http") and base_url:
            full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        else:
            full_url = path

    if not full_url:
        generic_match = GENERIC_URL_PATTERN.search(cleaned_line)
        if generic_match: full_url = generic_match.group(1)

    if full_url:
        full_url = full_url.rstrip('/')
        protocol, rest = full_url.split("://", 1)
        return f"{protocol}://{rest.replace('//', '/')}"

    return None

def _run_and_stream_tool(tool_name: str, command: List[str], base_url: Optional[str], all_urls_set: Set[str], per_tool_list: List[str], timeout: int):
    cmd_str = ' '.join(f'"{p}"' if ' ' in p else p for p in command)
    utils.console.print(f"[bold cyan]Uruchamiam: {tool_name}:[/bold cyan] [dim white]{cmd_str}[/dim white]")
    process = None
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )

        for line in iter(process.stdout.readline, ''):
            if not line: break
            parsed_url = _parse_tool_output_line(line, tool_name, base_url)
            if parsed_url:
                all_urls_set.add(parsed_url)
                per_tool_list.append(parsed_url)

        stdout, stderr = process.communicate(timeout=15)
        if stdout:
             for line in stdout.splitlines():
                parsed_url = _parse_tool_output_line(line, tool_name, base_url)
                if parsed_url:
                    all_urls_set.add(parsed_url)
                    per_tool_list.append(parsed_url)

        desc = f"dla {base_url}" if base_url else ""
        if process.returncode == 0 or (tool_name == "Dirsearch" and "DeprecationWarning" in stderr) or (tool_name == "Gobuster" and "the server returns a status code that matches" in stderr):
            utils.console.print(f"[bold green]✅ {tool_name} zakończył skanowanie {desc}.[/bold green]")
        else:
            utils.log_and_echo(f"Narzędzie {tool_name} zakończyło pracę z błędem (kod: {process.returncode}) {desc}. STDERR: {stderr[:250].strip()}...", "WARN")

    except subprocess.TimeoutExpired:
        if process and process.poll() is None:
            process.kill()
        utils.log_and_echo(f"Komenda '{tool_name}' przekroczyła limit czasu ({timeout}s) {desc}.", "WARN")
    except Exception as e:
        utils.log_and_echo(f"Ogólny błąd wykonania komendy '{tool_name}' {desc}: {e}", "ERROR")

def start_dir_search(
    urls: List[str],
    progress_obj: Optional[Progress],
    main_task_id: Optional[TaskID]
) -> Tuple[Dict[str, List[str]], str]:
    
    wordlist_to_use = config.WORDLIST_PHASE3
    if config.SAFE_MODE and not config.USER_CUSTOMIZED_WORDLIST_PHASE3:
        wordlist_to_use = config.SMALL_WORDLIST_PHASE3

    shuffled_wordlist_path = None
    if config.SAFE_MODE:
        utils.log_and_echo("Tryb Bezpieczny: tasuję listę słów...", "INFO")
        shuffled_wordlist_path = utils.shuffle_wordlist(wordlist_to_use, config.REPORT_DIR)
        if shuffled_wordlist_path:
            wordlist_to_use = shuffled_wordlist_path
            config.TEMP_FILES_TO_CLEAN.append(shuffled_wordlist_path)

    utils.log_and_echo(f"Używam listy słów: {wordlist_to_use}", "INFO")
    if config.PROXY:
        utils.log_and_echo(f"Używam proxy: {config.PROXY}", "INFO")

    all_unique_urls: Set[str] = set()
    per_tool_results: Dict[str, List[str]] = {"ffuf": [], "feroxbuster": [], "dirsearch": [], "gobuster": []}

    threads_to_use = 10 if config.SAFE_MODE else config.THREADS
    status_codes_to_match = "200,204,301,302,307,401,403,405"
    extensions = "php,html,js,aspx,jsp,json"

    tool_configs = [
        {"name": "Ffuf", "enabled": config.selected_phase3_tools[0], "base_cmd": ["ffuf", "-mc", status_codes_to_match, "-fc", "404", "-t", str(threads_to_use), "-w", wordlist_to_use]},
        {"name": "Feroxbuster", "enabled": config.selected_phase3_tools[1], "base_cmd": ["feroxbuster", "--wordlist", wordlist_to_use, "-s", status_codes_to_match, "--threads", str(threads_to_use), "--no-recursion"]},
        {"name": "Dirsearch", "enabled": config.selected_phase3_tools[2], "base_cmd": ["dirsearch", "-i", status_codes_to_match, "-w", wordlist_to_use, "-e", extensions, "--full-url", "--force-extensions", "--no-color"]},
        {"name": "Gobuster", "enabled": config.selected_phase3_tools[3], "base_cmd": ["gobuster", "dir", "-f", "-w", wordlist_to_use, "-k", "-t", str(threads_to_use), "-s", status_codes_to_match, "-b", "", "-x", extensions, "--timeout", f"{config.TOOL_TIMEOUT_SECONDS}s", "--retry", "--retry-attempts", "5", "--no-error"]}
    ]
    
    # ... (logika dodawania proxy i rekurencji bez zmian, ale używając `config.`)
    if config.PROXY:
        for cfg in tool_configs:
            tool_name = cfg["name"]
            if tool_name == "Ffuf": cfg["base_cmd"].extend(["-x", config.PROXY])
            elif tool_name == "Feroxbuster": cfg["base_cmd"].extend(["-p", config.PROXY])
            elif tool_name == "Dirsearch": cfg["base_cmd"].extend([f"--proxy={config.PROXY}"])
            elif tool_name == "Gobuster": cfg["base_cmd"].extend(["--proxy", config.PROXY])

    if config.RECURSION_DEPTH_P3 > 0:
        for cfg in tool_configs:
            if cfg["name"] == "Ffuf": cfg["base_cmd"].extend(["-recursion", "-recursion-depth", str(config.RECURSION_DEPTH_P3)])
            elif cfg["name"] == "Feroxbuster":
                if "--no-recursion" in cfg["base_cmd"]: cfg["base_cmd"].remove("--no-recursion")
                cfg["base_cmd"].extend(["--depth", str(config.RECURSION_DEPTH_P3)])
            elif cfg["name"] == "Dirsearch": cfg["base_cmd"].extend(["--recursive", f"--max-recursion-depth={config.RECURSION_DEPTH_P3}"])

    final_user_agent = config.CUSTOM_HEADER or (utils.get_random_user_agent_header() if config.SAFE_MODE else "")

    with ThreadPoolExecutor(max_workers=threads_to_use) as executor:
        futures = []
        for url in urls:
            for cfg in tool_configs:
                if cfg["enabled"]:
                    cmd = list(cfg["base_cmd"])
                    if cfg["name"] == "Ffuf": cmd.extend(["-u", f"{url}/FUZZ"])
                    else: cmd.extend(["-u", url])
                    
                    headers_to_add = []
                    if final_user_agent: headers_to_add.append(f"User-Agent: {final_user_agent}")
                    if config.SAFE_MODE: headers_to_add.extend(utils.get_random_browser_headers())

                    for header in headers_to_add:
                        is_ua = header.lower().startswith("user-agent:")
                        ua_val = header.split(":", 1)[1].strip()
                        if cfg["name"] == "Gobuster" and is_ua: cmd.extend(["-a", ua_val])
                        elif cfg["name"] == "Dirsearch" and is_ua: cmd.extend(["--user-agent", ua_val])
                        else: cmd.extend(["-H", header])
                    
                    if config.SAFE_MODE:
                        if cfg["name"] == "Ffuf": cmd.extend(["-rate", "50"])
                        elif cfg["name"] == "Gobuster": cmd.extend(["-d", "500ms"])
                        elif cfg["name"] == "Dirsearch": cmd.extend(["--delay", "0.1"])
                        elif cfg["name"] == "Feroxbuster": cmd.extend(["--rate-limit", "10"])

                    futures.append(executor.submit(_run_and_stream_tool, cfg["name"], cmd, url, all_unique_urls, per_tool_results[cfg["name"].lower()], config.TOOL_TIMEOUT_SECONDS))

        for future in as_completed(futures):
            try: future.result()
            except Exception as e: utils.log_and_echo(f"Błąd w wątku wykonawczym: {e}", "ERROR")
            if progress_obj and main_task_id is not None:
                progress_obj.update(main_task_id, advance=1)

    final_results = {}
    for tool_name, results_list in per_tool_results.items():
        final_results[tool_name] = sorted(list(set(r for r in results_list if r)))
    final_results["all_dirsearch_results"] = sorted(list(all_unique_urls))

    utils.log_and_echo("Ukończono fazę 3 - wyszukiwanie katalogów.", "INFO")

    verified_httpx_output = ""
    if all_unique_urls:
        task_desc = f"[bold green]Weryfikuję {len(all_unique_urls)} unikalnych ścieżek (HTTPX)...[/bold green]"
        verification_task = progress_obj.add_task(task_desc, total=1) if progress_obj else None

        with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=config.REPORT_DIR, suffix='.txt') as tmp:
            tmp.write('\n'.join(sorted(list(all_unique_urls))))
            urls_file = tmp.name
        config.TEMP_FILES_TO_CLEAN.append(urls_file)
        
        try:
            httpx_cmd = ["httpx", "-l", urls_file, "-silent", "-json"]
            if config.PROXY: httpx_cmd.extend(["-proxy", config.PROXY])
                
            process = subprocess.run(httpx_cmd, capture_output=True, text=True, timeout=config.TOOL_TIMEOUT_SECONDS * 2, encoding='utf-8', errors='ignore')
            verified_httpx_output = process.stdout
            with open(os.path.join(config.REPORT_DIR, "httpx_results_phase3_verified.txt"), 'w') as f:
                f.write(verified_httpx_output)

        except Exception as e:
            utils.log_and_echo(f"Błąd podczas weryfikacji HTTPX w Fazie 3: {e}", "ERROR")
        finally:
            if progress_obj and verification_task is not None:
                progress_obj.update(verification_task, completed=1)

    return final_results, verified_httpx_output

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
        tool_names = ["FFuf", "Feroxbuster", "Dirsearch", "Gobuster"]
        for i, tool_name in enumerate(tool_names):
            status_char = "[bold green]✓[/bold green]" if config.selected_phase3_tools[i] == 1 else "[bold red]✗[/bold red]"
            table.add_row(f"[{i+1}]", f"{status_char} {tool_name}")
        table.add_section()
        table.add_row("[s]", "[bold magenta]Zmień ustawienia Fazy 3[/bold magenta]")
        table.add_row("[b]", "Powrót do menu głównego")
        table.add_row("[q]", "Wyjdź")
        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(Text.from_markup("[bold cyan]Wybierz opcję i naciśnij Enter, aby rozpocząć[/bold cyan]", justify="center"))
        
        if choice.isdigit() and 1 <= int(choice) <= 4: config.selected_phase3_tools[int(choice) - 1] = 1 - config.selected_phase3_tools[int(choice) - 1]
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
        
        user_agent_display = f"[dim white]'{config.CUSTOM_HEADER}'[/dim white]"
        if config.USER_CUSTOMIZED_USER_AGENT and config.CUSTOM_HEADER: user_agent_display = f"[bold green]'{config.CUSTOM_HEADER}' (Użytkownika)[/bold green]"
        elif config.SAFE_MODE and not config.USER_CUSTOMIZED_USER_AGENT: user_agent_display = f"[bold yellow]Losowy + Dodatkowe (Safe Mode)[/bold yellow]"
        elif not config.CUSTOM_HEADER: user_agent_display = f"[dim white]Domyślny[/dim white]"
        
        proxy_display = "[dim]Brak[/dim]"
        if config.PROXY: proxy_display = f"[bold green]{config.PROXY}[/bold green]"

        table.add_row("[1]", f"[{'[bold green]✓[/bold green]' if config.SAFE_MODE else '[bold red]✗[/bold red]'}] Tryb bezpieczny")
        table.add_row("[2]", f"Lista słów (Faza 3): {wordlist_display}")
        table.add_row("[3]", f"User-Agent: {user_agent_display}")
        table.add_row("[4]", f"Proxy: {proxy_display}")
        table.add_row("[5]", f"Liczba wątków: {config.THREADS}")
        table.add_row("[6]", f"Limit czasu narzędzia: {config.TOOL_TIMEOUT_SECONDS}s")
        table.add_row("[7]", f"Głębokość rekurencji: {config.RECURSION_DEPTH_P3}")
        table.add_section()
        table.add_row("[b]", "Powrót do menu Fazy 3")
        table.add_row("[q]", "Wyjdź")
        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center"))

        if choice == '1':
            config.SAFE_MODE = not config.SAFE_MODE
        elif choice == '2':
            new_path = Prompt.ask("[bold cyan]Podaj ścieżkę do listy słów[/bold cyan]", default=config.WORDLIST_PHASE3)
            if os.path.isfile(new_path): config.WORDLIST_PHASE3, config.USER_CUSTOMIZED_WORDLIST_PHASE3 = new_path, True
            else: utils.console.print("[red]Nieprawidłowa ścieżka[/red]")
        elif choice == '3':
            new_ua = Prompt.ask("[bold cyan]Podaj User-Agent[/bold cyan]", default=config.CUSTOM_HEADER)
            config.CUSTOM_HEADER, config.USER_CUSTOMIZED_USER_AGENT = new_ua, bool(new_ua)
        elif choice == '4':
            new_proxy = Prompt.ask("[bold cyan]Podaj adres proxy[/bold cyan]", default=config.PROXY or "")
            config.PROXY, config.USER_CUSTOMIZED_PROXY = new_proxy, bool(new_proxy)
        elif choice == '5':
            new_threads = Prompt.ask("[bold cyan]Podaj liczbę wątków[/bold cyan]", default=str(config.THREADS))
            if new_threads.isdigit(): config.THREADS, config.USER_CUSTOMIZED_THREADS = int(new_threads), True
        elif choice == '6':
            new_timeout = Prompt.ask("[bold cyan]Podaj limit czasu (s)[/bold cyan]", default=str(config.TOOL_TIMEOUT_SECONDS))
            if new_timeout.isdigit(): config.TOOL_TIMEOUT_SECONDS, config.USER_CUSTOMIZED_TIMEOUT = int(new_timeout), True
        elif choice == '7':
            new_depth = Prompt.ask("[bold cyan]Podaj głębokość rekurencji[/bold cyan]", default=str(config.RECURSION_DEPTH_P3))
            if new_depth.isdigit(): config.RECURSION_DEPTH_P3, config.USER_CUSTOMIZED_RECURSION_DEPTH_P3 = int(new_depth), True
        elif choice.lower() == 'b': break
        elif choice.lower() == 'q': sys.exit(0)
