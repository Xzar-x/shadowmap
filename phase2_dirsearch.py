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
import shutil
import argparse
import tempfile

# --- Surowe logowanie do stderr przed inicjalizacją rich ---
def raw_log_error(message: str):
    print(f"RAW_ERROR (phase2_dirsearch.py): {message}", file=sys.stderr)

try:
    from rich.console import Console
    from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn, TimeElapsedColumn, TaskProgressColumn, TaskID
    from rich.align import Align
    from rich.spinner import Spinner
    console = Console(stderr=True)
    RICH_AVAILABLE = True
    
    def log_and_echo(message: str, level: str = "INFO", console_obj: Console = console, progress_obj: Optional[Progress] = None):
        if LOG_FILE:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {level.upper()} - {message}\n")
        
        console_target = progress_obj.console if progress_obj and progress_obj.live.is_started else console_obj
        
        if level == "ERROR":
            console_target.print(f"[bold red]BŁĄD W FAZIE 2: {message}[/bold red]")
        elif level == "WARN":
            console_target.print(f"[bold yellow]OSTRZEŻENIE W FAZIE 2: {message}[/bold yellow]")
        elif level == "INFO" or level == "DEBUG":
            console_target.print(f"[bold blue]{message}[/bold blue]")

except ImportError:
    RICH_AVAILABLE = False
    console = None
    def log_and_echo(message: str, level: str = "INFO", console_obj: Console = None, progress_obj: Optional[Progress] = None):
        if LOG_FILE:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {level.upper()} - {message}\n")
        if level == "ERROR":
            print(f"BŁĄD W FAZIE 2: {message}", file=sys.stderr)
        elif level == "WARN":
            print(f"OSTRZEŻENIE W FAZIE 2: {message}", file=sys.stderr)
        else:
            print(f"INFO (phase2_dirsearch.py): {message}", file=sys.stderr)

# --- Globalne zmienne ---
LOG_FILE: Optional[str] = None
USER_AGENTS_FILE: Optional[str] = None

# --- Wyrażenia regularne ---
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


# --- Nagłówki do rotacji w Safe Mode ---
ACCEPT_HEADERS = [
    "text/html",
    "application/json",
    "text/plain",
    "*/*"
]
ACCEPT_LANGUAGE_HEADERS = [
    "en-US", "en-GB", "de", "pl",
]
REFERER_HEADERS = [
    "https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/", ""
]

def get_random_browser_headers() -> List[str]:
    """Generuje listę losowych nagłówków przypominających przeglądarkę w celu ominięcia WAF."""
    headers = []
    headers.append(f"Accept: {random.choice(ACCEPT_HEADERS)}")
    headers.append(f"Accept-Language: {random.choice(ACCEPT_LANGUAGE_HEADERS)}")
    headers.append(f"Referer: {random.choice(REFERER_HEADERS)}")
    headers.append("Upgrade-Insecure-Requests: 1")
    headers.append("DNT: 1")
    headers.append("Cache-Control: max-age=0")
    dummy_session_id = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))
    headers.append(f"Cookie: sessionid={dummy_session_id}")
    return headers

def shuffle_wordlist(input_path: str, report_dir: str) -> Optional[str]:
    """Tasuje listę słów i zapisuje ją do pliku tymczasowego w katalogu raportu."""
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            lines = [line for line in f if line.strip()]
        
        random.shuffle(lines)
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, dir=report_dir, prefix='shuffled_wordlist_', suffix='.txt')
        temp_file.writelines(lines)
        temp_file.close()
        
        return temp_file.name
    except Exception as e:
        raw_log_error(f"Nie udało się potasować listy słów '{input_path}': {e}")
        return None

def get_random_user_agent_header(user_agents_file: Optional[str] = None, console_obj: Optional[Console] = None) -> str:
    """Odczytuje losowy User-Agent z pliku."""
    if user_agents_file is None:
        user_agents_file = USER_AGENTS_FILE
    
    if user_agents_file and os.path.exists(user_agents_file):
        try:
            with open(user_agents_file, 'r', encoding='utf-8') as f:
                user_agents = [line.strip() for line in f if line.strip()]
            if user_agents:
                return random.choice(user_agents)
        except Exception as e:
            msg = f"Błąd odczytu pliku User-Agenta '{user_agents_file}': {e}. Używam domyślnego."
            if console_obj: console_obj.print(Align.center(f"[bold yellow]OSTRZEŻENIE: {msg}[/bold yellow]"))
            else: raw_log_error(msg)
    else:
        msg = f"Plik User-Agenta '{user_agents_file}' nie znaleziony. Używam domyślnego."
        if console_obj: console_obj.print(Align.center(f"[bold yellow]OSTRZEŻENIE: {msg}[/bold yellow]"))
        else: raw_log_error(msg)
            
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"

def _parse_tool_output_line(line: str, tool_name: str, base_url: str) -> Optional[str]:
    """Parsuje pojedynczą linię z outputu narzędzia w celu znalezienia URL."""
    cleaned_line = ansi_escape_pattern.sub('', line).strip()
    if not cleaned_line or ":: Progress:" in cleaned_line or "Target: " in cleaned_line:
        return None

    full_url = None
    
    if tool_name == "Feroxbuster":
        try:
            data = json.loads(cleaned_line)
            if data.get("type") == "response":
                full_url = data.get("url")
        except json.JSONDecodeError:
            match = re.match(r'^\s*(\d{3})\s+\S+\s+\S+l\s+\S+w\s+\S+c\s+(https?:\/\/\S+)$', cleaned_line)
            if match: full_url = match.group(2)
    elif tool_name == "Dirsearch":
        match = DIRSEARCH_RESULT_PATTERN.match(cleaned_line)
        if match: full_url = match.group(3) or match.group(2)
    elif tool_name in ["Ffuf", "Gobuster"]:
        path = cleaned_line.split()[0]
        if not path.startswith("http"):
            full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        else:
            full_url = path
    
    if not full_url:
        generic_match = GENERIC_URL_PATTERN.search(cleaned_line)
        if generic_match:
            full_url = generic_match.group(1)

    if full_url:
        full_url = full_url.rstrip('/')
        if full_url != base_url:
            protocol, rest = full_url.split("://", 1)
            return f"{protocol}://{rest.replace('//', '/')}"

    return None

def _run_and_stream_tool(tool_name: str, command: List[str], base_url: str, all_urls_set: Set[str], per_tool_list: List[str], console_obj: Console, timeout: int):
    """Uruchamia narzędzie i przetwarza jego output w czasie rzeczywistym."""
    cmd_str = ' '.join(f'"{p}"' if ' ' in p else p for p in command)
    console_obj.print(f"[bold cyan]Uruchamiam: {tool_name}:[/bold cyan] [dim white]{cmd_str}[/dim white]")
    
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

        if process.returncode == 0:
            console_obj.print(f"[bold green]✅ {tool_name} zakończył skanowanie dla {base_url}.[/bold green]")
        else:
            log_and_echo(f"Narzędzie {tool_name} zakończyło pracę z błędem (kod: {process.returncode}) dla {base_url}. STDERR: {stderr[:250].strip()}...", "WARN", console_obj=console_obj)
            
    except subprocess.TimeoutExpired:
        process.kill()
        msg = f"Komenda '{tool_name}' przekroczyła limit czasu ({timeout}s) dla {base_url}."
        log_and_echo(msg, "WARN", console_obj=console_obj)
    except Exception as e:
        msg = f"Ogólny błąd wykonania komendy '{tool_name}' dla {base_url}: {e}"
        log_and_echo(msg, "ERROR", console_obj=console_obj)


def safe_sort_unique(input_lines: List[str]) -> List[str]:
    """Sortuje i usuwa duplikaty z listy linii."""
    return sorted(list(set(line.strip() for line in input_lines if line.strip())))


def start_dir_search(
    urls: List[str],
    report_dir: str,
    safe_mode: bool,
    custom_header: str,
    wordlist_path: str,
    small_wordlist_path: str,
    threads: int,
    tool_timeout: int,
    log_file: Optional[str],
    user_agents_file: Optional[str],
    selected_tools_config: List[int],
    recursion_depth: int,
    console_obj: Console,
    progress_obj: Optional[Progress],
    main_task_id: Optional[TaskID]
) -> Tuple[Dict[str, List[str]], str]:
    global LOG_FILE, USER_AGENTS_FILE
    LOG_FILE, USER_AGENTS_FILE = log_file, user_agents_file

    wordlist_to_use = small_wordlist_path if safe_mode and os.path.exists(small_wordlist_path) else wordlist_path
    
    shuffled_wordlist_path = None
    if safe_mode:
        log_and_echo("Tryb Bezpieczny: tasuję listę słów...", "INFO", console_obj=console_obj)
        shuffled_wordlist_path = shuffle_wordlist(wordlist_to_use, report_dir)
        if shuffled_wordlist_path:
            wordlist_to_use = shuffled_wordlist_path

    log_and_echo(f"Używam listy słów: {wordlist_to_use}", "INFO", console_obj=console_obj)

    all_unique_urls: Set[str] = set()
    per_tool_results: Dict[str, List[str]] = {"ffuf": [], "feroxbuster": [], "dirsearch": [], "gobuster": []}

    safe_mode_params = {}
    if safe_mode:
        log_and_echo("Tryb Bezpieczny: aktywuję techniki omijania WAF.", "INFO", console_obj=console_obj)
        safe_mode_params = {
            "ffuf_rate": "50", "gobuster_delay": "500ms", "dirsearch_delay": "0.1",
            "ferox_rate_limit": "10", "http_method": random.choice(["GET", "HEAD"]),
            "extra_headers": get_random_browser_headers()
        }
        threads = 10
    
    status_codes_to_match = "200,204,301,302,307,401,403,405"
    extensions = "php,html,js,aspx,jsp,json"
    
    # ZMIANA: Dodano flagę "-f" (--follow-redirect), aby gobuster podążał za przekierowaniami.
    # ROZWIĄZUJE TO PROBLEM: "the server returns a status code that matches the provided options for non existing urls"
    # w przypadku globalnych przekierowań HTTP na HTTPS.
    gobuster_base_cmd = ["gobuster", "dir", "-f", "-w", wordlist_to_use, "-k", "-t", str(threads), "-s", status_codes_to_match, "-b", "", "-x", extensions, "--timeout", f"{tool_timeout}s", "--retry", "--retry-attempts", "5", "--no-error"]

    tool_configs = [
        {"name": "Ffuf", "enabled": selected_tools_config[0], "base_cmd": ["ffuf", "-mc", status_codes_to_match, "-fc", "404", "-t", str(threads), "-w", wordlist_to_use]},
        {"name": "Feroxbuster", "enabled": selected_tools_config[1], "base_cmd": ["feroxbuster", "--wordlist", wordlist_to_use, "-s", status_codes_to_match, "--threads", str(threads), "--no-recursion", "--json", "--silent"]},
        {"name": "Dirsearch", "enabled": selected_tools_config[2], "base_cmd": ["dirsearch", "-i", status_codes_to_match, "-w", wordlist_to_use, "-e", extensions, "--full-url", "--force-extensions"]},
        {"name": "Gobuster", "enabled": selected_tools_config[3], "base_cmd": gobuster_base_cmd}
    ]

    if recursion_depth > 0:
        for config in tool_configs:
            if config["name"] == "Ffuf": config["base_cmd"].extend(["-recursion", "-recursion-depth", str(recursion_depth)])
            elif config["name"] == "Feroxbuster":
                if "--no-recursion" in config["base_cmd"]: config["base_cmd"].remove("--no-recursion")
                config["base_cmd"].extend(["--depth", str(recursion_depth)])
            elif config["name"] == "Dirsearch": config["base_cmd"].extend(["--recursive", f"--max-recursion-depth={recursion_depth}"])
    
    final_user_agent = custom_header or (get_random_user_agent_header(user_agents_file, console_obj) if safe_mode else "")

    with ThreadPoolExecutor(max_workers=len(urls) * 4) as executor:
        futures = []
        for url in urls:
            for config in tool_configs:
                if config["enabled"]:
                    tool_name = config["name"]
                    cmd = list(config["base_cmd"])
                    
                    if tool_name == "Ffuf": cmd.extend(["-u", f"{url}/FUZZ"])
                    else: cmd.extend(["-u", url])
                    
                    headers_to_add = []
                    if final_user_agent:
                        headers_to_add.append(f"User-Agent: {final_user_agent}")
                    
                    if safe_mode and "extra_headers" in safe_mode_params:
                        headers_to_add.extend(safe_mode_params["extra_headers"])

                    for header in headers_to_add:
                        if tool_name == "Gobuster":
                            if header.lower().startswith("user-agent:"):
                                if "--random-agent" not in cmd:
                                    cmd.extend(["--useragent", header.split(":", 1)[1].strip()])
                            else:
                                cmd.extend(["-H", header])
                        else:
                            cmd.extend(["-H", header])
                    
                    futures.append(executor.submit(
                        _run_and_stream_tool, tool_name, cmd, url, all_unique_urls, 
                        per_tool_results[tool_name.lower()], console_obj, tool_timeout
                    ))
        
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                log_and_echo(f"Błąd w wątku wykonawczym: {e}", "ERROR")
            if progress_obj and main_task_id is not None:
                progress_obj.update(main_task_id, advance=1)

    if shuffled_wordlist_path and os.path.exists(shuffled_wordlist_path):
        try: os.remove(shuffled_wordlist_path)
        except OSError: pass

    final_results = {}
    for tool_name, results_list in per_tool_results.items():
        final_results[tool_name] = safe_sort_unique(results_list)
    final_results["all_dirsearch_results"] = sorted(list(all_unique_urls))
    
    log_and_echo("Ukończono fazę 2 - wyszukiwanie katalogów (zbieranie surowych danych).", "INFO", console_obj=console_obj)
    
    verified_httpx_output = ""
    if all_unique_urls:
        task_desc = f"[bold green]Weryfikuję {len(all_unique_urls)} unikalnych ścieżek (HTTPX)...[/bold green]"
        verification_task = progress_obj.add_task(task_desc, total=1) if progress_obj else None
        
        urls_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=report_dir, suffix='.txt') as tmp:
                tmp.write('\n'.join(sorted(list(all_unique_urls))))
                urls_file = tmp.name
            
            httpx_cmd = ["httpx", "-l", urls_file, "-silent", "-json"]
            process = subprocess.run(
                httpx_cmd, capture_output=True, text=True, timeout=tool_timeout * 2,
                encoding='utf-8', errors='ignore'
            )
            verified_httpx_output = process.stdout
            with open(os.path.join(report_dir, "httpx_results_phase2_verified.txt"), 'w') as f:
                f.write(verified_httpx_output)

        except Exception as e:
            log_and_echo(f"Błąd podczas weryfikacji HTTPX w Fazie 2: {e}", "ERROR", console_obj=console_obj)
        finally:
            if urls_file and os.path.exists(urls_file): os.remove(urls_file)
            if progress_obj and verification_task is not None:
                progress_obj.update(verification_task, completed=1)
        
        log_and_echo(f"Weryfikacja HTTPX zakończona.", "INFO", console_obj=console_obj)

    return final_results, verified_httpx_output
