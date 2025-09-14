#!/usr/bin/env python3

import sys
import os
import subprocess
import json
import random
import time
import re
from typing import List, Dict, Optional, Tuple, Set, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import shutil
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
# ZMIANA: Ulepszone regexy do przechwytywania statusu, rozmiaru i URL
DIRSEARCH_RESULT_PATTERN = re.compile(
    r'\[\d{2}:\d{2}:\d{2}\]\s+'
    r'(\d{3})\s+'
    r'-\s*(\S+)\s*-\s+'
    r'(https?://\S+)'
    r'(?:\s*->\s*(https?://\S+))?'
)
FEROXBUSTER_RESULT_PATTERN = re.compile(r'^\s*(\d{3})\s+.*?(\S+c)\s+(https?://\S+)')
GENERIC_URL_PATTERN = re.compile(r'(https?://[^\s/$.?#].[^\s]*)')


# --- Nagłówki do rotacji w Safe Mode ---
ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "application/json, text/plain, */*",
    "*/*"
]
ACCEPT_LANGUAGE_HEADERS = [
    "en-US,en;q=0.9", "en-GB,en;q=0.8", "de-DE,de;q=0.9,en-US;q=0.8", "pl-PL,pl;q=0.9,en-US;q=0.8",
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

# ZMIANA: Nowa funkcja do parsowania rozmiaru
def _parse_size_to_bytes(size_str: str) -> int:
    """Konwertuje string z rozmiarem (np. 1.2K, 100B, 2M) na bajty."""
    size_str = size_str.upper().strip()
    if not size_str: return 0
    
    units = {"B": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    unit = "B"
    if size_str[-1] in units:
        unit = size_str[-1]
        size_str = size_str[:-1]

    try:
        size = float(size_str)
        return int(size * units[unit])
    except ValueError:
        return 0

# ZMIANA: Parser zwraca teraz słownik z pełnymi danymi, a nie tylko URL
def _parse_tool_output_line(line: str, tool_name: str, base_url: str) -> Optional[Dict[str, Any]]:
    """Parsuje pojedynczą linię z outputu narzędzia, zwracając słownik z danymi."""
    cleaned_line = ansi_escape_pattern.sub('', line).strip()
    if not cleaned_line or ":: Progress:" in cleaned_line or "Target: " in cleaned_line:
        return None

    result: Dict[str, Any] = {'source': tool_name}
    
    if tool_name == "Feroxbuster":
        match = FEROXBUSTER_RESULT_PATTERN.match(cleaned_line)
        if match:
            result['status_code'] = int(match.group(1))
            result['content_length'] = _parse_size_to_bytes(match.group(2))
            result['url'] = match.group(3)
    elif tool_name == "Dirsearch":
        match = DIRSEARCH_RESULT_PATTERN.match(cleaned_line)
        if match:
            result['status_code'] = int(match.group(1))
            result['content_length'] = _parse_size_to_bytes(match.group(2))
            result['url'] = match.group(4) or match.group(3) # Bierz URL po przekierowaniu, jeśli istnieje
    elif tool_name in ["Ffuf", "Gobuster"]:
        # Te narzędzia w trybie domyślnym dają tylko ścieżkę
        path = cleaned_line.split()[0]
        if not path.startswith("http"):
            result['url'] = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        else:
            result['url'] = path
    
    # Generyczne dopasowanie jako fallback, jeśli nic innego nie zadziałało
    if 'url' not in result:
        generic_match = GENERIC_URL_PATTERN.search(cleaned_line)
        if generic_match:
            result['url'] = generic_match.group(1)

    if 'url' in result:
        result['url'] = result['url'].rstrip('/')
        if result['url'] != base_url:
            protocol, rest = result['url'].split("://", 1)
            result['url'] = f"{protocol}://{rest.replace('//', '/')}"
            return result

    return None

# ZMIANA: _run_and_stream_tool operuje teraz na słownikach
def _run_and_stream_tool(tool_name: str, command: List[str], base_url: str, all_urls_set: Set[str], per_tool_list: List[Dict[str, Any]], console_obj: Console, timeout: int):
    """Uruchamia narzędzie i przetwarza jego output w czasie rzeczywistym."""
    cmd_str = ' '.join(command)
    console_obj.print(f"[bold cyan]Uruchamiam: {tool_name}:[/bold cyan] [dim white]{cmd_str}[/dim white]")
    
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding='utf-8', errors='ignore'
        )

        for line in iter(process.stdout.readline, ''):
            if not line: break
            parsed_result = _parse_tool_output_line(line, tool_name, base_url)
            if parsed_result:
                url = parsed_result['url']
                if url not in all_urls_set:
                    all_urls_set.add(url)
                    per_tool_list.append(parsed_result)
        
        process.wait(timeout=5)

        if process.returncode == 0:
            console_obj.print(f"[bold green]✅ {tool_name} zakończył skanowanie dla {base_url}.[/bold green]")
        else:
            stderr_output = process.stderr.read()
            log_and_echo(f"Narzędzie {tool_name} zakończyło pracę z błędem (kod: {process.returncode}) dla {base_url}. STDERR: {stderr_output[:200]}...", "WARN", console_obj=console_obj)
            
    except subprocess.TimeoutExpired:
        process.kill()
        log_and_echo(f"Komenda '{tool_name}' przekroczyła limit czasu ({timeout}s) dla {base_url}.", "WARN", console_obj=console_obj)
    except Exception as e:
        log_and_echo(f"Ogólny błąd wykonania komendy '{tool_name}' dla {base_url}: {e}", "ERROR", console_obj=console_obj)


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
    """
    Orkiestruje wyszukiwanie katalogów i generuje dane w formacie pseudo-httpx.
    Zwraca krotkę: (surowe_wyniki_narzędzi_jako_url, dane_json_do_raportu_jako_string)
    """
    global LOG_FILE, USER_AGENTS_FILE
    LOG_FILE, USER_AGENTS_FILE = log_file, user_agents_file

    wordlist_to_use = small_wordlist_path if safe_mode else wordlist_path
    
    shuffled_wordlist_path = None
    if safe_mode:
        log_and_echo("Tryb Bezpieczny: tasuję listę słów...", "INFO", console_obj=console_obj)
        shuffled_wordlist_path = shuffle_wordlist(wordlist_to_use, report_dir)
        if shuffled_wordlist_path:
            wordlist_to_use = shuffled_wordlist_path

    log_and_echo(f"Używam listy słów: {wordlist_to_use}", "INFO", console_obj=console_obj)

    # ZMIANA: per_tool_results przechowuje teraz listę słowników
    all_unique_urls: Set[str] = set()
    per_tool_results: Dict[str, List[Dict[str, Any]]] = {"ffuf": [], "feroxbuster": [], "dirsearch": [], "gobuster": []}

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
    
    gobuster_base_cmd = ["gobuster", "dir", "-w", wordlist_to_use, "-k", "-t", str(threads), "-s", status_codes_to_match, "-x", extensions, "--timeout", f"{tool_timeout}s", "--retry", "--retry-attempts", "5", "--no-error"]
    if recursion_depth > 0:
        gobuster_base_cmd.append("-r")
        
    tool_configs = [
        {"name": "Ffuf", "enabled": selected_tools_config[0], "base_cmd": ["ffuf", "-mc", status_codes_to_match, "-fc", "404", "-t", str(threads), "-w", wordlist_to_use]},
        {"name": "Feroxbuster", "enabled": selected_tools_config[1], "base_cmd": ["feroxbuster", "--wordlist", wordlist_to_use, "-s", status_codes_to_match, "--threads", str(threads), "--no-recursion", "--json"]},
        {"name": "Dirsearch", "enabled": selected_tools_config[2], "base_cmd": ["dirsearch", "--status-codes", status_codes_to_match, "-w", wordlist_to_use, "-e", extensions, "--full-url", "--force-extensions"]},
        {"name": "Gobuster", "enabled": selected_tools_config[3], "base_cmd": gobuster_base_cmd}
    ]

    # ... reszta konfiguracji narzędzi (rekurencja, safe mode) bez zmian ...

    final_custom_header = custom_header or (get_random_user_agent_header(user_agents_file, console_obj) if safe_mode else "")

    with ThreadPoolExecutor(max_workers=len(urls) * 4) as executor:
        futures = []
        for url in urls:
            for config in tool_configs:
                if config["enabled"]:
                    tool_name = config["name"]
                    cmd = list(config["base_cmd"])
                    if tool_name == "Ffuf": cmd.extend(["-u", f"{url}/FUZZ"])
                    else: cmd.extend(["-u", url])
                    if final_custom_header and not (tool_name == "Gobuster" and safe_mode):
                         cmd.extend(["-H", f"User-Agent: {final_custom_header}"])
                    if safe_mode and "extra_headers" in safe_mode_params:
                        for header in safe_mode_params["extra_headers"]:
                            if not header.lower().startswith("user-agent:"):
                                cmd.extend(["-H", header])
                    futures.append(executor.submit(
                        _run_and_stream_tool, tool_name, cmd, url, all_unique_urls, 
                        per_tool_results[tool_name.lower()], console_obj, tool_timeout
                    ))
        
        for future in as_completed(futures):
            try: future.result()
            except Exception as e: log_and_echo(f"Błąd w wątku wykonawczym: {e}", "ERROR")
            if progress_obj and main_task_id is not None:
                progress_obj.update(main_task_id, advance=1)

    if shuffled_wordlist_path and os.path.exists(shuffled_wordlist_path):
        try: os.remove(shuffled_wordlist_path)
        except OSError: pass

    # ZMIANA: Nowa sekcja do agregacji i generowania pseudo-httpx
    log_and_echo("Agreguję wyniki i generuję dane dla raportu...", "INFO", console_obj=console_obj)
    
    # Tworzymy `final_results` z listami URL-i dla kompatybilności z raportem
    final_results_urls: Dict[str, List[str]] = {}
    all_structured_results: List[Dict[str, Any]] = []

    for tool_name, results_list in per_tool_results.items():
        all_structured_results.extend(results_list)
        final_results_urls[tool_name] = safe_sort_unique([res['url'] for res in results_list])

    # Tworzymy listę wszystkich unikalnych URL-i
    final_results_urls["all_dirsearch_results"] = sorted(list(all_unique_urls))
    
    # Generujemy string w formacie JSONL, który imituje wyjście `httpx -json`
    pseudo_httpx_output_lines = []
    for item in all_structured_results:
        # Upewniamy się, że kluczowe pola istnieją, nawet jeśli są puste
        line_dict = {
            "url": item.get('url'),
            "status_code": item.get('status_code'),
            "content_length": item.get('content_length'),
            "title": "",  # Tych danych nie mamy bez httpx, ale raport ich oczekuje
            "webserver": ""
        }
        pseudo_httpx_output_lines.append(json.dumps(line_dict))
    
    pseudo_httpx_output_string = "\n".join(pseudo_httpx_output_lines)
    
    # Zapisujemy "fałszywe" wyniki httpx do pliku w celach diagnostycznych
    with open(os.path.join(report_dir, "pseudo_httpx_results_phase2.txt"), 'w') as f:
        f.write(pseudo_httpx_output_string)

    log_and_echo("Ukończono fazę 2 - wyszukiwanie katalogów.", "INFO", console_obj=console_obj)

    return final_results_urls, pseudo_httpx_output_string
