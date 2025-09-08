#!/usr/bin/env python3

import sys
import os
import subprocess
import json
import random
import time
import re
from typing import List, Dict, Optional
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
    """Generates a list of random, browser-like headers for WAF evasion."""
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
        raw_log_error(f"Failed to shuffle wordlist '{input_path}': {e}")
        return None

def get_random_user_agent_header(user_agents_file: Optional[str] = None, console_obj: Optional[Console] = None) -> str:
    """Reads a random User-Agent from a file."""
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


def _execute_tool_command(tool_name: str, command_parts: List[str], target_url: str, output_file: str, timeout: int, progress_obj: Progress):
    """
    Executes a single tool command and saves its output to a file.
    """
    cmd_str = ' '.join(command_parts)
    progress_obj.console.print(f"[bold cyan]Uruchamiam: {tool_name}:[/bold cyan] [dim white]{cmd_str}[/dim white]")
    
    try:
        process = subprocess.run(
            command_parts,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            check=False
        )
        
        combined_output = process.stdout
        if process.stderr:
            combined_output += "\n" + process.stderr

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(combined_output)

        if process.returncode == 0:
            progress_obj.console.print(f"[bold green]✅ {tool_name} zakończył skanowanie dla {target_url}.[/bold green]")
            return output_file
        else:
            log_and_echo(f"Błąd wykonania {tool_name} (kod: {process.returncode}) dla {target_url}.", "ERROR", progress_obj=progress_obj)
            if process.stderr:
                log_and_echo(f"STDERR (narzędzie) {tool_name} dla {target_url}: {process.stderr}", "ERROR", progress_obj=progress_obj)
            progress_obj.console.print(f"[bold red]❌ Błąd wykonania {tool_name} (kod: {process.returncode}) dla {target_url}. Sprawdź logi.[/bold red]")
            return None
    except subprocess.TimeoutExpired:
        msg = f"Komenda '{tool_name}' przekroczyła limit czasu ({timeout}s) dla {target_url}."
        log_and_echo(msg, "WARN", progress_obj=progress_obj)
        progress_obj.console.print(f"[bold yellow]⚠️ OSTRZEŻENIE: {msg}[/bold yellow]")
        return None
    except FileNotFoundError:
        msg = f"Narzędzie '{command_parts[0]}' nie zostało znalezione (sprawdź PATH)."
        log_and_echo(msg, "ERROR", progress_obj=progress_obj)
        progress_obj.console.print(f"[bold red]❌ BŁĄD: {msg}[/bold red]")
        return None
    except Exception as e:
        msg = f"Ogólny błąd wykonania komendy '{tool_name}' dla {target_url}: {e}"
        log_and_echo(msg, "ERROR", progress_obj=progress_obj)
        progress_obj.console.print(f"[bold red]❌ BŁĄD: {msg}[/bold red]")
        return None


def safe_sort_unique(input_lines: List[str]) -> List[str]:
    """Sorts and deduplicates a list of lines."""
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
) -> Dict[str, List[str]]:
    """
    Orchestrates directory searching using selected tools.
    """
    global LOG_FILE, USER_AGENTS_FILE
    LOG_FILE, USER_AGENTS_FILE = log_file, user_agents_file

    wordlist_to_use = small_wordlist_path if safe_mode else wordlist_path
    
    shuffled_wordlist_path = None
    if safe_mode:
        log_and_echo("Tryb Bezpieczny: tasuję listę słów...", "INFO", console_obj=console_obj, progress_obj=progress_obj)
        shuffled_wordlist_path = shuffle_wordlist(wordlist_to_use, report_dir)
        if shuffled_wordlist_path:
            wordlist_to_use = shuffled_wordlist_path
        else:
            log_and_echo(f"Nie udało się stasować listy słów, używam oryginalnej: {wordlist_to_use}", "WARN", console_obj=console_obj, progress_obj=progress_obj)

    log_and_echo(f"Używam listy słów: {wordlist_to_use}", "INFO", console_obj=console_obj, progress_obj=progress_obj)

    all_tool_results: Dict[str, List[str]] = {
        "ffuf": [], "feroxbuster": [], "dirsearch": [], "gobuster": [], "all_dirsearch_results": []
    }
    
    safe_mode_params = {}
    if safe_mode:
        log_and_echo("Tryb Bezpieczny: aktywuję techniki omijania WAF.", "INFO", console_obj=console_obj, progress_obj=progress_obj)
        safe_mode_params = {
            "ffuf_rate": "50",
            "gobuster_delay": "500ms",
            "dirsearch_delay": "0.1",
            "ferox_rate_limit": "10", 
            "http_method": random.choice(["GET", "HEAD"]),
            "extra_headers": get_random_browser_headers()
        }
        threads = 10 
    
    gobuster_base_cmd = ["gobuster", "dir", "-w", wordlist_to_use, "-k", "-t", str(threads), "-b", "404", "-q", "--timeout", f"{tool_timeout}s", "--retry", "--retry-attempts", "5", "--no-error"]
    if recursion_depth > 0:
        gobuster_base_cmd.append("-r")
        
    tool_configs = [
        {"name": "Ffuf", "enabled": selected_tools_config[0], "base_cmd": ["ffuf", "-mc", "200,204,301,302,307,403,405", "-fc", "404", "-t", str(threads), "-w", wordlist_to_use]},
        {"name": "Feroxbuster", "enabled": selected_tools_config[1], "base_cmd": ["feroxbuster", "--wordlist", wordlist_to_use, "-C", "404", "--threads", str(threads), "-q"]},
        {"name": "Dirsearch", "enabled": selected_tools_config[2], "base_cmd": ["dirsearch", "--quiet", "-w", wordlist_to_use, "-e", "php,html,js,aspx,jsp,json", "--full-url"]},
        {"name": "Gobuster", "enabled": selected_tools_config[3], "base_cmd": gobuster_base_cmd}
    ]

    # Add recursion options based on the provided depth
    if recursion_depth > 0:
        for config in tool_configs:
            if config["name"] == "Ffuf":
                config["base_cmd"].extend(["-recursion", "-recursion-depth", str(recursion_depth)])
            elif config["name"] == "Feroxbuster":
                config["base_cmd"].extend(["--depth", str(recursion_depth)])
            elif config["name"] == "Dirsearch":
                config["base_cmd"].extend(["--recursive"])
    else: # recursion_depth is 0, explicitly disable it for tools that are recursive by default
        for config in tool_configs:
            if config["name"] == "Feroxbuster":
                config["base_cmd"].append("--no-recursion")

    if safe_mode:
        for config in tool_configs:
            if config["name"] == "Ffuf": config["base_cmd"].extend(["-rate", safe_mode_params["ffuf_rate"], "-X", safe_mode_params["http_method"]])
            elif config["name"] == "Gobuster": 
                config["base_cmd"].extend(["--delay", safe_mode_params["gobuster_delay"], "-m", safe_mode_params["http_method"]])
                config["base_cmd"].append("--random-agent")
            elif config["name"] == "Dirsearch": config["base_cmd"].extend(["--delay", safe_mode_params["dirsearch_delay"], "-m", safe_mode_params["http_method"]])
            elif config["name"] == "Feroxbuster": config["base_cmd"].extend(["--rate-limit", safe_mode_params["ferox_rate_limit"], "-m", safe_mode_params["http_method"]])

    final_custom_header = custom_header
    if safe_mode and not custom_header:
        final_custom_header = get_random_user_agent_header(user_agents_file, console_obj)
    
    futures = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for url in urls:
            for tool_config in tool_configs:
                if tool_config["enabled"]:
                    tool_name = tool_config["name"]
                    cmd = list(tool_config["base_cmd"])

                    if tool_name == "Ffuf": cmd.extend(["-u", f"{url}/FUZZ"])
                    elif tool_name in ["Feroxbuster", "Gobuster", "Dirsearch"]: cmd.extend(["-u", url])
                    
                    if tool_name == "Gobuster" and safe_mode:
                        pass 
                    elif final_custom_header:
                         cmd.extend(["-H", f"User-Agent: {final_custom_header}"])

                    if safe_mode and "extra_headers" in safe_mode_params:
                        for header in safe_mode_params["extra_headers"]:
                            if not header.lower().startswith("user-agent:"):
                                header_value = header
                                if tool_name == "Gobuster" and "," in header_value:
                                    try:
                                        key, value = header_value.split(":", 1)
                                        value_without_comma = value.split(",")[0].strip()
                                        header_value = f"{key}: {value_without_comma}"
                                    except ValueError:
                                        continue
                                
                                cmd.extend(["-H", header_value])

                    output_file_name = f"{tool_name.lower()}_{re.sub(r'[^a-zA-Z0-9]', '_', url).lower()}.txt"
                    output_path = os.path.join(report_dir, output_file_name)
                    
                    future = executor.submit(_execute_tool_command, tool_name, cmd, url, output_path, tool_timeout, progress_obj)
                    futures.append({"future": future, "tool": tool_name, "url": url})

        for f_data in as_completed([f["future"] for f in futures]):
            for f_entry in futures:
                if f_entry["future"] == f_data:
                    tool_name = f_entry["tool"]
                    base_url = f_entry["url"].rstrip('/')
                    result_file = f_data.result()

                    if result_file and os.path.exists(result_file):
                        with open(result_file, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                            
                            filtered_results = []
                            for line in lines:
                                cleaned_line = ansi_escape_pattern.sub('', line).strip()
                                if not cleaned_line or ":: Progress:" in cleaned_line: continue
                                
                                full_url = None
                                
                                # Ulepszona logika parsowania
                                if tool_name == "Feroxbuster":
                                    match = re.match(r'^\s*(\d{3})\s+\S+\s+\S+l\s+\S+w\s+\S+c\s+(https?:\/\/\S+)$', cleaned_line)
                                    if match and 200 <= int(match.group(1)) < 400:
                                        full_url = match.group(2).rstrip('/')
                                elif tool_name == "Dirsearch":
                                    match = DIRSEARCH_RESULT_PATTERN.match(cleaned_line)
                                    if match and (200 <= int(match.group(1)) < 400 or int(match.group(1)) in [403, 405]):
                                        full_url = (match.group(3) or match.group(2)).rstrip('/')
                                else:
                                    match_status = re.match(r'^(.*?)\s+\[Status:\s*(\d{3}),.*', cleaned_line)
                                    if match_status:
                                        path = match_status.group(1).strip()
                                        if path and not path.startswith("http"):
                                            full_url = f"{base_url}/{path}"
                                    elif "(Status: " in cleaned_line:
                                        path = cleaned_line.split(" (Status:")[0].strip()
                                        if path and not path.startswith("http"):
                                            full_url = f"{base_url}/{path}"
                                    elif cleaned_line.startswith("http"):
                                        full_url = cleaned_line.split()[0].rstrip('/')

                                if not full_url:
                                    generic_match = re.search(r'(https?://[^\s/$.?#].[^\s]*)', cleaned_line)
                                    if generic_match:
                                        if not "Progress" in cleaned_line and not "Target" in cleaned_line:
                                            full_url = generic_match.group(1).rstrip('/')

                                if full_url and full_url != base_url:
                                    if "://" in full_url:
                                        protocol, rest = full_url.split("://", 1)
                                        full_url = f"{protocol}://{rest.replace('//', '/')}"
                                    filtered_results.append(full_url)


                            all_tool_results[tool_name.lower()].extend(filtered_results)
                            all_tool_results["all_dirsearch_results"].extend(filtered_results)
                    
                    if progress_obj and main_task_id is not None:
                        progress_obj.update(main_task_id, advance=1)
                    break 

    if shuffled_wordlist_path and os.path.exists(shuffled_wordlist_path):
        try: os.remove(shuffled_wordlist_path)
        except OSError: pass

    for tool_name in all_tool_results:
        all_tool_results[tool_name] = safe_sort_unique(all_tool_results[tool_name])

    log_and_echo("Ukończono fazę 2 - wyszukiwanie katalogów.", "INFO", console_obj=console_obj)
    
    return all_tool_results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 2 - Directory Searching Script")
    parser.add_argument("--urls", nargs='+', required=True, help="List of target URLs")
    parser.add_argument("--report-dir", required=True, help="Directory to save reports")
    # ... reszta argumentów
    args = parser.parse_args()
    local_console = Console(stderr=True)
    results = start_dir_search(
        urls=args.urls,
        report_dir=args.report_dir,
        safe_mode=args.safe_mode,
        custom_header=args.custom_header,
        wordlist_path=args.wordlist_path,
        small_wordlist_path=args.small_wordlist_path,
        threads=args.threads,
        tool_timeout=args.tool_timeout,
        log_file=args.log_file,
        user_agents_file=args.user_agents_file,
        selected_tools_config=args.selected_tools_config,
        recursion_depth=1, # Domyślna wartość, gdy uruchamiany bezpośrednio
        console_obj=local_console,
        progress_obj=None,
        main_task_id=None
    )
    print(json.dumps(results, indent=2))

