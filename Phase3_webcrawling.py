#!/usr/bin/env python3

import sys
import os
import subprocess
import re
import time
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
import json
import random

# --- Importowanie współdzielonych funkcji ---
try:
    from rich.console import Console
    from rich.progress import Progress, TaskID
    from rich.align import Align
    
    from phase2_dirsearch import (
        log_and_echo as shared_log_and_echo,
        get_random_user_agent_header,
        safe_sort_unique,
        ansi_escape_pattern
    )
    RICH_AVAILABLE = True
except ImportError:
    # Proste funkcje zastępcze, jeśli rich nie jest dostępny
    RICH_AVAILABLE = False
    def shared_log_and_echo(message, level="INFO", **kwargs):
        print(f"[{level}] {message}", file=sys.stderr)
    def get_random_user_agent_header(**kwargs):
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    def safe_sort_unique(lines):
        return sorted(list(set(l.strip() for l in lines if l.strip())))
    ansi_escape_pattern = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# --- Globalne zmienne dla tego modułu ---
LOG_FILE: Optional[str] = None
USER_AGENTS_FILE: Optional[str] = None

def _execute_crawl_command(tool_name: str, command_parts: List[str], target_desc: str, output_file: str, timeout: int, progress_obj: Optional[Progress]):
    cmd_str = ' '.join(command_parts)
    if progress_obj:
        progress_obj.console.print(f"[bold cyan]Faza 3 - Uruchamiam {tool_name} dla {target_desc}:[/bold cyan] [dim white]{cmd_str}[/dim white]")
    
    try:
        process = subprocess.run(
            command_parts,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, text=True, check=False, encoding='utf-8', errors='ignore'
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(process.stdout)
            if process.stderr:
                f.write("\n--- STDERR ---\n")
                f.write(process.stderr)
        
        if process.returncode == 0:
            if progress_obj: progress_obj.console.print(f"[bold green]✅ {tool_name} zakończył pracę dla {target_desc}.[/bold green]")
            return output_file
        else:
            shared_log_and_echo(f"{tool_name} zakończył z błędem (kod: {process.returncode}) dla {target_desc}.", "WARN", progress_obj=progress_obj)
            return output_file
            
    except subprocess.TimeoutExpired:
        msg = f"Narzędzie '{tool_name}' przekroczyło limit czasu ({timeout}s) dla {target_desc}."
        shared_log_and_echo(msg, "WARN", progress_obj=progress_obj)
        return None
    except Exception as e:
        msg = f"Krytyczny błąd wykonania '{tool_name}' dla {target_desc}: {e}"
        shared_log_and_echo(msg, "ERROR", progress_obj=progress_obj)
        return None

def categorize_url(url: str) -> Optional[str]:
    """Kategoryzuje URL na podstawie jego rozszerzenia lub słów kluczowych."""
    url_lower = url.lower()
    if '?' in url_lower or '=' in url_lower:
        return 'parameters'
    if re.search(r'\.js(\?.*)?$', url_lower):
        return 'js_files'
    if any(keyword in url_lower for keyword in ['/api/', 'api.']):
        return 'api_endpoints'
    if any(ext in url_lower for ext in ['.log', '.bak', '.config', '.env', '.sql', 'admin', 'dashboard', 'secret', 'token', 'backup']):
        return 'interesting_paths'
    return 'all_urls'

def start_web_crawl(
    urls: List[str],
    report_dir: str,
    safe_mode: bool,
    custom_header: str,
    threads: int,
    tool_timeout: int,
    log_file: Optional[str],
    user_agents_file: Optional[str],
    selected_tools_config: List[int],
    console_obj: Console,
    progress_obj: Optional[Progress],
    main_task_id: Optional[TaskID]
) -> Dict[str, List[str]]:
    
    global LOG_FILE, USER_AGENTS_FILE
    LOG_FILE, USER_AGENTS_FILE = log_file, user_agents_file

    all_tool_results: Dict[str, List[str]] = {
        "all_urls": [], "parameters": [], "js_files": [], "api_endpoints": [], "interesting_paths": []
    }

    tool_configs = [
        {"name": "Katana", "enabled": selected_tools_config[0], "base_cmd": ["katana", "-silent", "-jc", "-kf", "all"]},
        {"name": "Hakrawler", "enabled": selected_tools_config[1], "base_cmd": ["hakrawler", "-plain"]},
        {"name": "ParamSpider", "enabled": selected_tools_config[2], "base_cmd": ["paramspider", "--level", "high"]},
        {"name": "LinkFinder", "enabled": selected_tools_config[3], "base_cmd": ["linkfinder", "-i"]},
        {"name": "gauplus", "enabled": selected_tools_config[4], "base_cmd": ["gauplus", "-random-agent", "-subs"]}
    ]
    
    final_custom_header = custom_header or get_random_user_agent_header(user_agents_file, console_obj)
    
    # --- Etap 1: Zbieranie podstawowych URLi i plików JS ---
    collected_files = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for url in urls:
            domain = re.sub(r'https?://', '', url).split('/')[0]
            
            # Konfiguracja narzędzi działających na URL/domenie
            for config in tool_configs:
                if not config["enabled"] or config["name"] == "LinkFinder":
                    continue
                
                tool_name = config["name"]
                cmd = list(config["base_cmd"])
                target_desc = domain

                if tool_name in ["Katana"]:
                    cmd.extend(["-u", url])
                    if safe_mode: cmd.extend(["-rl", "10"])
                    if final_custom_header: cmd.extend(["-H", f"User-Agent: {final_custom_header}"])

                elif tool_name == "Hakrawler":
                    cmd = ["bash", "-c", f"echo {url} | hakrawler -plain"]

                elif tool_name == "ParamSpider":
                    cmd.extend(["-d", domain])
                    if final_custom_header: cmd.extend(["--headers", f"User-Agent: {final_custom_header}"])

                elif tool_name == "gauplus":
                    cmd.extend(["-t", "5" if safe_mode else "20"]) # Ograniczenie wątków gauplus
                    # gauplus ma wbudowany -random-agent
                    cmd.append(domain)

                output_filename = f"{tool_name.lower()}_{re.sub(r'[^a-zA-Z0-9]', '_', domain)}.txt"
                output_path = os.path.join(report_dir, output_filename)
                collected_files.append(output_path)
                
                futures.append(executor.submit(
                    _execute_crawl_command, tool_name, cmd, target_desc, output_path, tool_timeout, progress_obj
                ))

        for future in as_completed(futures):
            future.result() # Czekamy na zakończenie
            if progress_obj and main_task_id is not None:
                progress_obj.update(main_task_id, advance=1)

    # --- Etap 2: Parsowanie zebranych plików i uruchamianie LinkFindera ---
    js_files_to_scan = set()
    for file_path in collected_files:
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    cleaned_line = ansi_escape_pattern.sub('', line).strip()
                    if cleaned_line and cleaned_line.startswith('http'):
                        category = categorize_url(cleaned_line)
                        if category:
                            all_tool_results[category].append(cleaned_line)
                        if category == 'js_files':
                            js_files_to_scan.add(cleaned_line)

    # Uruchomienie LinkFindera, jeśli jest włączony i znaleziono pliki JS
    if any(t["name"] == "LinkFinder" and t["enabled"] for t in tool_configs) and js_files_to_scan:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for js_url in js_files_to_scan:
                config = next(t for t in tool_configs if t["name"] == "LinkFinder")
                cmd = list(config["base_cmd"])
                cmd.append(js_url)
                
                output_filename = f"linkfinder_{re.sub(r'[^a-zA-Z0-9]', '_', js_url)}.txt"
                output_path = os.path.join(report_dir, output_filename)
                
                futures.append(executor.submit(
                    _execute_crawl_command, "LinkFinder", cmd, js_url, output_path, tool_timeout, progress_obj
                ))

            for future in as_completed(futures):
                result_file = future.result()
                if result_file and os.path.exists(result_file):
                    with open(result_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            cleaned_line = ansi_escape_pattern.sub('', line).strip()
                            if cleaned_line and cleaned_line.startswith('/'):
                                # Linkfinder często zwraca ścieżki relatywne
                                # Można by próbować je składać z domeną, ale dla uproszczenia dodajemy jako 'interesting_paths'
                                all_tool_results['interesting_paths'].append(cleaned_line)
                if progress_obj and main_task_id is not None:
                    progress_obj.update(main_task_id, advance=1)
    
    # --- Finalizacja ---
    for category in all_tool_results:
        all_tool_results[category] = safe_sort_unique(all_tool_results[category])
        
    all_unique_urls = set(all_tool_results['all_urls'])
    for category, urls in all_tool_results.items():
        if category != 'all_urls':
            # Dodajemy tylko pełne URLe, ignorujemy ścieżki relatywne
            all_unique_urls.update(u for u in urls if u.startswith('http'))
    all_tool_results['all_urls'] = sorted(list(all_unique_urls))

    shared_log_and_echo("Ukończono fazę 3 - Web Crawling.", "INFO", console_obj=console_obj)
    return all_tool_results
