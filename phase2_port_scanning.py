#!/usr/bin/env python3

import sys
import os
import subprocess
import re
import time
from typing import List, Dict, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile

# --- Import shared functions ---
try:
    from rich.console import Console
    from rich.progress import Progress, TaskID

    # Załóżmy, że współdzielone funkcje będą w module 'utils' lub bezpośrednio w 'shadowmap'
    # Na razie, dla spójności, importujemy z przyszłego 'phase3_dirsearch'
    # W finalnej wersji może to wymagać refaktoryzacji do wspólnego modułu.
    from phase3_dirsearch import (
        log_and_echo as shared_log_and_echo,
        safe_sort_unique
    )
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    # Proste funkcje zastępcze, jeśli 'rich' lub inne moduły nie są dostępne
    def shared_log_and_echo(message, level="INFO", **kwargs):
        log_level = "ERROR" if "BŁĄD" in message else "WARN" if "OSTRZEŻENIE" in message else "INFO"
        print(f"[{log_level}] (phase2_port_scanning.py): {message}", file=sys.stderr)

    def safe_sort_unique(lines: List[str]) -> List[str]:
        return sorted(list(set(line.strip() for line in lines if line.strip())))


# --- Global variables for this module ---
LOG_FILE: Optional[str] = None

def _run_scan_tool(
    tool_name: str,
    command: List[str],
    target: str,
    output_file: str,
    timeout: int,
    console_obj: Console,
    progress_obj: Optional[Progress] = None
) -> Optional[str]:
    """
    Uruchamia narzędzie do skanowania portów i zapisuje jego wynik do pliku.

    Args:
        tool_name: Nazwa narzędzia (np. "Nmap").
        command: Lista argumentów polecenia.
        target: Cel skanowania (do logowania).
        output_file: Ścieżka do pliku wyjściowego.
        timeout: Limit czasu wykonania polecenia w sekundach.
        console_obj: Obiekt konsoli Rich do logowania.
        progress_obj: Obiekt paska postępu Rich (opcjonalny).

    Returns:
        Ścieżka do pliku wyjściowego w przypadku sukcesu, w przeciwnym razie None.
    """
    cmd_str = ' '.join(f'"{p}"' if ' ' in p else p for p in command)
    console_obj.print(f"[bold cyan]Uruchamiam: {tool_name} dla {target}:[/bold cyan] [dim white]{cmd_str}[/dim white]")

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            encoding='utf-8',
            errors='ignore'
        )

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(process.stdout)
            if process.stderr:
                f.write(f"\n--- STDERR ---\n{process.stderr}")

        if process.returncode == 0:
            console_obj.print(f"[bold green]✅ {tool_name} zakończył skanowanie dla {target}.[/bold green]")
        else:
            shared_log_and_echo(f"Narzędzie {tool_name} dla {target} zakończyło pracę z błędem (kod: {process.returncode}). STDERR: {process.stderr[:250].strip()}...", "WARN", console_obj=console_obj)
        
        return output_file

    except subprocess.TimeoutExpired:
        msg = f"Komenda '{tool_name}' dla {target} przekroczyła limit czasu ({timeout}s)."
        shared_log_and_echo(msg, "WARN", console_obj=console_obj)
    except Exception as e:
        msg = f"Ogólny błąd wykonania komendy '{tool_name}' dla {target}: {e}"
        shared_log_and_echo(msg, "ERROR", console_obj=console_obj)
    
    return None

def _parse_naabu_output(file_path: str) -> Dict[str, List[int]]:
    """Paruje wyjście z Naabu i grupuje porty według hosta."""
    ports_by_host: Dict[str, List[int]] = {}
    if not os.path.exists(file_path):
        return ports_by_host
        
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if ':' in line:
                parts = line.split(':')
                host, port_str = parts[0], parts[1]
                if port_str.isdigit():
                    port = int(port_str)
                    if host not in ports_by_host:
                        ports_by_host[host] = []
                    ports_by_host[host].append(port)
    
    for host in ports_by_host:
        ports_by_host[host] = sorted(list(set(ports_by_host[host])))
        
    return ports_by_host

def start_port_scan(
    targets: List[str],
    report_dir: str,
    safe_mode: bool,
    threads: int,
    tool_timeout: int,
    log_file: Optional[str],
    selected_tools_config: List[int],
    console_obj: Console,
    progress_obj: Optional[Progress],
    main_task_id: Optional[TaskID]
) -> Dict[str, any]:
    """
    Rozpoczyna Fazę 2: Skanowanie portów na podanych celach.

    Args:
        targets: Lista hostów (domen lub IP) do przeskanowania.
        report_dir: Katalog do zapisywania raportów i plików tymczasowych.
        safe_mode: Czy włączyć tryb bezpieczny (wolniejsze, bardziej ostrożne skanowanie).
        threads: Maksymalna liczba współbieżnych skanowań.
        tool_timeout: Limit czasu dla pojedynczego narzędzia w sekundach.
        log_file: Ścieżka do pliku logów.
        selected_tools_config: Lista flag (0 lub 1) włączająca narzędzia [Nmap, Naabu].
        console_obj: Obiekt konsoli Rich.
        progress_obj: Obiekt paska postępu Rich.
        main_task_id: ID głównego zadania w pasku postępu.

    Returns:
        Słownik zawierający wyniki skanowania.
    """
    global LOG_FILE
    LOG_FILE = log_file

    if safe_mode:
        shared_log_and_echo("Tryb Bezpieczny: aktywuję wolniejsze skanowanie portów.", "INFO", console_obj=console_obj)

    tool_configs = [
        {"name": "Nmap", "enabled": selected_tools_config[0], "base_cmd": ["nmap", "-sV", "-Pn"]},
        {"name": "Naabu", "enabled": selected_tools_config[1], "base_cmd": ["naabu", "-silent", "-p", "-"]}
    ]

    # Modyfikacje dla Safe Mode
    if safe_mode:
        # Nmap: zmiana timingu na T2 (wolniejszy)
        tool_configs[0]["base_cmd"].extend(["-T2"]) 
        # Naabu: ograniczenie liczby pakietów na sekundę
        tool_configs[1]["base_cmd"].extend(["-rate", "100"])
    else:
        # Nmap: agresywniejszy timing T4
        tool_configs[0]["base_cmd"].extend(["-T4"])
        # Naabu: wyższy rate limit
        tool_configs[1]["base_cmd"].extend(["-rate", "1000"])

    final_results = {
        "nmap_files": {},
        "naabu_file": None,
        "open_ports_by_host": {}
    }

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for target in targets:
            for config in tool_configs:
                if not config["enabled"]:
                    continue
                
                tool_name = config["name"]
                cmd = list(config["base_cmd"])
                
                output_filename = f"{tool_name.lower()}_{target.replace('.', '_')}.txt"
                output_file = os.path.join(report_dir, output_filename)

                if tool_name == "Nmap":
                    cmd.extend(["-oN", output_file, target])
                    # Nmap sam zapisuje plik, więc podajemy mu ścieżkę jako argument
                    # a nie tylko do naszej funkcji
                    cmd_to_run = cmd
                elif tool_name == "Naabu":
                    cmd.extend(["-host", target])
                    cmd_to_run = cmd

                futures.append(executor.submit(
                    _run_scan_tool, tool_name, cmd_to_run, target, output_file, tool_timeout, console_obj
                ))

        for future in as_completed(futures):
            try:
                result_file = future.result()
            except Exception as e:
                shared_log_and_echo(f"Błąd w wątku wykonawczym Fazy 2: {e}", "ERROR")
            if progress_obj and main_task_id is not None:
                progress_obj.update(main_task_id, advance=1)

    # Zbieranie i parsowanie wyników po zakończeniu wszystkich skanowań
    naabu_raw_file = os.path.join(report_dir, "naabu_aggregated_results.txt")
    
    with open(naabu_raw_file, 'w', encoding='utf-8') as agg_f:
        for target in targets:
            naabu_file = os.path.join(report_dir, f"naabu_{target.replace('.', '_')}.txt")
            if os.path.exists(naabu_file):
                with open(naabu_file, 'r', encoding='utf-8') as f:
                    agg_f.write(f.read())
    
    if os.path.exists(naabu_raw_file):
        final_results["naabu_file"] = naabu_raw_file
        final_results["open_ports_by_host"] = _parse_naabu_output(naabu_raw_file)

    for target in targets:
        nmap_file = os.path.join(report_dir, f"nmap_{target.replace('.', '_')}.txt")
        if os.path.exists(nmap_file):
            final_results["nmap_files"][target] = nmap_file

    shared_log_and_echo("Ukończono fazę 2 - skanowanie portów.", "INFO", console_obj=console_obj)

    return final_results