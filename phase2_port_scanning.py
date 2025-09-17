#!/usr/bin/env python3

import sys
import os
import subprocess
import re
import time
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

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

def _run_scan_tool(
    tool_name: str,
    command: List[str],
    target: str,
    output_file: str,
    timeout: int
) -> Optional[str]:
    """
    Uruchamia narzędzie do skanowania portów i zapisuje jego wynik do pliku.
    """
    sudo_prefix = []
    if tool_name == "Naabu" and os.geteuid() != 0:
        sudo_prefix = ["sudo"]

    full_command = sudo_prefix + command
    cmd_str = ' '.join(f'"{p}"' if ' ' in p else p for p in full_command)
    utils.console.print(f"[bold cyan]Uruchamiam: {tool_name} dla {target}:[/bold cyan] [dim white]{cmd_str}[/dim white]")

    try:
        process = subprocess.run(
            full_command,
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
            utils.console.print(f"[bold green]✅ {tool_name} zakończył skanowanie dla {target}.[/bold green]")
        else:
            utils.log_and_echo(f"Narzędzie {tool_name} dla {target} zakończyło pracę z błędem (kod: {process.returncode}). STDERR: {process.stderr[:250].strip()}...", "WARN")
        
        return output_file

    except subprocess.TimeoutExpired:
        msg = f"Komenda '{tool_name}' dla {target} przekroczyła limit czasu ({timeout}s)."
        utils.log_and_echo(msg, "WARN")
    except Exception as e:
        msg = f"Ogólny błąd wykonania komendy '{tool_name}' dla {target}: {e}"
        utils.log_and_echo(msg, "ERROR")
    
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
                if len(parts) == 2:
                    host, port_str = parts[0], parts[1]
                    if port_str.isdigit():
                        port = int(port_str)
                        if host not in ports_by_host:
                            ports_by_host[host] = []
                        ports_by_host[host].append(port)
    
    for host in ports_by_host:
        ports_by_host[host] = sorted(list(set(ports_by_host[host])))
        
    return ports_by_host

def _parse_nmap_output_fallback(nmap_files: Dict[str, str]) -> Dict[str, List[int]]:
    """Zlicza porty z plików Nmap jako fallback, jeśli Naabu zawiedzie."""
    ports_by_host: Dict[str, List[int]] = {}
    port_pattern = re.compile(r'^(\d+)\/tcp\s+open')
    for host, file_path in nmap_files.items():
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                host_ports = []
                for line in f:
                    match = port_pattern.match(line)
                    if match:
                        host_ports.append(int(match.group(1)))
                if host_ports:
                    ports_by_host[host] = sorted(list(set(host_ports)))
    return ports_by_host

def start_port_scan(
    targets: List[str],
    progress_obj: Optional[Progress],
    main_task_id: Optional[TaskID]
) -> Dict[str, any]:
    """
    Rozpoczyna Fazę 2: Skanowanie portów na podanych celach.
    """
    final_results = {
        "nmap_files": {},
        "naabu_file": None,
        "open_ports_by_host": {}
    }
    open_ports_by_host: Dict[str, List[int]] = {}

    naabu_enabled = config.selected_phase2_tools[1] == 1
    nmap_enabled = config.selected_phase2_tools[0] == 1

    # --- Krok 1: Uruchom Naabu, jeśli jest włączone ---
    if naabu_enabled:
        if config.SAFE_MODE:
            utils.log_and_echo("Tryb Bezpieczny: aktywuję wolniejsze skanowanie portów.", "INFO")
            if not config.USER_CUSTOMIZED_NAABU_SOURCE_PORT:
                config.NAABU_SOURCE_PORT = "53"

        naabu_base_cmd = ["naabu", "-silent", "-p", "-","-verify"]
        if config.NAABU_SOURCE_PORT:
            naabu_base_cmd.extend(["-source-ip", f"0.0.0.0:{config.NAABU_SOURCE_PORT}"])
        if config.SAFE_MODE:
            naabu_base_cmd.extend(["-rate", "100","-timeout", "500"])
        else:
            naabu_base_cmd.extend(["-rate", "1000","-timeout", "500"])

        with ThreadPoolExecutor(max_workers=config.THREADS) as executor:
            futures = []
            for target in targets:
                output_file = os.path.join(config.REPORT_DIR, f"naabu_{target.replace('.', '_')}.txt")
                cmd = naabu_base_cmd + ["-host", target]
                futures.append(executor.submit(_run_scan_tool, "Naabu", cmd, target, output_file, config.TOOL_TIMEOUT_SECONDS))
            
            for future in as_completed(futures):
                future.result()

        naabu_raw_file = os.path.join(config.REPORT_DIR, "naabu_aggregated_results.txt")
        with open(naabu_raw_file, 'w', encoding='utf-8') as agg_f:
            for target in targets:
                naabu_file = os.path.join(config.REPORT_DIR, f"naabu_{target.replace('.', '_')}.txt")
                if os.path.exists(naabu_file):
                    with open(naabu_file, 'r', encoding='utf-8') as f:
                        agg_f.write(f.read())
        
        if os.path.exists(naabu_raw_file) and os.path.getsize(naabu_raw_file) > 0:
            final_results["naabu_file"] = naabu_raw_file
            open_ports_by_host = _parse_naabu_output(naabu_raw_file)

    # --- Krok 2: Uruchom Nmap, jeśli jest włączony ---
    if nmap_enabled:
        nmap_base_cmd = ["nmap", "-sV", "-Pn"]
        if config.NMAP_AGGRESSIVE_SCAN: nmap_base_cmd.append("-A")
        elif config.NMAP_USE_SCRIPTS: nmap_base_cmd.append("-sC")
        
        if config.SAFE_MODE: nmap_base_cmd.extend(["-T2"])
        else: nmap_base_cmd.extend(["-T4"])

        with ThreadPoolExecutor(max_workers=config.THREADS) as executor:
            futures = []
            for target in targets:
                cmd = list(nmap_base_cmd)
                ports_to_scan = open_ports_by_host.get(target)
                
                # Jeśli Naabu znalazło porty, skanuj tylko je
                if ports_to_scan:
                    cmd.append("-p")
                    cmd.append(",".join(map(str, ports_to_scan)))
                # Jeśli Naabu nie było uruchomione lub nic nie znalazło, Nmap skanuje domyślnie
                
                output_file = os.path.join(config.REPORT_DIR, f"nmap_{target.replace('.', '_')}.txt")
                cmd.extend(["-oN", output_file, target])
                futures.append(executor.submit(_run_scan_tool, "Nmap", cmd, target, output_file, config.TOOL_TIMEOUT_SECONDS))
            
            for future in as_completed(futures):
                nmap_output_file = future.result()
                if nmap_output_file:
                    # Wyciągnij target z nazwy pliku, aby poprawnie go zmapować
                    filename = os.path.basename(nmap_output_file)
                    target_name_part = filename.replace("nmap_", "").replace(".txt", "").replace("_", ".")
                    # Proste dopasowanie, może wymagać ulepszenia
                    for t in targets:
                        if t in target_name_part:
                            final_results["nmap_files"][t] = nmap_output_file
                            break

    # --- Krok 3: Finalizacja wyników ---
    if open_ports_by_host:
        final_results["open_ports_by_host"] = open_ports_by_host
    else:
        # Fallback, jeśli Naabu nie dało wyników, a Nmap tak
        final_results["open_ports_by_host"] = _parse_nmap_output_fallback(final_results["nmap_files"])

    utils.log_and_echo("Ukończono fazę 2 - skanowanie portów.", "INFO")
    return final_results

def display_phase2_tool_selection_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(Align.center(Panel.fit("[bold magenta]Faza 2: Skanowanie Portów[/bold magenta]")))
        utils.console.print(Align.center(f"Obecny cel: [bold green]{config.ORIGINAL_TARGET}[/bold green]"))
        utils.console.print(Align.center(f"Tryb bezpieczny: {'[bold green]WŁĄCZONY[/bold green]' if config.SAFE_MODE else '[bold red]WYŁĄCZONY'}"))
        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        table.add_column("Key", style="bold blue", justify="center", min_width=5)
        table.add_column("Description", style="white", justify="left")
        tool_names = ["Nmap (szczegóły)", "Naabu (szybkie odkrywanie)"]
        for i, tool_name in enumerate(tool_names):
            status_char = "[bold green]✓[/bold green]" if config.selected_phase2_tools[i] == 1 else "[bold red]✗[/bold red]"
            table.add_row(f"[{i+1}]", f"{status_char} {tool_name}")
        table.add_section()
        table.add_row("[\fs]", "[bold magenta]Zmień ustawienia Fazy 2[/bold magenta]")
        table.add_row("[\fb]", "Powrót do menu głównego")
        table.add_row("[\fq]", "Wyjdź")
        utils.console.print(Align.center(table))
        utils.console.print(Align.center("[bold cyan]Rekomendacja: Włącz oba narzędzia dla najlepszej wydajności.[/bold cyan]"))
        choice = utils.get_single_char_input_with_prompt(Text.from_markup("[bold cyan]Wybierz opcję i naciśnij Enter, aby rozpocząć[/bold cyan]", justify="center"))
        
        if choice.isdigit() and 1 <= int(choice) <= 2:
            config.selected_phase2_tools[int(choice) - 1] = 1 - config.selected_phase2_tools[int(choice) - 1]
        elif choice.lower() == 's':
            display_phase2_settings_menu(display_banner_func)
        elif choice.lower() == 'q':
            sys.exit(0)
        elif choice.lower() == 'b':
            return False
        elif choice == '\r':
            if any(config.selected_phase2_tools): return True
            else: utils.console.print(Align.center("[bold yellow]Proszę wybrać co najmniej jedno narzędzie.[/bold yellow]"))
        else:
            utils.console.print(Align.center("[bold yellow]Nieprawidłowa opcja.[/bold yellow]"))
        time.sleep(0.1)

def display_phase2_settings_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 2[/bold cyan]")))
        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        table.add_column("Key", style="bold blue", justify="center", min_width=5)
        table.add_column("Description", style="white", justify="left")
        
        threads_display = f"[bold yellow]{config.THREADS}[/bold yellow]"
        if config.USER_CUSTOMIZED_THREADS: threads_display = f"[bold green]{config.THREADS} (Użytkownika)[/bold green]"
        timeout_display = f"[bold yellow]{config.TOOL_TIMEOUT_SECONDS}[/bold yellow]s"
        if config.USER_CUSTOMIZED_TIMEOUT: timeout_display = f"[bold green]{config.TOOL_TIMEOUT_SECONDS}s (Użytkownika)[/bold green]"

        naabu_port_display = "[dim]Domyślny[/dim]"
        if config.NAABU_SOURCE_PORT:
            style = "bold green" if config.USER_CUSTOMIZED_NAABU_SOURCE_PORT else "bold yellow"
            naabu_port_display = f"[{style}]{config.NAABU_SOURCE_PORT}[/{style}]"
            if config.SAFE_MODE and not config.USER_CUSTOMIZED_NAABU_SOURCE_PORT:
                 naabu_port_display += " (Safe Mode)"

        table.add_row("[1]", f"[{'[bold green]✓[/bold green]' if config.SAFE_MODE else '[bold red]✗[/bold red]'}] Tryb bezpieczny (wolniejsze skanowanie)")
        table.add_row("[2]", f"Liczba wątków: {threads_display}")
        table.add_row("[3]", f"Limit czasu narzędzia: {timeout_display}")
        table.add_section()
        table.add_row("[bold]Nmap[/bold]", "")
        table.add_row("[4]", f"[{'[bold green]✓[/bold green]' if config.NMAP_USE_SCRIPTS else '[bold red]✗[/bold red]'}] Skanowanie skryptów (-sC)")
        table.add_row("[5]", f"[{'[bold green]✓[/bold green]' if config.NMAP_AGGRESSIVE_SCAN else '[bold red]✗[/bold red]'}] Skan agresywny (-A)")
        table.add_section()
        table.add_row("[bold]Naabu[/bold]", "")
        table.add_row("[6]", f"Port źródłowy (--source-ip): {naabu_port_display}")
        table.add_section()
        table.add_row("[\fb]", "Powrót do menu Fazy 2")
        table.add_row("[\fq]", "Wyjdź")
        utils.console.print(Align.center(table))
    
        choice = utils.get_single_char_input_with_prompt(Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center"))

        if choice == '1':
            config.SAFE_MODE = not config.SAFE_MODE
        elif choice == '2':
            new_threads_str = Prompt.ask("[bold cyan]Wpisz nową liczbę wątków[/bold cyan]", default=str(config.THREADS))
            if new_threads_str.isdigit() and int(new_threads_str) > 0: config.THREADS, config.USER_CUSTOMIZED_THREADS = int(new_threads_str), True
            else: utils.console.print(Align.center("[bold red]Nieprawidłowa liczba wątków.[/bold red]"))
        elif choice == '3':
            new_timeout_str = Prompt.ask("[bold cyan]Wpisz nowy limit czasu w sekundach[/bold cyan]", default=str(config.TOOL_TIMEOUT_SECONDS))
            if new_timeout_str.isdigit() and int(new_timeout_str) > 0: config.TOOL_TIMEOUT_SECONDS, config.USER_CUSTOMIZED_TIMEOUT = int(new_timeout_str), True
            else: utils.console.print(Align.center("[bold red]Nieprawidłowy limit czasu.[/bold red]"))
        elif choice == '4':
            config.NMAP_USE_SCRIPTS = not config.NMAP_USE_SCRIPTS
            if config.NMAP_USE_SCRIPTS: config.NMAP_AGGRESSIVE_SCAN = False
        elif choice == '5':
            config.NMAP_AGGRESSIVE_SCAN = not config.NMAP_AGGRESSIVE_SCAN
            if config.NMAP_AGGRESSIVE_SCAN: config.NMAP_USE_SCRIPTS = False
        elif choice == '6':
            new_port_str = Prompt.ask("[bold cyan]Podaj port źródłowy dla Naabu (puste=domyślny)[/bold cyan]", default=config.NAABU_SOURCE_PORT or "")
            if new_port_str.isdigit() and 1 <= int(new_port_str) <= 65535:
                config.NAABU_SOURCE_PORT = new_port_str
                config.USER_CUSTOMIZED_NAABU_SOURCE_PORT = True
            elif not new_port_str:
                config.NAABU_SOURCE_PORT = None
                config.USER_CUSTOMIZED_NAABU_SOURCE_PORT = False
            else:
                utils.console.print(Align.center("[bold red]Nieprawidłowy numer portu.[/bold red]"))
        elif choice.lower() == 'b':
            break
        elif choice.lower() == 'q':
            sys.exit(0)
        else:
            utils.console.print(Align.center("[bold yellow]Nieprawidłowa opcja.[/bold yellow]"))
        time.sleep(0.1)

