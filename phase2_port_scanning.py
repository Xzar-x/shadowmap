#!/usr/bin/env python3

import sys
import os
import subprocess
import re
import time
import socket
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.progress import Progress, TaskID, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn
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
    Uruchamia narzędzie do skanowania portów za pomocą Popen, zarządza procesem i zapisuje wynik do pliku.
    """
    sudo_prefix = []
    if tool_name in ["Naabu", "Masscan"] and os.geteuid() != 0:
        sudo_prefix = ["sudo"]

    full_command = sudo_prefix + command
    cmd_str = ' '.join(f'"{p}"' if ' ' in p else p for p in full_command)
    utils.console.print(f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] [dim white]{cmd_str}[/dim white]")

    process = None
    try:
        process = subprocess.Popen(
            full_command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            encoding='utf-8', 
            errors='ignore'
        )
        
        with utils.processes_lock:
            utils.managed_processes.append(process)
        
        stdout, stderr = process.communicate(timeout=timeout)
        returncode = process.returncode
        
        with open(output_file, 'w', encoding='utf-8') as f:
            if tool_name == "Masscan":
                for line in stdout.splitlines():
                    if line.startswith("Discovered open port"):
                        parts = line.split()
                        port_proto = parts[3]
                        port = port_proto.split('/')[0]
                        ip = parts[5]
                        f.write(f"{ip}:{port}\n")
            else:
                f.write(stdout)
            
            if stderr:
                f.write(f"\n--- STDERR ---\n{stderr}")

        if returncode == 0:
            utils.console.print(f"[bold green]✅ {tool_name} zakończył skanowanie dla {target}.[/bold green]")
        else:
            utils.log_and_echo(f"Narzędzie {tool_name} dla {target} zakończyło pracę z błędem (kod: {returncode}).", "WARN")
        
        return output_file

    except subprocess.TimeoutExpired:
        msg = f"Komenda '{tool_name}' dla {target} przekroczyła limit czasu ({timeout}s)."
        utils.log_and_echo(msg, "WARN")
    except Exception as e:
        msg = f"Ogólny błąd wykonania komendy '{tool_name}' dla {target}: {e}"
        utils.log_and_echo(msg, "ERROR")
    finally:
        if process:
            with utils.processes_lock:
                if process in utils.managed_processes:
                    utils.managed_processes.remove(process)
    
    return None

def _parse_host_port_output(file_path: str) -> Dict[str, List[int]]:
    """Uniwersalny parser dla formatu 'host:port'."""
    ports_by_host: Dict[str, List[int]] = {}
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return ports_by_host
        
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if ':' in line:
                parts = line.split(':')
                if len(parts) == 2 and parts[1].isdigit():
                    host, port_str = parts[0], parts[1]
                    port = int(port_str)
                    ports_by_host.setdefault(host, []).append(port)
    
    for host in ports_by_host:
        ports_by_host[host] = sorted(list(set(ports_by_host[host])))
        
    return ports_by_host

def _parse_nmap_output_fallback(nmap_files: Dict[str, str]) -> Dict[str, List[int]]:
    """Zlicza porty z plików Nmap jako fallback."""
    ports_by_host: Dict[str, List[int]] = {}
    port_pattern = re.compile(r'^(\d+)\/tcp\s+open')
    for host, file_path in nmap_files.items():
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                host_ports = []
                for line in f:
                    match = port_pattern.match(line)
                    if match: host_ports.append(int(match.group(1)))
                if host_ports: ports_by_host[host] = sorted(list(set(host_ports)))
    return ports_by_host

def start_port_scan(
    targets: List[str],
    progress_obj: Optional[Progress],
    main_task_id: Optional[TaskID]
) -> Dict[str, any]:
    final_results = {"nmap_files": {}, "naabu_file": None, "masscan_file": None, "open_ports_by_host": {}}
    open_ports_by_host: Dict[str, List[int]] = {}

    nmap_enabled = config.selected_phase2_tools[0] == 1
    naabu_enabled = config.selected_phase2_tools[1] == 1
    masscan_enabled = config.selected_phase2_tools[2] == 1

    discovery_tools = []
    if naabu_enabled: discovery_tools.append("Naabu")
    if masscan_enabled: discovery_tools.append("Masscan")
    
    utils.console.print(Align.center(f"[bold green]Rozpoczynam Fazę 2 - Skanowanie Portów...[/bold green]"))

    unique_ips = set()
    with utils.console.status("[bold cyan]Rozpoznawanie nazw domen na unikalne adresy IP...[/bold cyan]"):
        for url in targets:
            hostname_match = re.search(r'https?://([^/:]+)', url)
            target_host = hostname_match.group(1) if hostname_match else url

            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target_host):
                unique_ips.add(target_host)
            else:
                try:
                    ip_address = socket.gethostbyname(target_host)
                    unique_ips.add(ip_address)
                except socket.gaierror:
                    utils.log_and_echo(f"Nie można rozwiązać domeny {target_host} na adres IP. Pomijam.", "WARN")
    
    targets_to_scan = sorted(list(unique_ips))
    utils.console.print(Align.center(f"Będę skanować [bold green]{len(targets_to_scan)}[/bold green] unikalnych adresów IP."))

    if not targets_to_scan:
        return final_results

    nmap_scan_type = config.NMAP_SOLO_SCAN_MODE
    if nmap_enabled and not discovery_tools:
        utils.console.print(Align.center(Panel(
            "[bold cyan]Nmap będzie działał samodzielnie.[/bold cyan]\n"
            "Jaki rodzaj skanowania portów chcesz przeprowadzić?",
            title="[yellow]Tryb Skanowania Nmap[/yellow]",
            border_style="yellow"
        )))
        nmap_scan_type = Prompt.ask(
            "[bold]Wybierz tryb[/bold]",
            choices=["default", "full", "fast"],
            default=config.NMAP_SOLO_SCAN_MODE
        )

    num_discovery_tools = naabu_enabled + masscan_enabled
    num_nmap_tasks = len(targets_to_scan) if nmap_enabled else 0
    total_tasks = (len(targets_to_scan) * num_discovery_tools) + num_nmap_tasks

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), MofNCompleteColumn(), "•", TimeElapsedColumn(), console=utils.console, transient=True) as progress:
        phase2_task = progress.add_task("[green]Faza 2: Skanowanie portów[/green]", total=total_tasks if total_tasks > 0 else 1)

        if discovery_tools:
            if config.SAFE_MODE:
                utils.log_and_echo("Tryb Bezpieczny: aktywuję wolniejsze skanowanie portów.", "INFO")
                if "Naabu" in discovery_tools and not config.USER_CUSTOMIZED_NAABU_SOURCE_PORT: config.NAABU_SOURCE_PORT = "53"
                if "Masscan" in discovery_tools and not config.USER_CUSTOMIZED_MASSCAN_RATE: config.MASSCAN_RATE = 100

            with ThreadPoolExecutor(max_workers=config.THREADS * len(discovery_tools)) as executor:
                futures = []
                for tool_name in discovery_tools:
                    for target in targets_to_scan:
                        output_file = os.path.join(config.REPORT_DIR, f"{tool_name.lower()}_{target.replace('.', '_')}.txt")
                        cmd = []
                        if tool_name == "Naabu":
                            cmd = ["naabu", "-silent", "-p", "-"]
                            if config.NAABU_SOURCE_PORT: cmd.extend(["-source-ip", f"0.0.0.0:{config.NAABU_SOURCE_PORT}"])
                            cmd.extend(["-rate", "100" if config.SAFE_MODE else "1000", "-host", target])
                        elif tool_name == "Masscan":
                            cmd = ["masscan", target, "-p1-65535", "--rate", str(config.MASSCAN_RATE)]
                        
                        futures.append(executor.submit(_run_scan_tool, tool_name, cmd, target, output_file, config.TOOL_TIMEOUT_SECONDS))
                
                for future in as_completed(futures):
                    future.result()
                    progress.update(phase2_task, advance=1)

            for tool_name in discovery_tools:
                agg_file = os.path.join(config.REPORT_DIR, f"{tool_name.lower()}_aggregated_results.txt")
                with open(agg_file, 'w', encoding='utf-8') as agg_f:
                    for target in targets_to_scan:
                        tool_file = os.path.join(config.REPORT_DIR, f"{tool_name.lower()}_{target.replace('.', '_')}.txt")
                        if os.path.exists(tool_file):
                            with open(tool_file, 'r', encoding='utf-8') as f: agg_f.write(f.read())
                
                if os.path.exists(agg_file) and os.path.getsize(agg_file) > 0:
                    final_results[f"{tool_name.lower()}_file"] = agg_file
                    ports_from_tool = _parse_host_port_output(agg_file)
                    for host, ports in ports_from_tool.items():
                        open_ports_by_host.setdefault(host, set()).update(ports)
        
        for host in open_ports_by_host: open_ports_by_host[host] = sorted(list(open_ports_by_host[host]))

        if nmap_enabled:
            nmap_base_cmd = ["nmap", "-sV", "-Pn"]
            if config.NMAP_AGGRESSIVE_SCAN: nmap_base_cmd.append("-A")
            elif config.NMAP_USE_SCRIPTS: nmap_base_cmd.append("-sC")
            nmap_base_cmd.extend(["-T2" if config.SAFE_MODE else "-T4"])

            with ThreadPoolExecutor(max_workers=config.THREADS) as executor:
                futures = {}
                for target in targets_to_scan:
                    ports_to_scan_for_target = open_ports_by_host.get(target)
                    if discovery_tools and not ports_to_scan_for_target:
                        utils.console.print(f"[yellow]Pomijam Nmap dla {target}, ponieważ nie znaleziono otwartych portów.[/yellow]")
                        progress.update(phase2_task, advance=1)
                        continue

                    cmd = list(nmap_base_cmd)
                    if ports_to_scan_for_target:
                        cmd.extend(["-p", ",".join(map(str, ports_to_scan_for_target))])
                    else: 
                        if nmap_scan_type == 'full':
                            cmd.extend(["-p-"])
                        elif nmap_scan_type == 'fast':
                            cmd.extend(["-F"])
                    
                    output_file = os.path.join(config.REPORT_DIR, f"nmap_{target.replace('.', '_')}.txt")
                    cmd.extend(["-oN", output_file, target])
                    futures[executor.submit(_run_scan_tool, "Nmap", cmd, target, output_file, config.TOOL_TIMEOUT_SECONDS)] = target
                
                for future in as_completed(futures):
                    target = futures[future]
                    if nmap_output_file := future.result(): final_results["nmap_files"][target] = nmap_output_file
                    progress.update(phase2_task, advance=1)

    if open_ports_by_host:
        final_results["open_ports_by_host"] = open_ports_by_host
    elif nmap_enabled:
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
        tool_names = ["Nmap (szczegóły)", "Naabu (szybkie odkrywanie)", "Masscan (super szybkie odkrywanie)"]
        for i, tool_name in enumerate(tool_names):
            status_char = "[bold green]✓[/bold green]" if config.selected_phase2_tools[i] == 1 else "[bold red]✗[/bold red]"
            table.add_row(f"[{i+1}]", f"{status_char} {tool_name}")
        table.add_section()
        table.add_row("[\fs]", "[bold magenta]Zmień ustawienia Fazy 2[/bold magenta]")
        table.add_row("[\fb]", "Powrót do menu głównego")
        table.add_row("[\fq]", "Wyjdź")
        utils.console.print(Align.center(table))
        utils.console.print(Align.center("[bold cyan]Rekomendacja: Włącz Nmap + Naabu + Masscan dla najlepszych wyników.[/bold cyan]"))
        choice = utils.get_single_char_input_with_prompt(Text.from_markup("[bold cyan]Wybierz opcję i naciśnij Enter, aby rozpocząć[/bold cyan]", justify="center"))
        
        if choice.isdigit() and 1 <= int(choice) <= 3:
            idx = int(choice) - 1
            config.selected_phase2_tools[idx] = 1 - config.selected_phase2_tools[idx]
        elif choice.lower() == 's': display_phase2_settings_menu(display_banner_func)
        elif choice.lower() == 'q': sys.exit(0)
        elif choice.lower() == 'b': return False
        elif choice == '\r':
            if any(config.selected_phase2_tools): return True
            else: utils.console.print(Align.center("[bold yellow]Proszę wybrać co najmniej jedno narzędzie.[/bold yellow]"))
        else: utils.console.print(Align.center("[bold yellow]Nieprawidłowa opcja.[/bold yellow]"))
        time.sleep(0.1)

def display_phase2_settings_menu(display_banner_func):
    nmap_solo_mode_map = {
        "default": "Top 1000 (Domyślnie)",
        "full": "Wszystkie Porty (1-65535)",
        "fast": "Szybkie Skanowanie (-F, Top 100)"
    }
    
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 2[/bold cyan]")))
        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        table.add_column("Key", style="bold blue", justify="center", min_width=5)
        table.add_column("Description", style="white", justify="left")
        
        masscan_rate_display = f"[bold yellow]{config.MASSCAN_RATE} pps[/bold yellow]"
        if config.USER_CUSTOMIZED_MASSCAN_RATE: masscan_rate_display = f"[bold green]{config.MASSCAN_RATE} pps (Użytkownika)[/bold green]"
        elif config.SAFE_MODE: masscan_rate_display = f"[bold red]100 pps (Safe Mode)[/bold red]"

        nmap_solo_display = f"[bold yellow]{nmap_solo_mode_map[config.NMAP_SOLO_SCAN_MODE]}[/bold yellow]"

        table.add_row("[1]", f"[{'[bold green]✓[/bold green]' if config.SAFE_MODE else '[bold red]✗[/bold red]'}] Tryb bezpieczny (wolniejsze skanowanie)")
        table.add_section()
        table.add_row("[bold]Nmap[/bold]", "")
        table.add_row("[2]", f"[{'[bold green]✓[/bold green]' if config.NMAP_USE_SCRIPTS else '[bold red]✗[/bold red]'}] Skanowanie skryptów (-sC)")
        table.add_row("[3]", f"[{'[bold green]✓[/bold green]' if config.NMAP_AGGRESSIVE_SCAN else '[bold red]✗[/bold red]'}] Skan agresywny (-A)")
        table.add_row("[4]", f"Zakres portów (gdy sam): {nmap_solo_display}")
        table.add_section()
        table.add_row("[bold]Masscan[/bold]", "")
        table.add_row("[5]", f"Szybkość skanowania (--rate): {masscan_rate_display}")
        table.add_section()
        table.add_row("[\fb]", "Powrót do menu Fazy 2")
        table.add_row("[\fq]", "Wyjdź")
        utils.console.print(Align.center(table))
    
        choice = utils.get_single_char_input_with_prompt(Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center"))

        if choice == '1':
            config.SAFE_MODE = not config.SAFE_MODE
            utils.handle_safe_mode_tor_check()
        elif choice == '2':
            config.NMAP_USE_SCRIPTS = not config.NMAP_USE_SCRIPTS
            if config.NMAP_USE_SCRIPTS: config.NMAP_AGGRESSIVE_SCAN = False
        elif choice == '3':
            config.NMAP_AGGRESSIVE_SCAN = not config.NMAP_AGGRESSIVE_SCAN
            if config.NMAP_AGGRESSIVE_SCAN: config.NMAP_USE_SCRIPTS = False
        elif choice == '4':
            new_mode = Prompt.ask(
                "[bold cyan]Wybierz tryb skanowania Nmap (gdy działa sam)[/bold cyan]",
                choices=["default", "full", "fast"],
                default=config.NMAP_SOLO_SCAN_MODE
            )
            config.NMAP_SOLO_SCAN_MODE = new_mode
        elif choice == '5':
            new_rate_str = Prompt.ask("[bold cyan]Podaj szybkość Masscan (pakiety/s)[/bold cyan]\n[bold yellow]UWAGA: Wysokie wartości (>1000) mogą zawiesić domowy router![/bold yellow]", default=str(config.MASSCAN_RATE))
            if new_rate_str.isdigit() and int(new_rate_str) > 0:
                config.MASSCAN_RATE = int(new_rate_str)
                config.USER_CUSTOMIZED_MASSCAN_RATE = True
            else: utils.console.print(Align.center("[bold red]Nieprawidłowa wartość.[/bold red]"))
        elif choice.lower() == 'b': break
        elif choice.lower() == 'q': sys.exit(0)
        else: utils.console.print(Align.center("[bold yellow]Nieprawidłowa opcja.[/bold yellow]"))
        time.sleep(0.1)


