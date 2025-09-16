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
    cmd_str = ' '.join(f'"{p}"' if ' ' in p else p for p in command)
    utils.console.print(f"[bold cyan]Uruchamiam: {tool_name} dla {target}:[/bold cyan] [dim white]{cmd_str}[/dim white]")

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
    progress_obj: Optional[Progress],
    main_task_id: Optional[TaskID]
) -> Dict[str, any]:
    """
    Rozpoczyna Fazę 2: Skanowanie portów na podanych celach.
    """
    if config.SAFE_MODE:
        utils.log_and_echo("Tryb Bezpieczny: aktywuję wolniejsze skanowanie portów.", "INFO")

    tool_configs = [
        {"name": "Nmap", "enabled": config.selected_phase2_tools[0], "base_cmd": ["nmap", "-sV", "-Pn"]},
        {"name": "Naabu", "enabled": config.selected_phase2_tools[1], "base_cmd": ["naabu", "-silent", "-p", "-"]}
    ]

    if config.SAFE_MODE:
        tool_configs[0]["base_cmd"].extend(["-T2"]) 
        tool_configs[1]["base_cmd"].extend(["-rate", "100"])
    else:
        tool_configs[0]["base_cmd"].extend(["-T4"])
        tool_configs[1]["base_cmd"].extend(["-rate", "1000"])

    final_results = {
        "nmap_files": {},
        "naabu_file": None,
        "open_ports_by_host": {}
    }

    with ThreadPoolExecutor(max_workers=config.THREADS) as executor:
        futures = []
        for target in targets:
            for tool_config in tool_configs:
                if not tool_config["enabled"]:
                    continue
                
                tool_name = tool_config["name"]
                cmd = list(tool_config["base_cmd"])
                
                output_filename = f"{tool_name.lower()}_{target.replace('.', '_')}.txt"
                output_file = os.path.join(config.REPORT_DIR, output_filename)

                if tool_name == "Nmap":
                    cmd.extend(["-oN", output_file, target])
                    cmd_to_run = cmd
                elif tool_name == "Naabu":
                    cmd.extend(["-host", target])
                    cmd_to_run = cmd

                futures.append(executor.submit(
                    _run_scan_tool, tool_name, cmd_to_run, target, output_file, config.TOOL_TIMEOUT_SECONDS
                ))

        for future in as_completed(futures):
            try:
                result_file = future.result()
            except Exception as e:
                utils.log_and_echo(f"Błąd w wątku wykonawczym Fazy 2: {e}", "ERROR")
            if progress_obj and main_task_id is not None:
                progress_obj.update(main_task_id, advance=1)

    naabu_raw_file = os.path.join(config.REPORT_DIR, "naabu_aggregated_results.txt")
    
    with open(naabu_raw_file, 'w', encoding='utf-8') as agg_f:
        for target in targets:
            naabu_file = os.path.join(config.REPORT_DIR, f"naabu_{target.replace('.', '_')}.txt")
            if os.path.exists(naabu_file):
                with open(naabu_file, 'r', encoding='utf-8') as f:
                    agg_f.write(f.read())
    
    if os.path.exists(naabu_raw_file):
        final_results["naabu_file"] = naabu_raw_file
        final_results["open_ports_by_host"] = _parse_naabu_output(naabu_raw_file)

    for target in targets:
        nmap_file = os.path.join(config.REPORT_DIR, f"nmap_{target.replace('.', '_')}.txt")
        if os.path.exists(nmap_file):
            final_results["nmap_files"][target] = nmap_file

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
        tool_names = ["Nmap", "Naabu"]
        for i, tool_name in enumerate(tool_names):
            status_char = "[bold green]✓[/bold green]" if config.selected_phase2_tools[i] == 1 else "[bold red]✗[/bold red]"
            table.add_row(f"[{i+1}]", f"{status_char} {tool_name}")
        table.add_section()
        table.add_row("[s]", "[bold magenta]Zmień ustawienia Fazy 2[/bold magenta]")
        table.add_row("[b]", "Powrót do menu głównego")
        table.add_row("[q]", "Wyjdź")
        utils.console.print(Align.center(table))
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

        table.add_row("[1]", f"[{'[bold green]✓[/bold green]' if config.SAFE_MODE else '[bold red]✗[/bold red]'}] Tryb bezpieczny (wolniejsze skanowanie)")
        table.add_row("[2]", f"Liczba wątków: {threads_display}")
        table.add_row("[3]", f"Limit czasu narzędzia: {timeout_display}")
        table.add_section()
        table.add_row("[b]", "Powrót do menu Fazy 2")
        table.add_row("[q]", "Wyjdź")
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
        elif choice.lower() == 'b':
            break
        elif choice.lower() == 'q':
            sys.exit(0)
        else:
            utils.console.print(Align.center("[bold yellow]Nieprawidłowa opcja.[/bold yellow]"))
        time.sleep(0.1)
