#!/usr/bin/env python3

import os
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set

from rich.align import Align
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

import config
import utils


def _run_scan_tool(
    tool_name: str, command: List[str], target: str, output_file: str, timeout: int
) -> Optional[str]:
    """Uruchamia narzędzie do skanowania portów i zapisuje wynik do pliku."""
    sudo_prefix = []
    if tool_name in ["Naabu", "Masscan"] and os.geteuid() != 0:
        sudo_prefix = ["sudo"]

    full_command = sudo_prefix + command
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in full_command)
    utils.console.print(
        f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] "
        f"[dim white]{cmd_str}[/dim white]"
    )

    process = None
    try:
        process = subprocess.Popen(
            full_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )

        with utils.processes_lock:
            utils.managed_processes.append(process)

        stdout, stderr = process.communicate(timeout=timeout)
        returncode = process.returncode

        if tool_name != "Nmap":
            with open(output_file, "w", encoding="utf-8") as f:
                if tool_name == "Masscan":
                    for line in stdout.splitlines():
                        if line.startswith("Discovered open port"):
                            parts = line.split()
                            port = parts[3].split("/")[0]
                            ip = parts[5]
                            f.write(f"{ip}:{port}\n")
                else:
                    f.write(stdout)

                if stderr:
                    f.write(f"\n--- STDERR ---\n{stderr}")
        elif stderr:
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(f"\n--- STDERR ---\n{stderr}")

        if returncode == 0:
            msg = f"✅ {tool_name} zakończył skanowanie dla {target}."
            utils.console.print(f"[bold green]{msg}[/bold green]")
        else:
            msg = f"Narzędzie {tool_name} dla {target} zakończyło z błędem."
            utils.log_and_echo(msg, "WARN")

        return output_file

    except subprocess.TimeoutExpired:
        msg = f"Komenda '{tool_name}' dla {target} przekroczyła limit czasu."
        utils.log_and_echo(msg, "WARN")
    except Exception as e:
        msg = f"Błąd wykonania '{tool_name}' dla {target}: {e}"
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

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if ":" in line:
                parts = line.split(":")
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
    port_pattern = re.compile(r"^(\d+)\/tcp\s+open")
    for host, file_path in nmap_files.items():
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                host_ports = []
                for line in f:
                    if match := port_pattern.match(line):
                        host_ports.append(int(match.group(1)))
                if host_ports:
                    ports_by_host[host] = sorted(list(set(host_ports)))
    return ports_by_host


def start_port_scan(
    targets: List[str], progress_obj: Optional[Progress], main_task_id: Optional[TaskID]
) -> Dict[str, Any]:
    final_results: Dict[str, Any] = {
        "nmap_files": {},
        "naabu_file": None,
        "masscan_file": None,
        "open_ports_by_host": {},
    }
    open_ports_by_host_set: Dict[str, Set[int]] = {}

    nmap_enabled = config.selected_phase2_tools[0] == 1
    naabu_enabled = config.selected_phase2_tools[1] == 1
    masscan_enabled = config.selected_phase2_tools[2] == 1
    discovery_tools = [
        t for t, e in zip(["Naabu", "Masscan"], [naabu_enabled, masscan_enabled]) if e
    ]

    title = "[bold green]Rozpoczynam Fazę 2 - Skanowanie Portów...[/bold green]"
    utils.console.print(Align.center(title))

    unique_ips = set()
    status_msg = "[cyan]Rozpoznawanie nazw na unikalne adresy IP...[/cyan]"
    with utils.console.status(status_msg, spinner="dots"):
        for url in targets:
            hostname_match = re.search(r"https?://([^/:]+)", url)
            target_host = hostname_match.group(1) if hostname_match else url

            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target_host):
                unique_ips.add(target_host)
            else:
                try:
                    unique_ips.add(socket.gethostbyname(target_host))
                except socket.gaierror:
                    msg = f"Nie można rozwiązać {target_host}. Pomijam."
                    utils.log_and_echo(msg, "WARN")

    targets_to_scan = sorted(list(unique_ips))
    count = len(targets_to_scan)
    utils.console.print(Align.center(f"Będę skanować [bold green]{count}[/bold green] IP."))
    if not targets_to_scan:
        return final_results

    nmap_scan_type = config.NMAP_SOLO_SCAN_MODE
    if nmap_enabled and not discovery_tools:
        panel_msg = (
            "[cyan]Nmap będzie działał samodzielnie.[/cyan]\n"
            "Jaki rodzaj skanowania portów chcesz przeprowadzić?"
        )
        panel = Panel(panel_msg, title="[yellow]Tryb Nmap[/yellow]", border_style="yellow")
        utils.console.print(Align.center(panel))
        nmap_scan_type = Prompt.ask(
            "[bold]Wybierz tryb[/bold]",
            choices=["default", "full", "fast"],
            default=config.NMAP_SOLO_SCAN_MODE,
        )

    total_tasks = (len(targets_to_scan) * len(discovery_tools)) + (
        len(targets_to_scan) if nmap_enabled else 0
    )

    phase2_dir = os.path.join(config.REPORT_DIR, "faza2_port_scanning")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        "•",
        TimeElapsedColumn(),
        console=utils.console,
        transient=True,
    ) as progress:
        task_desc = "[green]Faza 2: Skanowanie portów[/green]"
        phase2_task = progress.add_task(task_desc, total=total_tasks or 1)

        if discovery_tools:
            if config.SAFE_MODE:
                utils.log_and_echo("Tryb Bezpieczny: wolniejsze skanowanie.", "INFO")
                if "Naabu" in discovery_tools and not config.USER_CUSTOMIZED_NAABU_SOURCE_PORT:
                    config.NAABU_SOURCE_PORT = "53"
                if "Masscan" in discovery_tools and not config.USER_CUSTOMIZED_MASSCAN_RATE:
                    config.MASSCAN_RATE = 100

            with ThreadPoolExecutor(max_workers=config.THREADS * 2) as executor:
                futures: List[Future] = []
                for tool in discovery_tools:
                    for target in targets_to_scan:
                        out_file = os.path.join(
                            phase2_dir, f"{tool.lower()}_{target.replace('.', '_')}.txt"
                        )
                        cmd: List[str] = []
                        if tool == "Naabu":
                            cmd = ["naabu", "-silent", "-p", "-", "-warm-up-time", "0", "-retries", "1"]
                            if config.NAABU_SOURCE_PORT:
                                cmd.extend(["-source-ip", f"0.0.0.0:{config.NAABU_SOURCE_PORT}"])
                            rate = "100" if config.SAFE_MODE else str(config.NAABU_RATE)
                            cmd.extend(["-rate", rate, "-host", target])
                        elif tool == "Masscan":
                            cmd = ["masscan", target, "-p1-65535", "--rate", str(config.MASSCAN_RATE)]
                        futures.append(
                            executor.submit(
                                _run_scan_tool,
                                tool,
                                cmd,
                                target,
                                out_file,
                                config.TOOL_TIMEOUT_SECONDS,
                            )
                        )

                for future in as_completed(futures):
                    future.result()
                    progress.update(phase2_task, advance=1)

            for tool in discovery_tools:
                agg_file = os.path.join(config.REPORT_DIR, f"{tool.lower()}_aggregated.txt")
                with open(agg_file, "w", encoding="utf-8") as agg_f:
                    for target in targets_to_scan:
                        tool_file = os.path.join(
                            phase2_dir, f"{tool.lower()}_{target.replace('.', '_')}.txt"
                        )
                        if os.path.exists(tool_file):
                            with open(tool_file, "r", encoding="utf-8") as f:
                                agg_f.write(f.read())
                if os.path.exists(agg_file) and os.path.getsize(agg_file) > 0:
                    final_results[f"{tool.lower()}_file"] = agg_file
                    ports = _parse_host_port_output(agg_file)
                    for host, port_list in ports.items():
                        open_ports_by_host_set.setdefault(host, set()).update(port_list)

        open_ports_by_host = {h: sorted(list(p)) for h, p in open_ports_by_host_set.items()}

        if nmap_enabled:
            nmap_base_cmd = ["nmap", "-sV", "-Pn"]
            if config.NMAP_AGGRESSIVE_SCAN:
                nmap_base_cmd.append("-A")
            elif config.NMAP_USE_SCRIPTS:
                nmap_base_cmd.append("-sC")
            nmap_base_cmd.extend(["-T2" if config.SAFE_MODE else "-T4"])

            with ThreadPoolExecutor(max_workers=config.THREADS) as executor:
                futures_map: Dict[Future, str] = {}
                for target in targets_to_scan:
                    ports: Optional[List[int]] = open_ports_by_host.get(target)
                    if discovery_tools and not ports:
                        msg = f"[yellow]Pomijam Nmap dla {target} (brak portów).[/yellow]"
                        utils.console.print(msg)
                        progress.update(phase2_task, advance=1)
                        continue

                    cmd = list(nmap_base_cmd)
                    if ports:
                        cmd.extend(["-p", ",".join(map(str, ports))])
                    else:
                        if nmap_scan_type == "full":
                            cmd.extend(["-p-"])
                        elif nmap_scan_type == "fast":
                            cmd.extend(["-F"])

                    out_file = os.path.join(
                        phase2_dir, f"nmap_{target.replace('.', '_')}.txt"
                    )
                    cmd.extend(["-oN", out_file, target])
                    future = executor.submit(
                        _run_scan_tool, "Nmap", cmd, target, out_file, config.TOOL_TIMEOUT_SECONDS
                    )
                    futures_map[future] = target

                for future in as_completed(futures_map):
                    target = futures_map[future]
                    if nmap_file := future.result():
                        final_results["nmap_files"][target] = nmap_file
                    progress.update(phase2_task, advance=1)

    if open_ports_by_host:
        final_results["open_ports_by_host"] = open_ports_by_host
    elif nmap_enabled:
        final_results["open_ports_by_host"] = _parse_nmap_output_fallback(
            final_results["nmap_files"]
        )

    utils.log_and_echo("Ukończono fazę 2 - skanowanie portów.", "INFO")
    return final_results


def display_phase2_tool_selection_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        title = "[bold magenta]Faza 2: Skanowanie Portów[/bold magenta]"
        utils.console.print(Align.center(Panel.fit(title)))
        safe_mode_status = (
            "[bold green]WŁĄCZONY[/bold green]"
            if config.SAFE_MODE
            else "[bold red]WYŁĄCZONY[/bold red]"
        )
        utils.console.print(
            Align.center(
                f"Cel: [bold green]{config.ORIGINAL_TARGET}[/bold green] | "
                f"Tryb bezpieczny: {safe_mode_status}"
            )
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        tool_names = [
            "Nmap (szczegóły)",
            "Naabu (szybkie odkrywanie)",
            "Masscan (super szybkie)",
        ]
        for i, tool_name in enumerate(tool_names):
            status = (
                "[bold green]✓[/bold green]"
                if config.selected_phase2_tools[i]
                else "[bold red]✗[/bold red]"
            )
            table.add_row(f"[bold cyan][{i+1}][/bold cyan]", f"{status} {tool_name}")
        table.add_section()
        table.add_row(
            "[bold cyan][\fs][/bold cyan]",
            "[bold magenta]Zmień ustawienia Fazy 2[/bold magenta]",
        )
        table.add_row("[bold cyan][\fb][/bold cyan]", "Powrót do menu głównego")
        table.add_row("[bold cyan][\fq][/bold cyan]", "Wyjdź")

        utils.console.print(Align.center(table))
        reco = "Rekomendacja: Włącz Nmap + Naabu dla najlepszych wyników."
        utils.console.print(Align.center(f"[bold cyan]{reco}[/bold cyan]"))
        prompt_text = Text.from_markup(
            "[bold cyan]Wybierz opcję i naciśnij Enter[/bold cyan]", justify="center"
        )
        choice = utils.get_single_char_input_with_prompt(prompt_text)

        if choice.isdigit() and 1 <= int(choice) <= 3:
            config.selected_phase2_tools[int(choice) - 1] ^= 1
        elif choice.lower() == "s":
            display_phase2_settings_menu(display_banner_func)
        elif choice.lower() == "q":
            sys.exit(0)
        elif choice.lower() == "b":
            return False
        elif choice == "\r":
            if any(config.selected_phase2_tools):
                return True
            else:
                msg = "[bold yellow]Wybierz co najmniej jedno narzędzie.[/bold yellow]"
                utils.console.print(Align.center(msg))
        else:
            utils.console.print(Align.center("[bold yellow]Nieprawidłowa opcja.[/bold yellow]"))
        time.sleep(0.1)


def display_phase2_settings_menu(display_banner_func):
    nmap_solo_map = {
        "default": "Top 1000 (Domyślnie)",
        "full": "Wszystkie Porty (1-65535)",
        "fast": "Szybkie Skanowanie (-F, Top 100)",
    }
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 2[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        masscan_rate_disp = (
            f"[bold green]{config.MASSCAN_RATE} pps (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_MASSCAN_RATE
            else (
                "[bold yellow]100 pps (Safe Mode)[/bold yellow]"
                if config.SAFE_MODE
                else f"[dim]{config.MASSCAN_RATE} pps[/dim]"
            )
        )
        naabu_rate_disp = (
            f"[bold green]{config.NAABU_RATE} pps (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_NAABU_RATE
            else (
                "[bold yellow]100 pps (Safe Mode)[/bold yellow]"
                if config.SAFE_MODE
                else f"[dim]{config.NAABU_RATE} pps[/dim]"
            )
        )
        nmap_solo_disp = (
            f"[bold green]{nmap_solo_map[config.NMAP_SOLO_SCAN_MODE]} (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_NMAP_SOLO_SCAN_MODE
            else f"[dim]{nmap_solo_map[config.NMAP_SOLO_SCAN_MODE]}[/dim]"
        )
        safe_mode = "[bold green]✓[/bold green]" if config.SAFE_MODE else "[bold red]✗[/bold red]"
        nmap_scripts = "[bold green]✓[/bold green]" if config.NMAP_USE_SCRIPTS else "[bold red]✗[/bold red]"
        nmap_agg = "[bold green]✓[/bold green]" if config.NMAP_AGGRESSIVE_SCAN else "[bold red]✗[/bold red]"

        table.add_row("[bold cyan][1][/bold cyan]", f"[{safe_mode}] Tryb bezpieczny")
        table.add_section()
        table.add_row("[bold]Nmap[/bold]", "")
        table.add_row("[bold cyan][2][/bold cyan]", f"[{nmap_scripts}] Skanowanie skryptów (-sC)")
        table.add_row("[bold cyan][3][/bold cyan]", f"[{nmap_agg}] Skan agresywny (-A)")
        table.add_row("[bold cyan][4][/bold cyan]", f"Zakres portów (gdy sam): {nmap_solo_disp}")
        table.add_section()
        table.add_row("[bold]Naabu[/bold]", "")
        table.add_row("[bold cyan][5][/bold cyan]", f"Szybkość skanowania (rate): {naabu_rate_disp}")
        table.add_section()
        table.add_row("[bold]Masscan[/bold]", "")
        table.add_row("[bold cyan][6][/bold cyan]", f"Szybkość skanowania (--rate): {masscan_rate_disp}")
        table.add_section()
        table.add_row("[bold cyan][\fb][/bold cyan]", "Powrót do menu Fazy 2")
        table.add_row("[bold cyan][\fq][/bold cyan]", "Wyjdź")
        utils.console.print(Align.center(table))

        choice = utils.get_single_char_input_with_prompt(
            Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center")
        )

        if choice == "1":
            config.SAFE_MODE = not config.SAFE_MODE
            utils.handle_safe_mode_tor_check()
        elif choice == "2":
            config.NMAP_USE_SCRIPTS = not config.NMAP_USE_SCRIPTS
            if config.NMAP_USE_SCRIPTS:
                config.NMAP_AGGRESSIVE_SCAN = False
        elif choice == "3":
            config.NMAP_AGGRESSIVE_SCAN = not config.NMAP_AGGRESSIVE_SCAN
            if config.NMAP_AGGRESSIVE_SCAN:
                config.NMAP_USE_SCRIPTS = False
        elif choice == "4":
            new_mode = Prompt.ask(
                "[bold cyan]Wybierz tryb Nmap[/bold cyan]",
                choices=["default", "full", "fast"],
                default=config.NMAP_SOLO_SCAN_MODE,
            )
            config.NMAP_SOLO_SCAN_MODE = new_mode
            config.USER_CUSTOMIZED_NMAP_SOLO_SCAN_MODE = True
        elif choice == "5":
            new_rate = Prompt.ask(
                "[bold cyan]Podaj szybkość Naabu (pakiety/s)[/bold cyan]",
                default=str(config.NAABU_RATE),
            )
            if new_rate.isdigit() and int(new_rate) > 0:
                config.NAABU_RATE = int(new_rate)
                config.USER_CUSTOMIZED_NAABU_RATE = True
            else:
                utils.console.print(Align.center("[bold red]Nieprawidłowa wartość.[/bold red]"))
        elif choice == "6":
            new_rate = Prompt.ask(
                "[bold cyan]Podaj szybkość Masscan (pakiety/s)[/bold cyan]\n"
                "[yellow]UWAGA: Wysokie wartości mogą zawiesić router![/yellow]",
                default=str(config.MASSCAN_RATE),
            )
            if new_rate.isdigit() and int(new_rate) > 0:
                config.MASSCAN_RATE = int(new_rate)
                config.USER_CUSTOMIZED_MASSCAN_RATE = True
            else:
                utils.console.print(Align.center("[bold red]Nieprawidłowa wartość.[/bold red]"))
        elif choice.lower() == "b":
            break
        elif choice.lower() == "q":
            sys.exit(0)
