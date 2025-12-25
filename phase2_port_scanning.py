#!/usr/bin/env python3

import os
import re
import socket
import subprocess
import sys
import time
import tempfile
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


def _sanitize_target(target: str) -> str:
    """
    Usuwa protokół (http/https) i ścieżki z celu, pozostawiając domenę lub IP.
    Niezbędne dla narzędzi typu Naabu/Nmap/Masscan.
    """
    # Usuń protokół
    target = re.sub(r"^https?://", "", target)
    # Usuń wszystko po pierwszym slashu (ścieżki)
    target = target.split("/")[0]
    return target


def _run_scan_tool(
    tool_name: str,
    command: List[str],
    targets: List[str],  # Zmieniono z target: str na listę
    output_file: str,
    timeout: int,
) -> Optional[str]:
    """
    Uruchamia narzędzie do skanowania portów i zapisuje wynik do pliku.
    Obsługuje przekazywanie celów przez plik tymczasowy.
    """
    # Sanityzacja celów
    clean_targets = list(set([_sanitize_target(t) for t in targets if t]))

    if not clean_targets:
        utils.console.print(
            f"[bold red]Brak poprawnych celów dla {tool_name}![/bold red]"
        )
        return None

    # Tworzenie pliku tymczasowego z celami
    with tempfile.NamedTemporaryFile(
        mode="w+", delete=False, suffix="_targets.txt"
    ) as tmp_targets:
        tmp_targets.write("\n".join(clean_targets))
        targets_file_path = tmp_targets.name

    # Modyfikacja komendy w zależności od narzędzia, aby używało pliku wejściowego
    final_command = list(command)
    sudo_prefix = []

    if tool_name in ["Naabu", "Masscan"] and os.geteuid() != 0:
        sudo_prefix = ["sudo"]

    # Dodanie flagi wejściowej w zależności od narzędzia
    if tool_name == "Naabu":
        # Naabu używa -list do pliku
        if "-host" in final_command:
            # Usuwamy stare flagi jeśli istnieją w configu
            try:
                idx = final_command.index("-host")
                final_command.pop(idx)  # remove flag
                if idx < len(final_command):
                    final_command.pop(idx)  # remove value (placeholder)
            except ValueError:
                pass
        final_command.extend(["-list", targets_file_path])

    elif tool_name == "Masscan":
        # Masscan używa -iL do pliku
        final_command.extend(["-iL", targets_file_path])

    elif tool_name == "Nmap":
        # Nmap używa -iL do pliku
        final_command.extend(["-iL", targets_file_path])

    full_command = sudo_prefix + final_command

    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in full_command)

    # Skróć wyświetlanie komendy jeśli jest za długa
    display_cmd = cmd_str if len(cmd_str) < 100 else cmd_str[:97] + "..."

    utils.console.print(
        f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] "
        f"[dim white]{display_cmd}[/dim white]"
    )

    process = None
    try:
        process = subprocess.Popen(
            full_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate(timeout=timeout)

        if process.returncode == 0:
            # Niektóre narzędzia nie piszą do pliku jeśli nie znajdą nic,
            # ale stdout może zawierać dane.
            if tool_name == "Naabu" and (
                not os.path.exists(output_file) or os.path.getsize(output_file) == 0
            ):
                # Naabu domyślnie pisze na stdout, chyba że jest -o.
                # Jeśli plik pusty, spróbujmy zapisać stdout.
                if stdout:
                    with open(output_file, "w") as f:
                        f.write(stdout)

            return output_file
        else:
            utils.console.print(
                f"[bold red]Błąd {tool_name} (kod {process.returncode}):[/bold red]"
            )
            if stderr:
                utils.console.print(f"[red]{stderr.strip()}[/red]")
            return None

    except subprocess.TimeoutExpired:
        if process:
            process.kill()
        utils.console.print(f"[bold red]Limit czasu dla {tool_name} minął![/bold red]")
        return None
    except Exception as e:
        utils.console.print(f"[bold red]Wyjątek przy {tool_name}: {e}[/bold red]")
        return None
    finally:
        # Sprzątanie pliku tymczasowego
        if os.path.exists(targets_file_path):
            os.remove(targets_file_path)


def start_port_scan(
    targets: List[str],  # Przyjmujemy listę celów
) -> Dict[str, Any]:
    """
    Uruchamia skanowanie portów (Faza 2).
    """
    utils.console.print(
        Align.center(
            f"[bold green]Rozpoczynam Fazę 2 - Skanowanie Portów "
            f"({len(targets)} celów)...[/bold green]"
        )
    )

    # Przygotowanie katalogu wyjściowego
    phase2_dir = os.path.join(config.REPORT_DIR, "faza2_porty")
    os.makedirs(phase2_dir, exist_ok=True)

    scan_results = {
        "naabu_raw": "",
        "masscan_raw": "",
        "nmap_raw": "",
        "open_ports_summary": {},
    }

    # Wybór narzędzi na podstawie configu
    active_tools = []
    # Indeksy: 0=Naabu, 1=Masscan, 2=Nmap
    tool_flags = (
        config.selected_phase2_tools
        if not config.ASSUME_YES
        else config.silent_selected_phase2_tools
    )

    if tool_flags[0]:
        active_tools.append("Naabu")
    if tool_flags[1]:
        active_tools.append("Masscan")
    if tool_flags[2]:
        active_tools.append("Nmap")

    if not active_tools:
        utils.console.print(
            "[yellow]Nie wybrano żadnych narzędzi skanowania portów.[/yellow]"
        )
        return scan_results

    # 1. Skanowanie "szybkie" (Discovery) - Naabu lub Masscan
    # Używamy tylko jednego z nich do wstępnego odkrycia portów, preferując Naabu
    discovery_tool = None
    if "Naabu" in active_tools:
        discovery_tool = "Naabu"
    elif "Masscan" in active_tools:
        discovery_tool = "Masscan"

    discovered_ports_map: Dict[str, Set[int]] = {}

    if discovery_tool:
        output_file = os.path.join(phase2_dir, f"{discovery_tool.lower()}_results.txt")

        cmd = []
        if discovery_tool == "Naabu":
            # Naabu command construction
            cmd = ["naabu", "-rate", str(config.NAABU_RATE), "-o", output_file]
            # Dodaj wykluczenia portów jeśli zdefiniowane
            if config.EXCLUDED_PORTS:
                cmd.extend(
                    ["-exclude-ports", ",".join(map(str, config.EXCLUDED_PORTS))]
                )
            # Dodaj zakres portów (domyślnie top 1000 lub full)
            # Naabu domyślnie skanuje top 100. Dodajmy -top-ports 1000 lub -p -
            cmd.extend(["-top-ports", "1000"])

        elif discovery_tool == "Masscan":
            # Masscan requires specific format
            cmd = [
                "masscan",
                "-p1-65535",
                "--rate",
                str(config.MASSCAN_RATE),
                "-oG",  # Grepable output
                output_file,
            ]
            # Masscan wymaga sudo wewnątrz funkcji _run_scan_tool

        utils.console.print(
            f"[bold yellow]Uruchamiam szybkie skanowanie przy użyciu {discovery_tool}...[/bold yellow]"
        )

        res_file = _run_scan_tool(
            discovery_tool, cmd, targets, output_file, config.TOOL_TIMEOUT_SECONDS
        )

        if res_file and os.path.exists(res_file):
            # Parsowanie wyników wstępnych
            try:
                with open(res_file, "r") as f:
                    content = f.read()
                    if discovery_tool == "Naabu":
                        scan_results["naabu_raw"] = content
                        for line in content.splitlines():
                            parts = line.strip().split(":")
                            if len(parts) == 2:
                                host, port = parts[0], parts[1]
                                if host not in discovered_ports_map:
                                    discovered_ports_map[host] = set()
                                discovered_ports_map[host].add(int(port))

                    elif discovery_tool == "Masscan":
                        scan_results["masscan_raw"] = content
                        # Format Masscan -oG: Host: 1.2.3.4 () Ports: 80/open/tcp//http//
                        for line in content.splitlines():
                            if "Ports:" in line and "Host:" in line:
                                try:
                                    ip_part = (
                                        line.split("Host:")[1].split("()")[0].strip()
                                    )
                                    ports_part = line.split("Ports:")[1].strip()
                                    port_str = ports_part.split("/")[0]
                                    if ip_part not in discovered_ports_map:
                                        discovered_ports_map[ip_part] = set()
                                    discovered_ports_map[ip_part].add(int(port_str))
                                except Exception:
                                    continue
            except Exception as e:
                utils.console.print(
                    f"[red]Błąd parsowania wyników {discovery_tool}: {e}[/red]"
                )
    else:
        # Jeśli nie ma discovery tool, a jest Nmap, przekazujemy wszystkie cele do Nmapa
        # Zakładamy domyślne porty dla Nmapa
        for t in targets:
            clean_t = _sanitize_target(t)
            discovered_ports_map[clean_t] = set()  # Pusty set oznacza "skanuj domyślne"

    # 2. Skanowanie "głębokie" (Service Detection) - Nmap
    if "Nmap" in active_tools:
        # Jeśli nic nie znaleziono w fazie discovery, a była ona uruchomiona, pomiń Nmapa
        if discovery_tool and not discovered_ports_map:
            utils.console.print(
                "[yellow]Brak otwartych portów do sprawdzenia przez Nmap.[/yellow]"
            )
        else:
            nmap_outfile = os.path.join(phase2_dir, "nmap_results.xml")
            # Budowanie listy celów dla Nmapa.
            # Jeśli mamy konkretne porty, Nmap powinien być uruchamiany per host, LUB
            # Jeśli lista hostów jest długa, a porty różne, to jest skomplikowane dla jednego runu.
            # DLA UPROSZCZENIA: W tej wersji uruchomimy Nmapa na liście hostów z wykrytymi portami
            # lub na wszystkich hostach jeśli nie było discovery.

            # Strategia:
            # Jeśli mamy mapę host->porty, grupujemy hosty które mają te same porty?
            # To trudne. Prościej: Uruchom Nmapa na liście hostów skanując najpopularniejsze porty
            # LUB przekaż zbiór wszystkich unikalnych portów znalezionych w discovery.

            all_detected_ports = set()
            for p_set in discovered_ports_map.values():
                all_detected_ports.update(p_set)

            port_arg = ""
            if all_detected_ports:
                sorted_ports = sorted(list(all_detected_ports))
                port_arg = ",".join(map(str, sorted_ports))

            # Komenda Nmap
            cmd = ["nmap"]
            if config.NMAP_AGGRESSIVE_SCAN:
                cmd.append("-A")
            else:
                cmd.extend(["-sV", "-sC"])  # Service version + default scripts

            if config.NMAP_USE_SCRIPTS and not config.NMAP_CUSTOM_SCRIPTS:
                # default scripts already in -sC
                pass
            elif config.NMAP_CUSTOM_SCRIPTS:
                cmd.extend(["--script", config.NMAP_CUSTOM_SCRIPTS])

            if port_arg:
                cmd.extend(["-p", port_arg])

            cmd.extend(["-oX", nmap_outfile])

            # Jeśli mamy mapę hostów, weźmy te hosty
            hosts_to_scan = (
                list(discovered_ports_map.keys()) if discovered_ports_map else targets
            )

            utils.console.print(
                f"[bold yellow]Uruchamiam Nmap na {len(hosts_to_scan)} hostach...[/bold yellow]"
            )

            res_file = _run_scan_tool(
                "Nmap",
                cmd,
                hosts_to_scan,
                nmap_outfile,
                config.TOOL_TIMEOUT_SECONDS * 2,  # Nmap trwa dłużej
            )

            if res_file and os.path.exists(res_file):
                with open(res_file, "r") as f:
                    scan_results["nmap_raw"] = f.read()

    # Podsumowanie wyników
    utils.console.print(Align.center("[bold green]Faza 2 zakończona.[/bold green]"))

    # Prosta konwersja wyników do słownika dla raportu JSON
    # (Pełne parsowanie XML Nmapa odbywa się w JS w raporcie HTML, tutaj tylko metadane)
    final_summary = {}
    for host, ports in discovered_ports_map.items():
        final_summary[host] = list(ports)
    scan_results["open_ports_summary"] = final_summary

    return scan_results
