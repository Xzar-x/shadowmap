#!/usr/bin/env python3

import os
import re
import socket
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Set

from rich.align import Align
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

import config
import utils


def _sanitize_target(target: str) -> str:
    """
    Usuwa protokół (http/https), porty i ścieżki z celu, pozostawiając domenę lub IP.
    Niezbędne dla narzędzi typu Naabu/Nmap/Masscan.
    """
    # Usuń protokół
    target = re.sub(r"^https?://", "", target)
    # Usuń wszystko po pierwszym slashu (ścieżki)
    if "/" in target:
        target = target.split("/")[0]
    # Usuń port (Nmap/Naabu/Masscan zazwyczaj wolą czysty host/IP)
    if ":" in target:
        target = target.split(":")[0]
    return target


def _resolve_to_ip(target: str) -> Optional[str]:
    """Rozwiązuje nazwę hosta na IP. Zwraca None w przypadku błędu."""
    try:
        # Jeśli target to już IP, zwróć go
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _run_scan_tool(
    tool_name: str,
    command: List[str],
    targets: List[str],
    output_file: str,
    timeout: int,
) -> Optional[str]:
    """
    Uruchamia narzędzie do skanowania portów i zapisuje wynik do pliku.
    Obsługuje przekazywanie celów przez plik tymczasowy.
    """
    # Sanityzacja celów (redundantna jeśli start_port_scan to robi, ale bezpieczna)
    clean_targets = list(set([_sanitize_target(t) for t in targets if t]))

    # --- POPRAWKA DLA MASSCANA: WYMAGA IP ---
    if tool_name == "Masscan":
        ip_targets = []
        for t in clean_targets:
            ip = _resolve_to_ip(t)
            if ip:
                ip_targets.append(ip)
            else:
                utils.log_and_echo(
                    f"Masscan: Nie udało się rozwiązać IP dla {t}", "WARN"
                )

        if not ip_targets:
            utils.console.print(
                f"[bold red]Brak poprawnych adresów IP dla Masscana![/bold red]"
            )
            return None
        targets_to_write = ip_targets
    else:
        # Dla Naabu/Nmap mogą być domeny
        targets_to_write = clean_targets

    if not targets_to_write:
        utils.console.print(
            f"[bold red]Brak poprawnych celów dla {tool_name}![/bold red]"
        )
        return None

    # Tworzenie pliku tymczasowego z celami
    with tempfile.NamedTemporaryFile(
        mode="w+", delete=False, suffix="_targets.txt"
    ) as tmp_targets:
        tmp_targets.write("\n".join(targets_to_write))
        targets_file_path = tmp_targets.name

    # Modyfikacja komendy w zależności od narzędzia
    final_command = list(command)
    sudo_prefix = []

    if tool_name in ["Naabu", "Masscan"] and os.geteuid() != 0:
        sudo_prefix = ["sudo"]

    if tool_name == "Naabu":
        # Naabu cleanup host flags if present
        if "-host" in final_command:
            try:
                idx = final_command.index("-host")
                final_command.pop(idx)
                if idx < len(final_command):
                    final_command.pop(idx)
            except ValueError:
                pass
        final_command.extend(["-list", targets_file_path])

    elif tool_name == "Masscan":
        final_command.extend(["-iL", targets_file_path])

    elif tool_name == "Nmap":
        final_command.extend(["-iL", targets_file_path])

    full_command = sudo_prefix + final_command
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in full_command)
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
            if tool_name == "Naabu" and (
                not os.path.exists(output_file) or os.path.getsize(output_file) == 0
            ):
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
        if os.path.exists(targets_file_path):
            os.remove(targets_file_path)


def start_port_scan(
    targets: List[str],
    progress_obj: Optional[Progress] = None,
    main_task_id: Optional[TaskID] = None,
) -> Dict[str, Any]:
    """
    Uruchamia skanowanie portów (Faza 2).
    """
    # --- FIX: Sanityzacja celów na samym początku ---
    # Gwarantuje, że do narzędzi nie trafią adresy z http://
    targets = [_sanitize_target(t) for t in targets if t]

    utils.console.print(
        Align.center(
            f"[bold green]Rozpoczynam Fazę 2 - Skanowanie Portów "
            f"({len(targets)} celów)...[/bold green]"
        )
    )

    phase2_dir = os.path.join(config.REPORT_DIR, "faza2_porty")
    os.makedirs(phase2_dir, exist_ok=True)

    scan_results = {
        "naabu_raw": "",
        "masscan_raw": "",
        "nmap_raw": "",
        "open_ports_summary": {},
        "naabu_file": "",
        "masscan_file": "",
        "nmap_files": {},
    }

    tool_flags = (
        config.selected_phase2_tools
        if not config.AUTO_MODE
        else config.silent_selected_phase2_tools
    )

    active_tools = []
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

    # 1. Skanowanie "szybkie" (Discovery)
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
            cmd = ["naabu", "-rate", str(config.NAABU_RATE), "-o", output_file]
            if config.EXCLUDED_PORTS:
                cmd.extend(
                    ["-exclude-ports", ",".join(map(str, config.EXCLUDED_PORTS))]
                )
            cmd.extend(["-top-ports", "1000"])

        elif discovery_tool == "Masscan":
            cmd = [
                "masscan",
                "-p1-65535",
                "--rate",
                str(config.MASSCAN_RATE),
                "-oG",
                output_file,
            ]
            if config.EXCLUDED_PORTS:
                excluded = ",".join(map(str, config.EXCLUDED_PORTS))
                cmd.extend(["--exclude-ports", excluded])

        utils.console.print(
            f"[bold yellow]Uruchamiam szybkie skanowanie przy użyciu {discovery_tool}...[/bold yellow]"
        )

        res_file = _run_scan_tool(
            discovery_tool, cmd, targets, output_file, config.TOOL_TIMEOUT_SECONDS
        )

        if res_file and os.path.exists(res_file):
            if discovery_tool == "Naabu":
                scan_results["naabu_file"] = res_file
            elif discovery_tool == "Masscan":
                scan_results["masscan_file"] = res_file

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

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    # 2. Skanowanie "głębokie" (Service Detection) - Nmap
    if "Nmap" in active_tools:
        if discovery_tool and not discovered_ports_map:
            utils.console.print(
                "[yellow]Brak otwartych portów wykrytych w fazie szybkiej. Pomijam Nmap.[/yellow]"
            )
        else:
            nmap_outfile = os.path.join(phase2_dir, "nmap_results.xml")
            all_detected_ports = set()

            if discovered_ports_map:
                for p_set in discovered_ports_map.values():
                    all_detected_ports.update(p_set)
                utils.console.print(
                    f"[blue]Nmap sprawdzi {len(all_detected_ports)} portów odkrytych wcześniej.[/blue]"
                )
            else:
                # SOLO MODE - brak wyników discovery
                strat_display = "Domyślna (Top 1000)"
                if config.NMAP_SCAN_STRATEGY == "top-ports":
                    strat_display = f"Top {config.NMAP_CUSTOM_PORT_RANGE or 1000}"
                elif config.NMAP_SCAN_STRATEGY == "custom":
                    strat_display = f"Zakres: {config.NMAP_CUSTOM_PORT_RANGE}"
                elif config.NMAP_SCAN_STRATEGY == "all":  # Legacy fallback
                    strat_display = "Wszystkie (-p-)"

                utils.console.print(
                    f"[blue]Nmap działa samodzielnie. Strategia: {strat_display}[/blue]"
                )

            # Konstrukcja argumentu -p
            port_arg = ""
            cmd_additions = []

            if all_detected_ports:
                sorted_ports = sorted(list(all_detected_ports))
                port_arg = ",".join(map(str, sorted_ports))
            else:
                # Nmap Solo Logic based on config
                if config.NMAP_SCAN_STRATEGY == "top1000":
                    pass  # Default nmap behavior
                elif config.NMAP_SCAN_STRATEGY == "top-ports":
                    count = config.NMAP_CUSTOM_PORT_RANGE or "1000"
                    cmd_additions.extend(["--top-ports", str(count)])
                elif config.NMAP_SCAN_STRATEGY == "custom":
                    if config.NMAP_CUSTOM_PORT_RANGE:
                        port_arg = config.NMAP_CUSTOM_PORT_RANGE
                elif config.NMAP_SCAN_STRATEGY == "all":
                    port_arg = "-"

            cmd = ["nmap"]
            if config.NMAP_AGGRESSIVE_SCAN:
                cmd.append("-A")
            else:
                cmd.extend(["-sV", "-sC"])

            if config.NMAP_CUSTOM_SCRIPTS:
                cmd.extend(["--script", config.NMAP_CUSTOM_SCRIPTS])

            if port_arg:
                cmd.extend(["-p", port_arg])

            if cmd_additions:
                cmd.extend(cmd_additions)

            cmd.extend(["-oX", nmap_outfile])

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
                config.TOOL_TIMEOUT_SECONDS * 2,
            )

            if res_file and os.path.exists(res_file):
                scan_results["nmap_files"] = {"Nmap": res_file}
                with open(res_file, "r") as f:
                    scan_results["nmap_raw"] = f.read()

            if progress_obj and main_task_id is not None:
                progress_obj.update(main_task_id, advance=1)

    utils.console.print(Align.center("[bold green]Faza 2 zakończona.[/bold green]"))

    final_summary = {}
    for host, ports in discovered_ports_map.items():
        final_summary[host] = list(ports)
    scan_results["open_ports_summary"] = final_summary

    return scan_results


def display_phase2_tool_selection_menu(display_banner_func):
    """Wyświetla menu wyboru narzędzi dla Fazy 2."""
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(
                Panel.fit("[bold magenta]Faza 2: Skanowanie Portów[/bold magenta]")
            )
        )
        utils.console.print(
            Align.center(f"Cel: [bold green]{config.ORIGINAL_TARGET}[/bold green]")
        )

        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        tool_names = [
            "Naabu (Szybkie odkrywanie)",
            "Masscan (Super szybkie - wymaga root)",
            "Nmap (Wersje usług + Skrypty)",
        ]

        for i, tool_name in enumerate(tool_names):
            exe_cmd = config.TOOL_EXECUTABLE_MAP.get(tool_name)
            if "Naabu" in tool_name:
                exe_cmd = "naabu"
            if "Masscan" in tool_name:
                exe_cmd = "masscan"
            if "Nmap" in tool_name:
                exe_cmd = "nmap"

            is_missing = exe_cmd in config.MISSING_TOOLS
            status = (
                "[bold green]✓[/bold green]"
                if config.selected_phase2_tools[i]
                else "[bold red]✗[/bold red]"
            )
            display_str = f"{status} {tool_name}"
            row_style = "dim" if is_missing else ""
            if is_missing:
                display_str += " (niedostępne)"

            table.add_row(
                f"[bold cyan][{i+1}][/bold cyan]", display_str, style=row_style
            )

        table.add_section()
        table.add_row(
            "[bold cyan][\fs][/bold cyan]",
            "[bold magenta]Ustawienia Fazy 2[/bold magenta]",
        )
        table.add_row("[bold cyan][\b][/bold cyan]", "Powrót do menu")
        table.add_row("[bold cyan][\fq][/bold cyan]", "Wyjdź")

        utils.console.print(Align.center(table))
        prompt = Text.from_markup(
            "[bold cyan]Wybierz opcję i naciśnij Enter[/bold cyan]", justify="center"
        )
        choice = utils.get_single_char_input_with_prompt(prompt)

        if choice.isdigit() and 1 <= int(choice) <= 3:
            idx = int(choice) - 1
            tool_check = tool_names[idx]
            exe_cmd = ""
            if "Naabu" in tool_check:
                exe_cmd = "naabu"
            elif "Masscan" in tool_check:
                exe_cmd = "masscan"
            elif "Nmap" in tool_check:
                exe_cmd = "nmap"

            if exe_cmd in config.MISSING_TOOLS:
                utils.console.print(Align.center("[red]Narzędzie niedostępne.[/red]"))
                time.sleep(1)
            else:
                if idx == 0:  # Naabu
                    config.selected_phase2_tools[idx] ^= 1
                    if config.selected_phase2_tools[0]:
                        config.selected_phase2_tools[1] = 0
                elif idx == 1:  # Masscan
                    config.selected_phase2_tools[idx] ^= 1
                    if config.selected_phase2_tools[1]:
                        config.selected_phase2_tools[0] = 0
                else:
                    config.selected_phase2_tools[idx] ^= 1

        elif choice.lower() == "s":
            display_phase2_settings_menu(display_banner_func)
        elif choice.lower() == "q":
            sys.exit(0)
        elif choice.lower() == "b":
            return False
        elif choice == "\r":
            if any(config.selected_phase2_tools):
                # Nowa logika: Jeśli wybrano TYLKO Nmap, zapytaj o zakres
                # Indeksy: 0=Naabu, 1=Masscan, 2=Nmap
                if config.selected_phase2_tools == [0, 0, 1]:
                    utils.console.print(
                        Align.center(
                            Panel(
                                "[bold cyan]Konfiguracja Nmap (Solo Mode)[/bold cyan]",
                                border_style="cyan",
                            )
                        )
                    )

                    choice_mode = utils.ask_user_decision(
                        "Wybierz zakres skanowania:\n"
                        "[bold]D[/bold] - Default (Top 1000)\n"
                        "[bold]T[/bold] - Top X ports\n"
                        "[bold]C[/bold] - Custom range",
                        ["d", "t", "c"],
                        "d",
                    )

                    if choice_mode == "d":
                        config.NMAP_SCAN_STRATEGY = "top1000"
                    elif choice_mode == "t":
                        config.NMAP_SCAN_STRATEGY = "top-ports"
                        val = Prompt.ask(
                            "Podaj liczbę top portów (np. 100)", default="100"
                        )
                        config.NMAP_CUSTOM_PORT_RANGE = val
                    elif choice_mode == "c":
                        config.NMAP_SCAN_STRATEGY = "custom"
                        val = Prompt.ask(
                            "Podaj zakres (np. 1-65535, 80,443)", default="1-65535"
                        )
                        config.NMAP_CUSTOM_PORT_RANGE = val

                    config.USER_CUSTOMIZED_NMAP_STRATEGY = True

                return True
            else:
                utils.console.print(
                    Align.center(
                        "[yellow]Wybierz co najmniej jedno narzędzie.[/yellow]"
                    )
                )
                time.sleep(1)


def display_phase2_settings_menu(display_banner_func):
    """Wyświetla menu ustawień dla Fazy 2."""
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 2[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        naabu_rate_disp = f"[dim]{config.NAABU_RATE}[/dim]"
        if config.USER_CUSTOMIZED_NAABU_RATE:
            naabu_rate_disp = f"[bold green]{config.NAABU_RATE}[/bold green]"

        masscan_rate_disp = f"[dim]{config.MASSCAN_RATE}[/dim]"
        if config.USER_CUSTOMIZED_MASSCAN_RATE:
            masscan_rate_disp = f"[bold green]{config.MASSCAN_RATE}[/bold green]"

        nmap_scripts = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_USE_SCRIPTS
            else "[dim]NIE[/dim]"
        )
        nmap_aggressive = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_AGGRESSIVE_SCAN
            else "[dim]NIE[/dim]"
        )

        # Wyświetlanie aktualnej strategii (dla informacji)
        strat_info = config.NMAP_SCAN_STRATEGY
        if strat_info == "top1000":
            strat_info = "Top 1000"
        elif strat_info == "top-ports":
            strat_info = f"Top {config.NMAP_CUSTOM_PORT_RANGE}"
        elif strat_info == "custom":
            strat_info = f"Custom {config.NMAP_CUSTOM_PORT_RANGE}"

        excluded_ports_str = (
            ",".join(map(str, config.EXCLUDED_PORTS))
            if config.EXCLUDED_PORTS
            else "Brak"
        )

        table.add_row(
            "[bold cyan][1][/bold cyan]", f"Rate Limit (Naabu): {naabu_rate_disp}"
        )
        table.add_row(
            "[bold cyan][2][/bold cyan]", f"Rate Limit (Masscan): {masscan_rate_disp}"
        )
        table.add_row(
            "[bold cyan][3][/bold cyan]",
            f"Nmap: Domyślne Skrypty (-sC): {nmap_scripts}",
        )
        table.add_row(
            "[bold cyan][4][/bold cyan]",
            f"Nmap: Agresywny Skan (-A): {nmap_aggressive}",
        )
        table.add_row(
            "[bold cyan][5][/bold cyan]",
            f"Własne skrypty Nmap (--script): {config.NMAP_CUSTOM_SCRIPTS or 'Brak'}",
        )
        table.add_row(
            "[bold cyan][6][/bold cyan]", f"Wykluczone porty: {excluded_ports_str}"
        )
        table.add_row("", f"[dim]Aktualna strategia Nmap (Solo): {strat_info}[/dim]")

        table.add_section()
        table.add_row("[bold cyan][\fb][/bold cyan]", "Powrót")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text("Wybierz opcję", justify="center")
        )

        if choice == "1":
            val = Prompt.ask(
                "Podaj rate limit dla Naabu", default=str(config.NAABU_RATE)
            )
            if val.isdigit():
                config.NAABU_RATE = int(val)
                config.USER_CUSTOMIZED_NAABU_RATE = True
        elif choice == "2":
            val = Prompt.ask(
                "Podaj rate limit dla Masscan", default=str(config.MASSCAN_RATE)
            )
            if val.isdigit():
                config.MASSCAN_RATE = int(val)
                config.USER_CUSTOMIZED_MASSCAN_RATE = True
        elif choice == "3":
            config.NMAP_USE_SCRIPTS = not config.NMAP_USE_SCRIPTS
        elif choice == "4":
            config.NMAP_AGGRESSIVE_SCAN = not config.NMAP_AGGRESSIVE_SCAN
        elif choice == "5":
            val = Prompt.ask(
                "Podaj nazwy skryptów (po przecinku)",
                default=config.NMAP_CUSTOM_SCRIPTS,
            )
            config.NMAP_CUSTOM_SCRIPTS = val
            config.USER_CUSTOMIZED_NMAP_SCRIPTS = True
        elif choice == "6":
            val = Prompt.ask("Podaj porty do wykluczenia (po przecinku)", default="")
            try:
                config.EXCLUDED_PORTS = [
                    int(p.strip()) for p in val.split(",") if p.strip().isdigit()
                ]
            except ValueError:
                pass
        elif choice.lower() == "b":
            break  #!/usr/bin/env python3


import os
import re
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set

from rich.align import Align
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

import config
import utils


def _sanitize_target(target: str) -> str:
    """
    Usuwa protokół (http/https), porty i ścieżki z celu, pozostawiając domenę lub IP.
    Niezbędne dla narzędzi typu Naabu/Nmap/Masscan.
    """
    # Usuń protokół
    target = re.sub(r"^https?://", "", target)
    # Usuń wszystko po pierwszym slashu (ścieżki)
    if "/" in target:
        target = target.split("/")[0]
    # Usuń port (Nmap/Naabu/Masscan zazwyczaj wolą czysty host/IP)
    if ":" in target:
        target = target.split(":")[0]
    return target


def _resolve_to_ip(target: str) -> Optional[str]:
    """Rozwiązuje nazwę hosta na IP. Zwraca None w przypadku błędu."""
    try:
        # Jeśli target to już IP, zwróć go
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _run_scan_tool(
    tool_name: str,
    command: List[str],
    targets: List[str],
    output_file: str,
    timeout: int,
) -> Optional[str]:
    """
    Uruchamia narzędzie do skanowania portów i zapisuje wynik do pliku.
    Obsługuje przekazywanie celów przez plik tymczasowy.
    """
    # Sanityzacja celów (redundantna jeśli start_port_scan to robi, ale bezpieczna)
    clean_targets = list(set([_sanitize_target(t) for t in targets if t]))

    # --- POPRAWKA DLA MASSCANA: WYMAGA IP ---
    if tool_name == "Masscan":
        ip_targets = []
        for t in clean_targets:
            ip = _resolve_to_ip(t)
            if ip:
                ip_targets.append(ip)
            else:
                utils.log_and_echo(
                    f"Masscan: Nie udało się rozwiązać IP dla {t}", "WARN"
                )

        if not ip_targets:
            utils.console.print(
                f"[bold red]Brak poprawnych adresów IP dla Masscana![/bold red]"
            )
            return None
        targets_to_write = ip_targets
    else:
        # Dla Naabu/Nmap mogą być domeny
        targets_to_write = clean_targets

    if not targets_to_write:
        utils.console.print(
            f"[bold red]Brak poprawnych celów dla {tool_name}![/bold red]"
        )
        return None

    # Tworzenie pliku tymczasowego z celami
    with tempfile.NamedTemporaryFile(
        mode="w+", delete=False, suffix="_targets.txt"
    ) as tmp_targets:
        tmp_targets.write("\n".join(targets_to_write))
        targets_file_path = tmp_targets.name

    # Modyfikacja komendy w zależności od narzędzia
    final_command = list(command)
    sudo_prefix = []

    if tool_name in ["Naabu", "Masscan"] and os.geteuid() != 0:
        sudo_prefix = ["sudo"]

    if tool_name == "Naabu":
        # Naabu cleanup host flags if present
        if "-host" in final_command:
            try:
                idx = final_command.index("-host")
                final_command.pop(idx)
                if idx < len(final_command):
                    final_command.pop(idx)
            except ValueError:
                pass
        final_command.extend(["-list", targets_file_path])

    elif tool_name == "Masscan":
        final_command.extend(["-iL", targets_file_path])

    elif tool_name == "Nmap":
        final_command.extend(["-iL", targets_file_path])

    full_command = sudo_prefix + final_command
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in full_command)
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
            if tool_name == "Naabu" and (
                not os.path.exists(output_file) or os.path.getsize(output_file) == 0
            ):
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
        if os.path.exists(targets_file_path):
            os.remove(targets_file_path)


def start_port_scan(
    targets: List[str],
    progress_obj: Optional[Progress] = None,
    main_task_id: Optional[TaskID] = None,
) -> Dict[str, Any]:
    """
    Uruchamia skanowanie portów (Faza 2).
    """
    # --- FIX: Sanityzacja celów na samym początku ---
    # Gwarantuje, że do narzędzi nie trafią adresy z http://
    targets = [_sanitize_target(t) for t in targets if t]

    utils.console.print(
        Align.center(
            f"[bold green]Rozpoczynam Fazę 2 - Skanowanie Portów "
            f"({len(targets)} celów)...[/bold green]"
        )
    )

    phase2_dir = os.path.join(config.REPORT_DIR, "faza2_porty")
    os.makedirs(phase2_dir, exist_ok=True)

    scan_results = {
        "naabu_raw": "",
        "masscan_raw": "",
        "nmap_raw": "",
        "open_ports_by_host": {},  # Zmieniono nazwę klucza, aby pasowała do shadowmap.py
        "naabu_file": "",
        "masscan_file": "",
        "nmap_files": {},
    }

    tool_flags = (
        config.selected_phase2_tools
        if not config.AUTO_MODE
        else config.silent_selected_phase2_tools
    )

    active_tools = []
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

    # 1. Skanowanie "szybkie" (Discovery)
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
            cmd = ["naabu", "-rate", str(config.NAABU_RATE), "-o", output_file]
            if config.EXCLUDED_PORTS:
                cmd.extend(
                    ["-exclude-ports", ",".join(map(str, config.EXCLUDED_PORTS))]
                )
            cmd.extend(["-top-ports", "1000"])

        elif discovery_tool == "Masscan":
            cmd = [
                "masscan",
                "-p1-65535",
                "--rate",
                str(config.MASSCAN_RATE),
                "-oG",
                output_file,
            ]
            if config.EXCLUDED_PORTS:
                excluded = ",".join(map(str, config.EXCLUDED_PORTS))
                cmd.extend(["--exclude-ports", excluded])

        utils.console.print(
            f"[bold yellow]Uruchamiam szybkie skanowanie przy użyciu {discovery_tool}...[/bold yellow]"
        )

        res_file = _run_scan_tool(
            discovery_tool, cmd, targets, output_file, config.TOOL_TIMEOUT_SECONDS
        )

        if res_file and os.path.exists(res_file):
            if discovery_tool == "Naabu":
                scan_results["naabu_file"] = res_file
            elif discovery_tool == "Masscan":
                scan_results["masscan_file"] = res_file

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

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    # 2. Skanowanie "głębokie" (Service Detection) - Nmap
    if "Nmap" in active_tools:
        if discovery_tool and not discovered_ports_map:
            utils.console.print(
                "[yellow]Brak otwartych portów wykrytych w fazie szybkiej. "
                "Ponieważ wybrano Nmapa (lub jest to tryb Solo), uruchamiam Nmap bezpośrednio.[/yellow]"
            )
            # Nie pomijamy Nmapa, jeśli jest wybrany, nawet jeśli discovery nie znalazło portów
            # (może to być błąd discovery, a Nmap jest dokładniejszy)
            pass

        nmap_outfile = os.path.join(phase2_dir, "nmap_results.xml")
        all_detected_ports = set()

        if discovered_ports_map:
            for p_set in discovered_ports_map.values():
                all_detected_ports.update(p_set)
            utils.console.print(
                f"[blue]Nmap sprawdzi {len(all_detected_ports)} portów odkrytych wcześniej.[/blue]"
            )
        else:
            # SOLO MODE - brak wyników discovery
            strat_display = "Domyślna (Top 1000)"
            if config.NMAP_SCAN_STRATEGY == "top-ports":
                strat_display = f"Top {config.NMAP_CUSTOM_PORT_RANGE or 1000}"
            elif config.NMAP_SCAN_STRATEGY == "custom":
                strat_display = f"Zakres: {config.NMAP_CUSTOM_PORT_RANGE}"
            elif config.NMAP_SCAN_STRATEGY == "all":  # Legacy fallback
                strat_display = "Wszystkie (-p-)"

            utils.console.print(
                f"[blue]Nmap działa samodzielnie. Strategia: {strat_display}[/blue]"
            )

        # Konstrukcja argumentu -p
        port_arg = ""
        cmd_additions = []

        if all_detected_ports:
            sorted_ports = sorted(list(all_detected_ports))
            port_arg = ",".join(map(str, sorted_ports))
        else:
            # Nmap Solo Logic based on config
            if config.NMAP_SCAN_STRATEGY == "top1000":
                pass  # Default nmap behavior
            elif config.NMAP_SCAN_STRATEGY == "top-ports":
                count = config.NMAP_CUSTOM_PORT_RANGE or "1000"
                cmd_additions.extend(["--top-ports", str(count)])
            elif config.NMAP_SCAN_STRATEGY == "custom":
                if config.NMAP_CUSTOM_PORT_RANGE:
                    port_arg = config.NMAP_CUSTOM_PORT_RANGE
            elif config.NMAP_SCAN_STRATEGY == "all":
                port_arg = "-"

        cmd = ["nmap"]
        if config.NMAP_AGGRESSIVE_SCAN:
            cmd.append("-A")
        else:
            cmd.extend(["-sV", "-sC"])

        if config.NMAP_CUSTOM_SCRIPTS:
            cmd.extend(["--script", config.NMAP_CUSTOM_SCRIPTS])

        if port_arg:
            cmd.extend(["-p", port_arg])

        if cmd_additions:
            cmd.extend(cmd_additions)

        cmd.extend(["-oX", nmap_outfile])

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
            config.TOOL_TIMEOUT_SECONDS * 2,
        )

        if res_file and os.path.exists(res_file):
            scan_results["nmap_files"] = {"Nmap": res_file}
            with open(res_file, "r") as f:
                scan_results["nmap_raw"] = f.read()

            # --- PARSOWANIE WYNIKÓW NMAPA ---
            # To kluczowe dla trybu "Nmap Solo", aby zaktualizować listę znalezionych portów
            try:
                tree = ET.parse(res_file)
                root = tree.getroot()
                for host in root.findall("host"):
                    status = host.find("status")
                    if status is None or status.get("state") != "up":
                        continue

                    # Próba pobrania adresu
                    addr_elem = host.find("address")
                    if addr_elem is None:
                        continue
                    host_ip = addr_elem.get("addr")

                    ports_elem = host.find("ports")
                    if ports_elem is None:
                        continue

                    if host_ip not in discovered_ports_map:
                        discovered_ports_map[host_ip] = set()

                    for port in ports_elem.findall("port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            portid = port.get("portid")
                            if portid:
                                discovered_ports_map[host_ip].add(int(portid))

            except Exception as e:
                utils.console.print(
                    f"[red]Błąd podczas parsowania XML z Nmap: {e}[/red]"
                )

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    utils.console.print(Align.center("[bold green]Faza 2 zakończona.[/bold green]"))

    final_summary = {}
    for host, ports in discovered_ports_map.items():
        final_summary[host] = sorted(list(ports))
    scan_results["open_ports_by_host"] = final_summary

    return scan_results


def display_phase2_tool_selection_menu(display_banner_func):
    """Wyświetla menu wyboru narzędzi dla Fazy 2."""
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(
                Panel.fit("[bold magenta]Faza 2: Skanowanie Portów[/bold magenta]")
            )
        )
        utils.console.print(
            Align.center(f"Cel: [bold green]{config.ORIGINAL_TARGET}[/bold green]")
        )

        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        tool_names = [
            "Naabu (Szybkie odkrywanie)",
            "Masscan (Super szybkie - wymaga root)",
            "Nmap (Wersje usług + Skrypty)",
        ]

        for i, tool_name in enumerate(tool_names):
            exe_cmd = config.TOOL_EXECUTABLE_MAP.get(tool_name)
            if "Naabu" in tool_name:
                exe_cmd = "naabu"
            if "Masscan" in tool_name:
                exe_cmd = "masscan"
            if "Nmap" in tool_name:
                exe_cmd = "nmap"

            is_missing = exe_cmd in config.MISSING_TOOLS
            status = (
                "[bold green]✓[/bold green]"
                if config.selected_phase2_tools[i]
                else "[bold red]✗[/bold red]"
            )
            display_str = f"{status} {tool_name}"
            row_style = "dim" if is_missing else ""
            if is_missing:
                display_str += " (niedostępne)"

            table.add_row(
                f"[bold cyan][{i+1}][/bold cyan]", display_str, style=row_style
            )

        table.add_section()
        table.add_row(
            "[bold cyan][\fs][/bold cyan]",
            "[bold magenta]Ustawienia Fazy 2[/bold magenta]",
        )
        table.add_row("[bold cyan][\fb][/bold cyan]", "Powrót do menu")
        table.add_row("[bold cyan][\fq][/bold cyan]", "Wyjdź")

        utils.console.print(Align.center(table))
        prompt = Text.from_markup(
            "[bold cyan]Wybierz opcję i naciśnij Enter[/bold cyan]", justify="center"
        )
        choice = utils.get_single_char_input_with_prompt(prompt)

        if choice.isdigit() and 1 <= int(choice) <= 3:
            idx = int(choice) - 1
            tool_check = tool_names[idx]
            exe_cmd = ""
            if "Naabu" in tool_check:
                exe_cmd = "naabu"
            elif "Masscan" in tool_check:
                exe_cmd = "masscan"
            elif "Nmap" in tool_check:
                exe_cmd = "nmap"

            if exe_cmd in config.MISSING_TOOLS:
                utils.console.print(Align.center("[red]Narzędzie niedostępne.[/red]"))
                time.sleep(1)
            else:
                if idx == 0:  # Naabu
                    config.selected_phase2_tools[idx] ^= 1
                    if config.selected_phase2_tools[0]:
                        config.selected_phase2_tools[1] = 0
                elif idx == 1:  # Masscan
                    config.selected_phase2_tools[idx] ^= 1
                    if config.selected_phase2_tools[1]:
                        config.selected_phase2_tools[0] = 0
                else:
                    config.selected_phase2_tools[idx] ^= 1

        elif choice.lower() == "s":
            display_phase2_settings_menu(display_banner_func)
        elif choice.lower() == "q":
            sys.exit(0)
        elif choice.lower() == "b":
            return False
        elif choice == "\r":
            if any(config.selected_phase2_tools):
                # Nowa logika: Jeśli wybrano TYLKO Nmap, zapytaj o zakres
                # Indeksy: 0=Naabu, 1=Masscan, 2=Nmap
                if config.selected_phase2_tools == [0, 0, 1]:
                    utils.console.print(
                        Align.center(
                            Panel(
                                "[bold cyan]Konfiguracja Nmap (Solo Mode)[/bold cyan]",
                                border_style="cyan",
                            )
                        )
                    )

                    choice_mode = utils.ask_user_decision(
                        "Wybierz zakres skanowania:\n"
                        "[bold]D[/bold] - Default (Top 1000)\n"
                        "[bold]T[/bold] - Top X ports\n"
                        "[bold]C[/bold] - Custom range",
                        ["d", "t", "c"],
                        "d",
                    )

                    if choice_mode == "d":
                        config.NMAP_SCAN_STRATEGY = "top1000"
                    elif choice_mode == "t":
                        config.NMAP_SCAN_STRATEGY = "top-ports"
                        val = Prompt.ask(
                            "Podaj liczbę top portów (np. 100)", default="100"
                        )
                        config.NMAP_CUSTOM_PORT_RANGE = val
                    elif choice_mode == "c":
                        config.NMAP_SCAN_STRATEGY = "custom"
                        val = Prompt.ask(
                            "Podaj zakres (np. 1-65535, 80,443)", default="1-65535"
                        )
                        config.NMAP_CUSTOM_PORT_RANGE = val

                    config.USER_CUSTOMIZED_NMAP_STRATEGY = True

                return True
            else:
                utils.console.print(
                    Align.center(
                        "[yellow]Wybierz co najmniej jedno narzędzie.[/yellow]"
                    )
                )
                time.sleep(1)


def display_phase2_settings_menu(display_banner_func):
    """Wyświetla menu ustawień dla Fazy 2."""
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 2[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        naabu_rate_disp = f"[dim]{config.NAABU_RATE}[/dim]"
        if config.USER_CUSTOMIZED_NAABU_RATE:
            naabu_rate_disp = f"[bold green]{config.NAABU_RATE}[/bold green]"

        masscan_rate_disp = f"[dim]{config.MASSCAN_RATE}[/dim]"
        if config.USER_CUSTOMIZED_MASSCAN_RATE:
            masscan_rate_disp = f"[bold green]{config.MASSCAN_RATE}[/bold green]"

        nmap_scripts = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_USE_SCRIPTS
            else "[dim]NIE[/dim]"
        )
        nmap_aggressive = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_AGGRESSIVE_SCAN
            else "[dim]NIE[/dim]"
        )

        # Wyświetlanie aktualnej strategii (dla informacji)
        strat_info = config.NMAP_SCAN_STRATEGY
        if strat_info == "top1000":
            strat_info = "Top 1000"
        elif strat_info == "top-ports":
            strat_info = f"Top {config.NMAP_CUSTOM_PORT_RANGE}"
        elif strat_info == "custom":
            strat_info = f"Custom {config.NMAP_CUSTOM_PORT_RANGE}"

        excluded_ports_str = (
            ",".join(map(str, config.EXCLUDED_PORTS))
            if config.EXCLUDED_PORTS
            else "Brak"
        )

        table.add_row(
            "[bold cyan][1][/bold cyan]", f"Rate Limit (Naabu): {naabu_rate_disp}"
        )
        table.add_row(
            "[bold cyan][2][/bold cyan]", f"Rate Limit (Masscan): {masscan_rate_disp}"
        )
        table.add_row(
            "[bold cyan][3][/bold cyan]",
            f"Nmap: Domyślne Skrypty (-sC): {nmap_scripts}",
        )
        table.add_row(
            "[bold cyan][4][/bold cyan]",
            f"Nmap: Agresywny Skan (-A): {nmap_aggressive}",
        )
        table.add_row(
            "[bold cyan][5][/bold cyan]",
            f"Własne skrypty Nmap (--script): {config.NMAP_CUSTOM_SCRIPTS or 'Brak'}",
        )
        table.add_row(
            "[bold cyan][6][/bold cyan]", f"Wykluczone porty: {excluded_ports_str}"
        )
        table.add_row("", f"[dim]Aktualna strategia Nmap (Solo): {strat_info}[/dim]")

        table.add_section()
        table.add_row("[bold cyan][\\fb][/bold cyan]", "Powrót")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text("Wybierz opcję", justify="center")
        )

        if choice == "1":
            val = Prompt.ask(
                "Podaj rate limit dla Naabu", default=str(config.NAABU_RATE)
            )
            if val.isdigit():
                config.NAABU_RATE = int(val)
                config.USER_CUSTOMIZED_NAABU_RATE = True
        elif choice == "2":
            val = Prompt.ask(
                "Podaj rate limit dla Masscan", default=str(config.MASSCAN_RATE)
            )
            if val.isdigit():
                config.MASSCAN_RATE = int(val)
                config.USER_CUSTOMIZED_MASSCAN_RATE = True
        elif choice == "3":
            config.NMAP_USE_SCRIPTS = not config.NMAP_USE_SCRIPTS
        elif choice == "4":
            config.NMAP_AGGRESSIVE_SCAN = not config.NMAP_AGGRESSIVE_SCAN
        elif choice == "5":
            val = Prompt.ask(
                "Podaj nazwy skryptów (po przecinku)",
                default=config.NMAP_CUSTOM_SCRIPTS,
            )
            config.NMAP_CUSTOM_SCRIPTS = val
            config.USER_CUSTOMIZED_NMAP_SCRIPTS = True
        elif choice == "6":
            val = Prompt.ask("Podaj porty do wykluczenia (po przecinku)", default="")
            try:
                config.EXCLUDED_PORTS = [
                    int(p.strip()) for p in val.split(",") if p.strip().isdigit()
                ]
            except ValueError:
                pass
        elif choice.lower() == "b":
            break  #!/usr/bin/env python3


import os
import re
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set

from rich.align import Align
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

import config
import utils


def _sanitize_target(target: str) -> str:
    """
    Usuwa protokół (http/https), porty i ścieżki z celu, pozostawiając domenę lub IP.
    Niezbędne dla narzędzi typu Naabu/Nmap/Masscan.
    """
    # Usuń protokół
    target = re.sub(r"^https?://", "", target)
    # Usuń wszystko po pierwszym slashu (ścieżki)
    if "/" in target:
        target = target.split("/")[0]
    # Usuń port (Nmap/Naabu/Masscan zazwyczaj wolą czysty host/IP)
    if ":" in target:
        target = target.split(":")[0]
    return target


def _resolve_to_ip(target: str) -> Optional[str]:
    """Rozwiązuje nazwę hosta na IP. Zwraca None w przypadku błędu."""
    try:
        # Jeśli target to już IP, zwróć go
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _run_scan_tool(
    tool_name: str,
    command: List[str],
    targets: List[str],
    output_file: str,
    timeout: int,
) -> Optional[str]:
    """
    Uruchamia narzędzie do skanowania portów i zapisuje wynik do pliku.
    Obsługuje przekazywanie celów przez plik tymczasowy.
    """
    # Sanityzacja celów (redundantna jeśli start_port_scan to robi, ale bezpieczna)
    clean_targets = list(set([_sanitize_target(t) for t in targets if t]))

    # --- POPRAWKA DLA MASSCANA: WYMAGA IP ---
    if tool_name == "Masscan":
        ip_targets = []
        for t in clean_targets:
            ip = _resolve_to_ip(t)
            if ip:
                ip_targets.append(ip)
            else:
                utils.log_and_echo(
                    f"Masscan: Nie udało się rozwiązać IP dla {t}", "WARN"
                )

        if not ip_targets:
            utils.console.print(
                f"[bold red]Brak poprawnych adresów IP dla Masscana![/bold red]"
            )
            return None
        targets_to_write = ip_targets
    else:
        # Dla Naabu/Nmap mogą być domeny
        targets_to_write = clean_targets

    if not targets_to_write:
        utils.console.print(
            f"[bold red]Brak poprawnych celów dla {tool_name}![/bold red]"
        )
        return None

    # Tworzenie pliku tymczasowego z celami
    with tempfile.NamedTemporaryFile(
        mode="w+", delete=False, suffix="_targets.txt"
    ) as tmp_targets:
        tmp_targets.write("\n".join(targets_to_write))
        targets_file_path = tmp_targets.name

    # Modyfikacja komendy w zależności od narzędzia
    final_command = list(command)
    sudo_prefix = []

    if tool_name in ["Naabu", "Masscan"] and os.geteuid() != 0:
        sudo_prefix = ["sudo"]

    if tool_name == "Naabu":
        # Naabu cleanup host flags if present
        if "-host" in final_command:
            try:
                idx = final_command.index("-host")
                final_command.pop(idx)
                if idx < len(final_command):
                    final_command.pop(idx)
            except ValueError:
                pass
        final_command.extend(["-list", targets_file_path])

    elif tool_name == "Masscan":
        final_command.extend(["-iL", targets_file_path])

    elif tool_name == "Nmap":
        final_command.extend(["-iL", targets_file_path])

    full_command = sudo_prefix + final_command
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in full_command)
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
            if tool_name == "Naabu" and (
                not os.path.exists(output_file) or os.path.getsize(output_file) == 0
            ):
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
        if os.path.exists(targets_file_path):
            os.remove(targets_file_path)


def start_port_scan(
    targets: List[str],
    progress_obj: Optional[Progress] = None,
    main_task_id: Optional[TaskID] = None,
) -> Dict[str, Any]:
    """
    Uruchamia skanowanie portów (Faza 2).
    """
    # --- FIX: Sanityzacja celów na samym początku ---
    # Gwarantuje, że do narzędzi nie trafią adresy z http://
    targets = [_sanitize_target(t) for t in targets if t]

    utils.console.print(
        Align.center(
            f"[bold green]Rozpoczynam Fazę 2 - Skanowanie Portów "
            f"({len(targets)} celów)...[/bold green]"
        )
    )

    phase2_dir = os.path.join(config.REPORT_DIR, "faza2_porty")
    os.makedirs(phase2_dir, exist_ok=True)

    scan_results = {
        "naabu_raw": "",
        "masscan_raw": "",
        "nmap_raw": "",
        "open_ports_by_host": {},  # Zmieniono nazwę klucza, aby pasowała do shadowmap.py
        "naabu_file": "",
        "masscan_file": "",
        "nmap_files": {},
    }

    tool_flags = (
        config.selected_phase2_tools
        if not config.AUTO_MODE
        else config.silent_selected_phase2_tools
    )

    active_tools = []
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

    # 1. Skanowanie "szybkie" (Discovery)
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
            cmd = ["naabu", "-rate", str(config.NAABU_RATE), "-o", output_file]
            if config.EXCLUDED_PORTS:
                cmd.extend(
                    ["-exclude-ports", ",".join(map(str, config.EXCLUDED_PORTS))]
                )
            cmd.extend(["-top-ports", "1000"])

        elif discovery_tool == "Masscan":
            cmd = [
                "masscan",
                "-p1-65535",
                "--rate",
                str(config.MASSCAN_RATE),
                "-oG",
                output_file,
            ]
            if config.EXCLUDED_PORTS:
                excluded = ",".join(map(str, config.EXCLUDED_PORTS))
                cmd.extend(["--exclude-ports", excluded])

        utils.console.print(
            f"[bold yellow]Uruchamiam szybkie skanowanie przy użyciu {discovery_tool}...[/bold yellow]"
        )

        res_file = _run_scan_tool(
            discovery_tool, cmd, targets, output_file, config.TOOL_TIMEOUT_SECONDS
        )

        if res_file and os.path.exists(res_file):
            if discovery_tool == "Naabu":
                scan_results["naabu_file"] = res_file
            elif discovery_tool == "Masscan":
                scan_results["masscan_file"] = res_file

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

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    # 2. Skanowanie "głębokie" (Service Detection) - Nmap
    if "Nmap" in active_tools:
        if discovery_tool and not discovered_ports_map:
            utils.console.print(
                "[yellow]Brak otwartych portów wykrytych w fazie szybkiej. "
                "Ponieważ wybrano Nmapa (lub jest to tryb Solo), uruchamiam Nmap bezpośrednio.[/yellow]"
            )
            # Nie pomijamy Nmapa, jeśli jest wybrany, nawet jeśli discovery nie znalazło portów
            # (może to być błąd discovery, a Nmap jest dokładniejszy)
            pass

        nmap_outfile = os.path.join(phase2_dir, "nmap_results.xml")
        all_detected_ports = set()

        if discovered_ports_map:
            for p_set in discovered_ports_map.values():
                all_detected_ports.update(p_set)
            utils.console.print(
                f"[blue]Nmap sprawdzi {len(all_detected_ports)} portów odkrytych wcześniej.[/blue]"
            )
        else:
            # SOLO MODE - brak wyników discovery
            strat_display = "Domyślna (Top 1000)"
            if config.NMAP_SCAN_STRATEGY == "top-ports":
                strat_display = f"Top {config.NMAP_CUSTOM_PORT_RANGE or 1000}"
            elif config.NMAP_SCAN_STRATEGY == "custom":
                strat_display = f"Zakres: {config.NMAP_CUSTOM_PORT_RANGE}"
            elif config.NMAP_SCAN_STRATEGY == "all":  # Legacy fallback
                strat_display = "Wszystkie (-p-)"

            utils.console.print(
                f"[blue]Nmap działa samodzielnie. Strategia: {strat_display}[/blue]"
            )

        # Konstrukcja argumentu -p
        port_arg = ""
        cmd_additions = []

        if all_detected_ports:
            sorted_ports = sorted(list(all_detected_ports))
            port_arg = ",".join(map(str, sorted_ports))
        else:
            # Nmap Solo Logic based on config
            if config.NMAP_SCAN_STRATEGY == "top1000":
                pass  # Default nmap behavior
            elif config.NMAP_SCAN_STRATEGY == "top-ports":
                count = config.NMAP_CUSTOM_PORT_RANGE or "1000"
                cmd_additions.extend(["--top-ports", str(count)])
            elif config.NMAP_SCAN_STRATEGY == "custom":
                if config.NMAP_CUSTOM_PORT_RANGE:
                    port_arg = config.NMAP_CUSTOM_PORT_RANGE
            elif config.NMAP_SCAN_STRATEGY == "all":
                port_arg = "-"

        cmd = ["nmap"]
        if config.NMAP_AGGRESSIVE_SCAN:
            cmd.append("-A")
        else:
            cmd.extend(["-sV", "-sC"])

        if config.NMAP_CUSTOM_SCRIPTS:
            cmd.extend(["--script", config.NMAP_CUSTOM_SCRIPTS])

        if port_arg:
            cmd.extend(["-p", port_arg])

        if cmd_additions:
            cmd.extend(cmd_additions)

        cmd.extend(["-oX", nmap_outfile])

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
            config.TOOL_TIMEOUT_SECONDS * 2,
        )

        if res_file and os.path.exists(res_file):
            scan_results["nmap_files"] = {"Nmap": res_file}
            with open(res_file, "r") as f:
                scan_results["nmap_raw"] = f.read()

            # --- PARSOWANIE WYNIKÓW NMAPA ---
            # To kluczowe dla trybu "Nmap Solo", aby zaktualizować listę znalezionych portów
            try:
                tree = ET.parse(res_file)
                root = tree.getroot()
                ports_found_in_xml = 0
                for host in root.findall("host"):
                    status = host.find("status")
                    if status is None or status.get("state") != "up":
                        continue

                    # Próba pobrania adresu
                    host_ip = None
                    for addr in host.findall("address"):
                        if addr.get("addrtype") == "ipv4":
                            host_ip = addr.get("addr")
                            break

                    # Fallback dla starego typu lub braku addrtype
                    if not host_ip:
                        addr = host.find("address")
                        if addr is not None:
                            host_ip = addr.get("addr")

                    if not host_ip:
                        continue

                    ports_elem = host.find("ports")
                    if ports_elem is None:
                        continue

                    if host_ip not in discovered_ports_map:
                        discovered_ports_map[host_ip] = set()

                    for port in ports_elem.findall("port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            portid = port.get("portid")
                            if portid:
                                discovered_ports_map[host_ip].add(int(portid))
                                ports_found_in_xml += 1

                if ports_found_in_xml > 0:
                    utils.console.print(
                        f"[green]Nmap XML: Zaktualizowano wyniki. Znaleziono {ports_found_in_xml} otwartych portów.[/green]"
                    )
                else:
                    utils.console.print(
                        f"[yellow]Nmap XML: Przetworzono poprawnie, ale nie znaleziono otwartych portów w XML.[/yellow]"
                    )

            except Exception as e:
                utils.console.print(
                    f"[red]Błąd podczas parsowania XML z Nmap: {e}[/red]"
                )
                try:
                    with open(res_file, "r") as dbg_f:
                        head = dbg_f.read(300)
                        utils.console.print(
                            f"[dim]Początek pliku XML (debug): {head}[/dim]"
                        )
                except:
                    pass

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    utils.console.print(Align.center("[bold green]Faza 2 zakończona.[/bold green]"))

    final_summary = {}
    for host, ports in discovered_ports_map.items():
        final_summary[host] = sorted(list(ports))
    scan_results["open_ports_by_host"] = final_summary

    return scan_results


def display_phase2_tool_selection_menu(display_banner_func):
    """Wyświetla menu wyboru narzędzi dla Fazy 2."""
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(
                Panel.fit("[bold magenta]Faza 2: Skanowanie Portów[/bold magenta]")
            )
        )
        utils.console.print(
            Align.center(f"Cel: [bold green]{config.ORIGINAL_TARGET}[/bold green]")
        )

        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        tool_names = [
            "Naabu (Szybkie odkrywanie)",
            "Masscan (Super szybkie - wymaga root)",
            "Nmap (Wersje usług + Skrypty)",
        ]

        for i, tool_name in enumerate(tool_names):
            exe_cmd = config.TOOL_EXECUTABLE_MAP.get(tool_name)
            if "Naabu" in tool_name:
                exe_cmd = "naabu"
            if "Masscan" in tool_name:
                exe_cmd = "masscan"
            if "Nmap" in tool_name:
                exe_cmd = "nmap"

            is_missing = exe_cmd in config.MISSING_TOOLS
            status = (
                "[bold green]✓[/bold green]"
                if config.selected_phase2_tools[i]
                else "[bold red]✗[/bold red]"
            )
            display_str = f"{status} {tool_name}"
            row_style = "dim" if is_missing else ""
            if is_missing:
                display_str += " (niedostępne)"

            table.add_row(
                f"[bold cyan][{i+1}][/bold cyan]", display_str, style=row_style
            )

        table.add_section()
        table.add_row(
            "[bold cyan][\fs][/bold cyan]",
            "[bold magenta]Ustawienia Fazy 2[/bold magenta]",
        )
        table.add_row("[bold cyan][\fb][/bold cyan]", "Powrót do menu")
        table.add_row("[bold cyan][\fq][/bold cyan]", "Wyjdź")

        utils.console.print(Align.center(table))
        prompt = Text.from_markup(
            "[bold cyan]Wybierz opcję i naciśnij Enter[/bold cyan]", justify="center"
        )
        choice = utils.get_single_char_input_with_prompt(prompt)

        if choice.isdigit() and 1 <= int(choice) <= 3:
            idx = int(choice) - 1
            tool_check = tool_names[idx]
            exe_cmd = ""
            if "Naabu" in tool_check:
                exe_cmd = "naabu"
            elif "Masscan" in tool_check:
                exe_cmd = "masscan"
            elif "Nmap" in tool_check:
                exe_cmd = "nmap"

            if exe_cmd in config.MISSING_TOOLS:
                utils.console.print(Align.center("[red]Narzędzie niedostępne.[/red]"))
                time.sleep(1)
            else:
                if idx == 0:  # Naabu
                    config.selected_phase2_tools[idx] ^= 1
                    if config.selected_phase2_tools[0]:
                        config.selected_phase2_tools[1] = 0
                elif idx == 1:  # Masscan
                    config.selected_phase2_tools[idx] ^= 1
                    if config.selected_phase2_tools[1]:
                        config.selected_phase2_tools[0] = 0
                else:
                    config.selected_phase2_tools[idx] ^= 1

        elif choice.lower() == "s":
            display_phase2_settings_menu(display_banner_func)
        elif choice.lower() == "q":
            sys.exit(0)
        elif choice.lower() == "b":
            return False
        elif choice == "\r":
            if any(config.selected_phase2_tools):
                # Nowa logika: Jeśli wybrano TYLKO Nmap, zapytaj o zakres
                # Indeksy: 0=Naabu, 1=Masscan, 2=Nmap
                if config.selected_phase2_tools == [0, 0, 1]:
                    utils.console.print(
                        Align.center(
                            Panel(
                                "[bold cyan]Konfiguracja Nmap (Solo Mode)[/bold cyan]",
                                border_style="cyan",
                            )
                        )
                    )

                    choice_mode = utils.ask_user_decision(
                        "Wybierz zakres skanowania:\n"
                        "[bold]D[/bold] - Default (Top 1000)\n"
                        "[bold]T[/bold] - Top X ports\n"
                        "[bold]C[/bold] - Custom range",
                        ["d", "t", "c"],
                        "d",
                    )

                    if choice_mode == "d":
                        config.NMAP_SCAN_STRATEGY = "top1000"
                    elif choice_mode == "t":
                        config.NMAP_SCAN_STRATEGY = "top-ports"
                        val = Prompt.ask(
                            "Podaj liczbę top portów (np. 100)", default="100"
                        )
                        config.NMAP_CUSTOM_PORT_RANGE = val
                    elif choice_mode == "c":
                        config.NMAP_SCAN_STRATEGY = "custom"
                        val = Prompt.ask(
                            "Podaj zakres (np. 1-65535, 80,443)", default="1-65535"
                        )
                        config.NMAP_CUSTOM_PORT_RANGE = val

                    config.USER_CUSTOMIZED_NMAP_STRATEGY = True

                return True
            else:
                utils.console.print(
                    Align.center(
                        "[yellow]Wybierz co najmniej jedno narzędzie.[/yellow]"
                    )
                )
                time.sleep(1)


def display_phase2_settings_menu(display_banner_func):
    """Wyświetla menu ustawień dla Fazy 2."""
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 2[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        naabu_rate_disp = f"[dim]{config.NAABU_RATE}[/dim]"
        if config.USER_CUSTOMIZED_NAABU_RATE:
            naabu_rate_disp = f"[bold green]{config.NAABU_RATE}[/bold green]"

        masscan_rate_disp = f"[dim]{config.MASSCAN_RATE}[/dim]"
        if config.USER_CUSTOMIZED_MASSCAN_RATE:
            masscan_rate_disp = f"[bold green]{config.MASSCAN_RATE}[/bold green]"

        nmap_scripts = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_USE_SCRIPTS
            else "[dim]NIE[/dim]"
        )
        nmap_aggressive = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_AGGRESSIVE_SCAN
            else "[dim]NIE[/dim]"
        )

        # Wyświetlanie aktualnej strategii (dla informacji)
        strat_info = config.NMAP_SCAN_STRATEGY
        if strat_info == "top1000":
            strat_info = "Top 1000"
        elif strat_info == "top-ports":
            strat_info = f"Top {config.NMAP_CUSTOM_PORT_RANGE}"
        elif strat_info == "custom":
            strat_info = f"Custom {config.NMAP_CUSTOM_PORT_RANGE}"

        excluded_ports_str = (
            ",".join(map(str, config.EXCLUDED_PORTS))
            if config.EXCLUDED_PORTS
            else "Brak"
        )

        table.add_row(
            "[bold cyan][1][/bold cyan]", f"Rate Limit (Naabu): {naabu_rate_disp}"
        )
        table.add_row(
            "[bold cyan][2][/bold cyan]", f"Rate Limit (Masscan): {masscan_rate_disp}"
        )
        table.add_row(
            "[bold cyan][3][/bold cyan]",
            f"Nmap: Domyślne Skrypty (-sC): {nmap_scripts}",
        )
        table.add_row(
            "[bold cyan][4][/bold cyan]",
            f"Nmap: Agresywny Skan (-A): {nmap_aggressive}",
        )
        table.add_row(
            "[bold cyan][5][/bold cyan]",
            f"Własne skrypty Nmap (--script): {config.NMAP_CUSTOM_SCRIPTS or 'Brak'}",
        )
        table.add_row(
            "[bold cyan][6][/bold cyan]", f"Wykluczone porty: {excluded_ports_str}"
        )
        table.add_row("", f"[dim]Aktualna strategia Nmap (Solo): {strat_info}[/dim]")

        table.add_section()
        table.add_row("[bold cyan][\\fb][/bold cyan]", "Powrót")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text("Wybierz opcję", justify="center")
        )

        if choice == "1":
            val = Prompt.ask(
                "Podaj rate limit dla Naabu", default=str(config.NAABU_RATE)
            )
            if val.isdigit():
                config.NAABU_RATE = int(val)
                config.USER_CUSTOMIZED_NAABU_RATE = True
        elif choice == "2":
            val = Prompt.ask(
                "Podaj rate limit dla Masscan", default=str(config.MASSCAN_RATE)
            )
            if val.isdigit():
                config.MASSCAN_RATE = int(val)
                config.USER_CUSTOMIZED_MASSCAN_RATE = True
        elif choice == "3":
            config.NMAP_USE_SCRIPTS = not config.NMAP_USE_SCRIPTS
        elif choice == "4":
            config.NMAP_AGGRESSIVE_SCAN = not config.NMAP_AGGRESSIVE_SCAN
        elif choice == "5":
            val = Prompt.ask(
                "Podaj nazwy skryptów (po przecinku)",
                default=config.NMAP_CUSTOM_SCRIPTS,
            )
            config.NMAP_CUSTOM_SCRIPTS = val
            config.USER_CUSTOMIZED_NMAP_SCRIPTS = True
        elif choice == "6":
            val = Prompt.ask("Podaj porty do wykluczenia (po przecinku)", default="")
            try:
                config.EXCLUDED_PORTS = [
                    int(p.strip()) for p in val.split(",") if p.strip().isdigit()
                ]
            except ValueError:
                pass
        elif choice.lower() == "b":
            break  #!/usr/bin/env python3


import os
import re
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set

from rich.align import Align
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

import config
import utils


def _sanitize_target(target: str) -> str:
    """
    Usuwa protokół (http/https), porty i ścieżki z celu, pozostawiając domenę lub IP.
    Niezbędne dla narzędzi typu Naabu/Nmap/Masscan.
    """
    # Usuń protokół
    target = re.sub(r"^https?://", "", target)
    # Usuń wszystko po pierwszym slashu (ścieżki)
    if "/" in target:
        target = target.split("/")[0]
    # Usuń port (Nmap/Naabu/Masscan zazwyczaj wolą czysty host/IP)
    if ":" in target:
        target = target.split(":")[0]
    return target


def _resolve_to_ip(target: str) -> Optional[str]:
    """Rozwiązuje nazwę hosta na IP. Zwraca None w przypadku błędu."""
    try:
        # Jeśli target to już IP, zwróć go
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _run_scan_tool(
    tool_name: str,
    command: List[str],
    targets: List[str],
    output_file: str,
    timeout: int,
) -> Optional[str]:
    """
    Uruchamia narzędzie do skanowania portów i zapisuje wynik do pliku.
    Obsługuje przekazywanie celów przez plik tymczasowy.
    """
    # Sanityzacja celów (redundantna jeśli start_port_scan to robi, ale bezpieczna)
    clean_targets = list(set([_sanitize_target(t) for t in targets if t]))

    # --- POPRAWKA DLA MASSCANA: WYMAGA IP ---
    if tool_name == "Masscan":
        ip_targets = []
        for t in clean_targets:
            ip = _resolve_to_ip(t)
            if ip:
                ip_targets.append(ip)
            else:
                utils.log_and_echo(
                    f"Masscan: Nie udało się rozwiązać IP dla {t}", "WARN"
                )

        if not ip_targets:
            utils.console.print(
                f"[bold red]Brak poprawnych adresów IP dla Masscana![/bold red]"
            )
            return None
        targets_to_write = ip_targets
    else:
        # Dla Naabu/Nmap mogą być domeny
        targets_to_write = clean_targets

    if not targets_to_write:
        utils.console.print(
            f"[bold red]Brak poprawnych celów dla {tool_name}![/bold red]"
        )
        return None

    # Tworzenie pliku tymczasowego z celami
    with tempfile.NamedTemporaryFile(
        mode="w+", delete=False, suffix="_targets.txt"
    ) as tmp_targets:
        tmp_targets.write("\n".join(targets_to_write))
        targets_file_path = tmp_targets.name

    # Modyfikacja komendy w zależności od narzędzia
    final_command = list(command)
    sudo_prefix = []

    if tool_name in ["Naabu", "Masscan"] and os.geteuid() != 0:
        sudo_prefix = ["sudo"]

    if tool_name == "Naabu":
        # Naabu cleanup host flags if present
        if "-host" in final_command:
            try:
                idx = final_command.index("-host")
                final_command.pop(idx)
                if idx < len(final_command):
                    final_command.pop(idx)
            except ValueError:
                pass
        final_command.extend(["-list", targets_file_path])

    elif tool_name == "Masscan":
        final_command.extend(["-iL", targets_file_path])

    elif tool_name == "Nmap":
        final_command.extend(["-iL", targets_file_path])

    full_command = sudo_prefix + final_command
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in full_command)
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
            if tool_name == "Naabu" and (
                not os.path.exists(output_file) or os.path.getsize(output_file) == 0
            ):
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
        if os.path.exists(targets_file_path):
            os.remove(targets_file_path)


def start_port_scan(
    targets: List[str],
    progress_obj: Optional[Progress] = None,
    main_task_id: Optional[TaskID] = None,
) -> Dict[str, Any]:
    """
    Uruchamia skanowanie portów (Faza 2).
    """
    # --- FIX: Sanityzacja celów na samym początku ---
    # Gwarantuje, że do narzędzi nie trafią adresy z http://
    targets = [_sanitize_target(t) for t in targets if t]

    utils.console.print(
        Align.center(
            f"[bold green]Rozpoczynam Fazę 2 - Skanowanie Portów "
            f"({len(targets)} celów)...[/bold green]"
        )
    )

    phase2_dir = os.path.join(config.REPORT_DIR, "faza2_porty")
    os.makedirs(phase2_dir, exist_ok=True)

    scan_results = {
        "naabu_raw": "",
        "masscan_raw": "",
        "nmap_raw": "",
        "open_ports_by_host": {},  # Zmieniono nazwę klucza, aby pasowała do shadowmap.py
        "naabu_file": "",
        "masscan_file": "",
        "nmap_files": {},
    }

    tool_flags = (
        config.selected_phase2_tools
        if not config.AUTO_MODE
        else config.silent_selected_phase2_tools
    )

    active_tools = []
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

    # 1. Skanowanie "szybkie" (Discovery)
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
            cmd = ["naabu", "-rate", str(config.NAABU_RATE), "-o", output_file]
            if config.EXCLUDED_PORTS:
                cmd.extend(
                    ["-exclude-ports", ",".join(map(str, config.EXCLUDED_PORTS))]
                )
            cmd.extend(["-top-ports", "1000"])

        elif discovery_tool == "Masscan":
            cmd = [
                "masscan",
                "-p1-65535",
                "--rate",
                str(config.MASSCAN_RATE),
                "-oG",
                output_file,
            ]
            if config.EXCLUDED_PORTS:
                excluded = ",".join(map(str, config.EXCLUDED_PORTS))
                cmd.extend(["--exclude-ports", excluded])

        utils.console.print(
            f"[bold yellow]Uruchamiam szybkie skanowanie przy użyciu {discovery_tool}...[/bold yellow]"
        )

        res_file = _run_scan_tool(
            discovery_tool, cmd, targets, output_file, config.TOOL_TIMEOUT_SECONDS
        )

        if res_file and os.path.exists(res_file):
            if discovery_tool == "Naabu":
                scan_results["naabu_file"] = res_file
            elif discovery_tool == "Masscan":
                scan_results["masscan_file"] = res_file

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

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    # 2. Skanowanie "głębokie" (Service Detection) - Nmap
    if "Nmap" in active_tools:
        if discovery_tool and not discovered_ports_map:
            utils.console.print(
                "[yellow]Brak otwartych portów wykrytych w fazie szybkiej. "
                "Ponieważ wybrano Nmapa (lub jest to tryb Solo), uruchamiam Nmap bezpośrednio.[/yellow]"
            )
            # Nie pomijamy Nmapa, jeśli jest wybrany, nawet jeśli discovery nie znalazło portów
            # (może to być błąd discovery, a Nmap jest dokładniejszy)
            pass

        nmap_outfile = os.path.join(phase2_dir, "nmap_results.xml")
        nmap_outfile_txt = os.path.join(phase2_dir, "nmap_results.txt")
        all_detected_ports = set()

        if discovered_ports_map:
            for p_set in discovered_ports_map.values():
                all_detected_ports.update(p_set)
            utils.console.print(
                f"[blue]Nmap sprawdzi {len(all_detected_ports)} portów odkrytych wcześniej.[/blue]"
            )
        else:
            # SOLO MODE - brak wyników discovery
            strat_display = "Domyślna (Top 1000)"
            if config.NMAP_SCAN_STRATEGY == "top-ports":
                strat_display = f"Top {config.NMAP_CUSTOM_PORT_RANGE or 1000}"
            elif config.NMAP_SCAN_STRATEGY == "custom":
                strat_display = f"Zakres: {config.NMAP_CUSTOM_PORT_RANGE}"
            elif config.NMAP_SCAN_STRATEGY == "all":  # Legacy fallback
                strat_display = "Wszystkie (-p-)"

            utils.console.print(
                f"[blue]Nmap działa samodzielnie. Strategia: {strat_display}[/blue]"
            )

        # Konstrukcja argumentu -p
        port_arg = ""
        cmd_additions = []

        if all_detected_ports:
            sorted_ports = sorted(list(all_detected_ports))
            port_arg = ",".join(map(str, sorted_ports))
        else:
            # Nmap Solo Logic based on config
            if config.NMAP_SCAN_STRATEGY == "top1000":
                pass  # Default nmap behavior
            elif config.NMAP_SCAN_STRATEGY == "top-ports":
                count = config.NMAP_CUSTOM_PORT_RANGE or "1000"
                cmd_additions.extend(["--top-ports", str(count)])
            elif config.NMAP_SCAN_STRATEGY == "custom":
                if config.NMAP_CUSTOM_PORT_RANGE:
                    port_arg = config.NMAP_CUSTOM_PORT_RANGE
            elif config.NMAP_SCAN_STRATEGY == "all":
                port_arg = "-"

        cmd = ["nmap"]
        if config.NMAP_AGGRESSIVE_SCAN:
            cmd.append("-A")
        else:
            cmd.extend(["-sV", "-sC"])

        if config.NMAP_CUSTOM_SCRIPTS:
            cmd.extend(["--script", config.NMAP_CUSTOM_SCRIPTS])

        if port_arg:
            cmd.extend(["-p", port_arg])

        if cmd_additions:
            cmd.extend(cmd_additions)

        # Generujemy OBA formaty: XML (dla Pythona) i Normal (dla HTML Raportu)
        cmd.extend(["-oX", nmap_outfile, "-oN", nmap_outfile_txt])

        hosts_to_scan = (
            list(discovered_ports_map.keys()) if discovered_ports_map else targets
        )

        utils.console.print(
            f"[bold yellow]Uruchamiam Nmap na {len(hosts_to_scan)} hostach...[/bold yellow]"
        )

        # _run_scan_tool zwraca plik, który mu podamy (nmap_outfile), więc sprawdzamy XML
        res_file = _run_scan_tool(
            "Nmap",
            cmd,
            hosts_to_scan,
            nmap_outfile,
            config.TOOL_TIMEOUT_SECONDS * 2,
        )

        if res_file and os.path.exists(res_file):
            # 1. Parsowanie XML do logiki wewnętrznej (discovered_ports_map)
            try:
                tree = ET.parse(res_file)
                root = tree.getroot()
                ports_found_in_xml = 0
                for host in root.findall("host"):
                    status = host.find("status")
                    if status is None or status.get("state") != "up":
                        continue

                    # Próba pobrania adresu
                    host_ip = None
                    for addr in host.findall("address"):
                        if addr.get("addrtype") == "ipv4":
                            host_ip = addr.get("addr")
                            break

                    if not host_ip:
                        addr = host.find("address")
                        if addr is not None:
                            host_ip = addr.get("addr")

                    if not host_ip:
                        continue

                    ports_elem = host.find("ports")
                    if ports_elem is None:
                        continue

                    if host_ip not in discovered_ports_map:
                        discovered_ports_map[host_ip] = set()

                    for port in ports_elem.findall("port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            portid = port.get("portid")
                            if portid:
                                discovered_ports_map[host_ip].add(int(portid))
                                ports_found_in_xml += 1

                if ports_found_in_xml > 0:
                    utils.console.print(
                        f"[green]Nmap: Znaleziono {ports_found_in_xml} otwartych portów (zaktualizowano).[/green]"
                    )
                else:
                    utils.console.print(
                        f"[yellow]Nmap: Przetworzono wyniki, ale nie wykryto nowych otwartych portów.[/yellow]"
                    )

            except Exception as e:
                utils.console.print(
                    f"[red]Błąd podczas parsowania XML z Nmap: {e}[/red]"
                )

            # 2. Przygotowanie danych dla raportu HTML (wersja tekstowa/grepable)
            # Raport HTML oczekuje formatu tekstowego Nmapa, a nie XML.
            if os.path.exists(nmap_outfile_txt):
                scan_results["nmap_files"] = {"Nmap": nmap_outfile_txt}
                with open(nmap_outfile_txt, "r") as f:
                    scan_results["nmap_raw"] = f.read()
            else:
                # Fallback, jeśli z jakiegoś powodu txt nie powstał
                scan_results["nmap_files"] = {"Nmap": res_file}
                with open(res_file, "r") as f:
                    scan_results["nmap_raw"] = f.read()

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    utils.console.print(Align.center("[bold green]Faza 2 zakończona.[/bold green]"))

    final_summary = {}
    for host, ports in discovered_ports_map.items():
        final_summary[host] = sorted(list(ports))
    scan_results["open_ports_by_host"] = final_summary

    return scan_results


def display_phase2_tool_selection_menu(display_banner_func):
    """Wyświetla menu wyboru narzędzi dla Fazy 2."""
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(
                Panel.fit("[bold magenta]Faza 2: Skanowanie Portów[/bold magenta]")
            )
        )
        utils.console.print(
            Align.center(f"Cel: [bold green]{config.ORIGINAL_TARGET}[/bold green]")
        )

        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        tool_names = [
            "Naabu (Szybkie odkrywanie)",
            "Masscan (Super szybkie - wymaga root)",
            "Nmap (Wersje usług + Skrypty)",
        ]

        for i, tool_name in enumerate(tool_names):
            exe_cmd = config.TOOL_EXECUTABLE_MAP.get(tool_name)
            if "Naabu" in tool_name:
                exe_cmd = "naabu"
            if "Masscan" in tool_name:
                exe_cmd = "masscan"
            if "Nmap" in tool_name:
                exe_cmd = "nmap"

            is_missing = exe_cmd in config.MISSING_TOOLS
            status = (
                "[bold green]✓[/bold green]"
                if config.selected_phase2_tools[i]
                else "[bold red]✗[/bold red]"
            )
            display_str = f"{status} {tool_name}"
            row_style = "dim" if is_missing else ""
            if is_missing:
                display_str += " (niedostępne)"

            table.add_row(
                f"[bold cyan][{i+1}][/bold cyan]", display_str, style=row_style
            )

        table.add_section()
        table.add_row(
            "[bold cyan][\fs][/bold cyan]",
            "[bold magenta]Ustawienia Fazy 2[/bold magenta]",
        )
        table.add_row("[bold cyan][\fb][/bold cyan]", "Powrót do menu")
        table.add_row("[bold cyan][\fq][/bold cyan]", "Wyjdź")

        utils.console.print(Align.center(table))
        prompt = Text.from_markup(
            "[bold cyan]Wybierz opcję i naciśnij Enter[/bold cyan]", justify="center"
        )
        choice = utils.get_single_char_input_with_prompt(prompt)

        if choice.isdigit() and 1 <= int(choice) <= 3:
            idx = int(choice) - 1
            tool_check = tool_names[idx]
            exe_cmd = ""
            if "Naabu" in tool_check:
                exe_cmd = "naabu"
            elif "Masscan" in tool_check:
                exe_cmd = "masscan"
            elif "Nmap" in tool_check:
                exe_cmd = "nmap"

            if exe_cmd in config.MISSING_TOOLS:
                utils.console.print(Align.center("[red]Narzędzie niedostępne.[/red]"))
                time.sleep(1)
            else:
                if idx == 0:  # Naabu
                    config.selected_phase2_tools[idx] ^= 1
                    if config.selected_phase2_tools[0]:
                        config.selected_phase2_tools[1] = 0
                elif idx == 1:  # Masscan
                    config.selected_phase2_tools[idx] ^= 1
                    if config.selected_phase2_tools[1]:
                        config.selected_phase2_tools[0] = 0
                else:
                    config.selected_phase2_tools[idx] ^= 1

        elif choice.lower() == "s":
            display_phase2_settings_menu(display_banner_func)
        elif choice.lower() == "q":
            sys.exit(0)
        elif choice.lower() == "b":
            return False
        elif choice == "\r":
            if any(config.selected_phase2_tools):
                # Nowa logika: Jeśli wybrano TYLKO Nmap, zapytaj o zakres
                # Indeksy: 0=Naabu, 1=Masscan, 2=Nmap
                if config.selected_phase2_tools == [0, 0, 1]:
                    utils.console.print(
                        Align.center(
                            Panel(
                                "[bold cyan]Konfiguracja Nmap (Solo Mode)[/bold cyan]",
                                border_style="cyan",
                            )
                        )
                    )

                    choice_mode = utils.ask_user_decision(
                        "Wybierz zakres skanowania:\n"
                        "[bold]D[/bold] - Default (Top 1000)\n"
                        "[bold]T[/bold] - Top X ports\n"
                        "[bold]C[/bold] - Custom range",
                        ["d", "t", "c"],
                        "d",
                    )

                    if choice_mode == "d":
                        config.NMAP_SCAN_STRATEGY = "top1000"
                    elif choice_mode == "t":
                        config.NMAP_SCAN_STRATEGY = "top-ports"
                        val = Prompt.ask(
                            "Podaj liczbę top portów (np. 100)", default="100"
                        )
                        config.NMAP_CUSTOM_PORT_RANGE = val
                    elif choice_mode == "c":
                        config.NMAP_SCAN_STRATEGY = "custom"
                        val = Prompt.ask(
                            "Podaj zakres (np. 1-65535, 80,443)", default="1-65535"
                        )
                        config.NMAP_CUSTOM_PORT_RANGE = val

                    config.USER_CUSTOMIZED_NMAP_STRATEGY = True

                return True
            else:
                utils.console.print(
                    Align.center(
                        "[yellow]Wybierz co najmniej jedno narzędzie.[/yellow]"
                    )
                )
                time.sleep(1)


def display_phase2_settings_menu(display_banner_func):
    """Wyświetla menu ustawień dla Fazy 2."""
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 2[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        naabu_rate_disp = f"[dim]{config.NAABU_RATE}[/dim]"
        if config.USER_CUSTOMIZED_NAABU_RATE:
            naabu_rate_disp = f"[bold green]{config.NAABU_RATE}[/bold green]"

        masscan_rate_disp = f"[dim]{config.MASSCAN_RATE}[/dim]"
        if config.USER_CUSTOMIZED_MASSCAN_RATE:
            masscan_rate_disp = f"[bold green]{config.MASSCAN_RATE}[/bold green]"

        nmap_scripts = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_USE_SCRIPTS
            else "[dim]NIE[/dim]"
        )
        nmap_aggressive = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_AGGRESSIVE_SCAN
            else "[dim]NIE[/dim]"
        )

        # Wyświetlanie aktualnej strategii (dla informacji)
        strat_info = config.NMAP_SCAN_STRATEGY
        if strat_info == "top1000":
            strat_info = "Top 1000"
        elif strat_info == "top-ports":
            strat_info = f"Top {config.NMAP_CUSTOM_PORT_RANGE}"
        elif strat_info == "custom":
            strat_info = f"Custom {config.NMAP_CUSTOM_PORT_RANGE}"

        excluded_ports_str = (
            ",".join(map(str, config.EXCLUDED_PORTS))
            if config.EXCLUDED_PORTS
            else "Brak"
        )

        table.add_row(
            "[bold cyan][1][/bold cyan]", f"Rate Limit (Naabu): {naabu_rate_disp}"
        )
        table.add_row(
            "[bold cyan][2][/bold cyan]", f"Rate Limit (Masscan): {masscan_rate_disp}"
        )
        table.add_row(
            "[bold cyan][3][/bold cyan]",
            f"Nmap: Domyślne Skrypty (-sC): {nmap_scripts}",
        )
        table.add_row(
            "[bold cyan][4][/bold cyan]",
            f"Nmap: Agresywny Skan (-A): {nmap_aggressive}",
        )
        table.add_row(
            "[bold cyan][5][/bold cyan]",
            f"Własne skrypty Nmap (--script): {config.NMAP_CUSTOM_SCRIPTS or 'Brak'}",
        )
        table.add_row(
            "[bold cyan][6][/bold cyan]", f"Wykluczone porty: {excluded_ports_str}"
        )
        table.add_row("", f"[dim]Aktualna strategia Nmap (Solo): {strat_info}[/dim]")

        table.add_section()
        table.add_row("[bold cyan][\\fb][/bold cyan]", "Powrót")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text("Wybierz opcję", justify="center")
        )

        if choice == "1":
            val = Prompt.ask(
                "Podaj rate limit dla Naabu", default=str(config.NAABU_RATE)
            )
            if val.isdigit():
                config.NAABU_RATE = int(val)
                config.USER_CUSTOMIZED_NAABU_RATE = True
        elif choice == "2":
            val = Prompt.ask(
                "Podaj rate limit dla Masscan", default=str(config.MASSCAN_RATE)
            )
            if val.isdigit():
                config.MASSCAN_RATE = int(val)
                config.USER_CUSTOMIZED_MASSCAN_RATE = True
        elif choice == "3":
            config.NMAP_USE_SCRIPTS = not config.NMAP_USE_SCRIPTS
        elif choice == "4":
            config.NMAP_AGGRESSIVE_SCAN = not config.NMAP_AGGRESSIVE_SCAN
        elif choice == "5":
            val = Prompt.ask(
                "Podaj nazwy skryptów (po przecinku)",
                default=config.NMAP_CUSTOM_SCRIPTS,
            )
            config.NMAP_CUSTOM_SCRIPTS = val
            config.USER_CUSTOMIZED_NMAP_SCRIPTS = True
        elif choice == "6":
            val = Prompt.ask("Podaj porty do wykluczenia (po przecinku)", default="")
            try:
                config.EXCLUDED_PORTS = [
                    int(p.strip()) for p in val.split(",") if p.strip().isdigit()
                ]
            except ValueError:
                pass
        elif choice.lower() == "b":
            break  #!/usr/bin/env python3


import os
import re
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set

from rich.align import Align
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

import config
import utils


def _sanitize_target(target: str) -> str:
    """
    Usuwa protokół (http/https), porty i ścieżki z celu, pozostawiając domenę lub IP.
    Niezbędne dla narzędzi typu Naabu/Nmap/Masscan.
    """
    # Usuń protokół
    target = re.sub(r"^https?://", "", target)
    # Usuń wszystko po pierwszym slashu (ścieżki)
    if "/" in target:
        target = target.split("/")[0]
    # Usuń port (Nmap/Naabu/Masscan zazwyczaj wolą czysty host/IP)
    if ":" in target:
        target = target.split(":")[0]
    return target


def _resolve_to_ip(target: str) -> Optional[str]:
    """Rozwiązuje nazwę hosta na IP. Zwraca None w przypadku błędu."""
    try:
        # Jeśli target to już IP, zwróć go
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _run_scan_tool(
    tool_name: str,
    command: List[str],
    targets: List[str],
    output_file: str,
    timeout: int,
) -> Optional[str]:
    """
    Uruchamia narzędzie do skanowania portów i zapisuje wynik do pliku.
    Obsługuje przekazywanie celów przez plik tymczasowy.
    Dodano: Spinner (pasek postępu) informujący o działaniu w tle.
    """
    # Sanityzacja celów (redundantna jeśli start_port_scan to robi, ale bezpieczna)
    clean_targets = list(set([_sanitize_target(t) for t in targets if t]))

    # --- POPRAWKA DLA MASSCANA: WYMAGA IP ---
    if tool_name == "Masscan":
        ip_targets = []
        for t in clean_targets:
            ip = _resolve_to_ip(t)
            if ip:
                ip_targets.append(ip)
            else:
                utils.log_and_echo(
                    f"Masscan: Nie udało się rozwiązać IP dla {t}", "WARN"
                )

        if not ip_targets:
            utils.console.print(
                f"[bold red]Brak poprawnych adresów IP dla Masscana![/bold red]"
            )
            return None
        targets_to_write = ip_targets
    else:
        # Dla Naabu/Nmap mogą być domeny
        targets_to_write = clean_targets

    if not targets_to_write:
        utils.console.print(
            f"[bold red]Brak poprawnych celów dla {tool_name}![/bold red]"
        )
        return None

    # Tworzenie pliku tymczasowego z celami
    with tempfile.NamedTemporaryFile(
        mode="w+", delete=False, suffix="_targets.txt"
    ) as tmp_targets:
        tmp_targets.write("\n".join(targets_to_write))
        targets_file_path = tmp_targets.name

    # Modyfikacja komendy w zależności od narzędzia
    final_command = list(command)
    sudo_prefix = []

    # --- ZMIANA: Nmap również potrzebuje sudo dla -O/-A i skanowania SYN ---
    if tool_name in ["Naabu", "Masscan", "Nmap"] and os.geteuid() != 0:
        sudo_prefix = ["sudo"]

    if tool_name == "Naabu":
        # Naabu cleanup host flags if present
        if "-host" in final_command:
            try:
                idx = final_command.index("-host")
                final_command.pop(idx)
                if idx < len(final_command):
                    final_command.pop(idx)
            except ValueError:
                pass
        final_command.extend(["-list", targets_file_path])

    elif tool_name == "Masscan":
        final_command.extend(["-iL", targets_file_path])

    elif tool_name == "Nmap":
        final_command.extend(["-iL", targets_file_path])

    full_command = sudo_prefix + final_command
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in full_command)
    display_cmd = cmd_str if len(cmd_str) < 100 else cmd_str[:97] + "..."

    utils.console.print(
        f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] "
        f"[dim white]{display_cmd}[/dim white]"
    )

    process = None
    try:
        # --- ZMIANA: Dodanie statusu (spinnera) ---
        status_msg = f"[bold green]Narzędzie {tool_name} pracuje...[/bold green] [dim](Może to chwilę potrwać)[/dim]"
        with utils.console.status(status_msg, spinner="dots"):
            process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = process.communicate(timeout=timeout)

        if process.returncode == 0:
            if tool_name == "Naabu" and (
                not os.path.exists(output_file) or os.path.getsize(output_file) == 0
            ):
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
        if os.path.exists(targets_file_path):
            os.remove(targets_file_path)


def start_port_scan(
    targets: List[str],
    progress_obj: Optional[Progress] = None,
    main_task_id: Optional[TaskID] = None,
) -> Dict[str, Any]:
    """
    Uruchamia skanowanie portów (Faza 2).
    """
    # --- FIX: Sanityzacja celów na samym początku ---
    # Gwarantuje, że do narzędzi nie trafią adresy z http://
    targets = [_sanitize_target(t) for t in targets if t]

    utils.console.print(
        Align.center(
            f"[bold green]Rozpoczynam Fazę 2 - Skanowanie Portów "
            f"({len(targets)} celów)...[/bold green]"
        )
    )

    phase2_dir = os.path.join(config.REPORT_DIR, "faza2_porty")
    os.makedirs(phase2_dir, exist_ok=True)

    scan_results = {
        "naabu_raw": "",
        "masscan_raw": "",
        "nmap_raw": "",
        "open_ports_by_host": {},  # Zmieniono nazwę klucza, aby pasowała do shadowmap.py
        "naabu_file": "",
        "masscan_file": "",
        "nmap_files": {},
    }

    tool_flags = (
        config.selected_phase2_tools
        if not config.AUTO_MODE
        else config.silent_selected_phase2_tools
    )

    active_tools = []
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

    # 1. Skanowanie "szybkie" (Discovery)
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
            cmd = ["naabu", "-rate", str(config.NAABU_RATE), "-o", output_file]
            if config.EXCLUDED_PORTS:
                cmd.extend(
                    ["-exclude-ports", ",".join(map(str, config.EXCLUDED_PORTS))]
                )
            cmd.extend(["-top-ports", "1000"])

        elif discovery_tool == "Masscan":
            cmd = [
                "masscan",
                "-p1-65535",
                "--rate",
                str(config.MASSCAN_RATE),
                "-oG",
                output_file,
            ]
            if config.EXCLUDED_PORTS:
                excluded = ",".join(map(str, config.EXCLUDED_PORTS))
                cmd.extend(["--exclude-ports", excluded])

        utils.console.print(
            f"[bold yellow]Uruchamiam szybkie skanowanie przy użyciu {discovery_tool}...[/bold yellow]"
        )

        res_file = _run_scan_tool(
            discovery_tool, cmd, targets, output_file, config.TOOL_TIMEOUT_SECONDS
        )

        if res_file and os.path.exists(res_file):
            if discovery_tool == "Naabu":
                scan_results["naabu_file"] = res_file
            elif discovery_tool == "Masscan":
                scan_results["masscan_file"] = res_file

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

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    # 2. Skanowanie "głębokie" (Service Detection) - Nmap
    if "Nmap" in active_tools:
        nmap_strategy_override = None

        if discovery_tool:
            if not discovered_ports_map:
                utils.console.print(
                    "[bold red]Brak otwartych portów wykrytych w fazie szybkiej.[/bold red]"
                )
                if not config.AUTO_MODE and not config.QUIET_MODE:
                    # Zapytaj użytkownika o fallback
                    fallback = utils.ask_user_decision(
                        "Discovery (Masscan/Naabu) nic nie znalazło. Jak uruchomić Nmap?\n"
                        "[bold]D[/bold] - Default (Top 1000) - Szybciej\n"
                        "[bold]A[/bold] - All Ports (1-65535) - Dokładniej, ale wolno",
                        ["d", "a"],
                        "d",
                    )
                    if fallback == "a":
                        nmap_strategy_override = "all"
                        utils.console.print(
                            "[yellow]Wymuszono pełny skan Nmap (1-65535).[/yellow]"
                        )
                else:
                    utils.console.print(
                        "[yellow]Uruchamiam Nmap bezpośrednio (Strategia domyślna).[/yellow]"
                    )
            else:
                port_count = sum(len(p) for p in discovered_ports_map.values())
                utils.console.print(
                    f"[blue]Wykryto łącznie {port_count} portów. Nmap sprawdzi tylko te porty.[/blue]"
                )

        nmap_outfile = os.path.join(phase2_dir, "nmap_results.xml")
        nmap_outfile_txt = os.path.join(phase2_dir, "nmap_results.txt")
        all_detected_ports = set()

        if discovered_ports_map:
            for p_set in discovered_ports_map.values():
                all_detected_ports.update(p_set)

        # Logika wyboru portów dla Nmapa
        port_arg = ""
        cmd_additions = []
        strategy_used = "Specific Ports"

        if all_detected_ports:
            sorted_ports = sorted(list(all_detected_ports))
            port_arg = ",".join(map(str, sorted_ports))
        else:
            # SOLO MODE lub Discovery Failed
            # Ustalanie strategii: Override > Config > Default
            strategy = (
                nmap_strategy_override
                if nmap_strategy_override
                else config.NMAP_SCAN_STRATEGY
            )

            if strategy == "top1000":
                strategy_used = "Top 1000 (Default)"
                pass  # Default nmap behavior
            elif strategy == "top-ports":
                count = config.NMAP_CUSTOM_PORT_RANGE or "1000"
                cmd_additions.extend(["--top-ports", str(count)])
                strategy_used = f"Top {count}"
            elif strategy == "custom":
                if config.NMAP_CUSTOM_PORT_RANGE:
                    port_arg = config.NMAP_CUSTOM_PORT_RANGE
                    strategy_used = f"Custom: {port_arg}"
            elif strategy == "all":
                port_arg = "-"
                strategy_used = "All Ports (1-65535)"

            utils.console.print(
                f"[blue]Nmap działa samodzielnie. Strategia: {strategy_used}[/blue]"
            )

        cmd = ["nmap"]
        if config.NMAP_AGGRESSIVE_SCAN:
            cmd.append("-A")
        else:
            cmd.extend(["-sV", "-sC"])

        if config.NMAP_CUSTOM_SCRIPTS:
            cmd.extend(["--script", config.NMAP_CUSTOM_SCRIPTS])

        if port_arg:
            cmd.extend(["-p", port_arg])

        if cmd_additions:
            cmd.extend(cmd_additions)

        # Generujemy OBA formaty: XML (dla Pythona) i Normal (dla HTML Raportu)
        cmd.extend(["-oX", nmap_outfile, "-oN", nmap_outfile_txt])

        hosts_to_scan = (
            list(discovered_ports_map.keys()) if discovered_ports_map else targets
        )

        utils.console.print(
            f"[bold yellow]Uruchamiam Nmap na {len(hosts_to_scan)} hostach...[/bold yellow]"
        )

        # _run_scan_tool zwraca plik, który mu podamy (nmap_outfile), więc sprawdzamy XML
        res_file = _run_scan_tool(
            "Nmap",
            cmd,
            hosts_to_scan,
            nmap_outfile,
            config.TOOL_TIMEOUT_SECONDS * 2,
        )

        if res_file and os.path.exists(res_file):
            # 1. Parsowanie XML do logiki wewnętrznej (discovered_ports_map)
            try:
                tree = ET.parse(res_file)
                root = tree.getroot()
                ports_found_in_xml = 0
                for host in root.findall("host"):
                    status = host.find("status")
                    if status is None or status.get("state") != "up":
                        continue

                    # Próba pobrania adresu
                    host_ip = None
                    for addr in host.findall("address"):
                        if addr.get("addrtype") == "ipv4":
                            host_ip = addr.get("addr")
                            break

                    if not host_ip:
                        addr = host.find("address")
                        if addr is not None:
                            host_ip = addr.get("addr")

                    if not host_ip:
                        continue

                    ports_elem = host.find("ports")
                    if ports_elem is None:
                        continue

                    if host_ip not in discovered_ports_map:
                        discovered_ports_map[host_ip] = set()

                    for port in ports_elem.findall("port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            portid = port.get("portid")
                            if portid:
                                discovered_ports_map[host_ip].add(int(portid))
                                ports_found_in_xml += 1

                if ports_found_in_xml > 0:
                    utils.console.print(
                        f"[green]Nmap: Znaleziono {ports_found_in_xml} otwartych portów (zaktualizowano).[/green]"
                    )
                else:
                    utils.console.print(
                        f"[yellow]Nmap: Przetworzono wyniki, ale nie wykryto nowych otwartych portów.[/yellow]"
                    )

            except Exception as e:
                utils.console.print(
                    f"[red]Błąd podczas parsowania XML z Nmap: {e}[/red]"
                )

            # 2. Przygotowanie danych dla raportu HTML (wersja tekstowa/grepable)
            # Raport HTML oczekuje formatu tekstowego Nmapa, a nie XML.
            if os.path.exists(nmap_outfile_txt):
                scan_results["nmap_files"] = {"Nmap": nmap_outfile_txt}
                with open(nmap_outfile_txt, "r") as f:
                    scan_results["nmap_raw"] = f.read()
            else:
                # Fallback, jeśli z jakiegoś powodu txt nie powstał
                scan_results["nmap_files"] = {"Nmap": res_file}
                with open(res_file, "r") as f:
                    scan_results["nmap_raw"] = f.read()

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    utils.console.print(Align.center("[bold green]Faza 2 zakończona.[/bold green]"))

    final_summary = {}
    for host, ports in discovered_ports_map.items():
        final_summary[host] = sorted(list(ports))
    scan_results["open_ports_by_host"] = final_summary

    return scan_results


def display_phase2_tool_selection_menu(display_banner_func):
    """Wyświetla menu wyboru narzędzi dla Fazy 2."""
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(
                Panel.fit("[bold magenta]Faza 2: Skanowanie Portów[/bold magenta]")
            )
        )
        utils.console.print(
            Align.center(f"Cel: [bold green]{config.ORIGINAL_TARGET}[/bold green]")
        )

        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        tool_names = [
            "Naabu (Szybkie odkrywanie)",
            "Masscan (Super szybkie - wymaga root)",
            "Nmap (Wersje usług + Skrypty)",
        ]

        for i, tool_name in enumerate(tool_names):
            exe_cmd = config.TOOL_EXECUTABLE_MAP.get(tool_name)
            if "Naabu" in tool_name:
                exe_cmd = "naabu"
            if "Masscan" in tool_name:
                exe_cmd = "masscan"
            if "Nmap" in tool_name:
                exe_cmd = "nmap"

            is_missing = exe_cmd in config.MISSING_TOOLS
            status = (
                "[bold green]✓[/bold green]"
                if config.selected_phase2_tools[i]
                else "[bold red]✗[/bold red]"
            )
            display_str = f"{status} {tool_name}"
            row_style = "dim" if is_missing else ""
            if is_missing:
                display_str += " (niedostępne)"

            table.add_row(
                f"[bold cyan][{i+1}][/bold cyan]", display_str, style=row_style
            )

        table.add_section()
        table.add_row(
            "[bold cyan][\fs][/bold cyan]",
            "[bold magenta]Ustawienia Fazy 2[/bold magenta]",
        )
        table.add_row("[bold cyan][\fb][/bold cyan]", "Powrót do menu")
        table.add_row("[bold cyan][\fq][/bold cyan]", "Wyjdź")

        utils.console.print(Align.center(table))
        prompt = Text.from_markup(
            "[bold cyan]Wybierz opcję i naciśnij Enter[/bold cyan]", justify="center"
        )
        choice = utils.get_single_char_input_with_prompt(prompt)

        if choice.isdigit() and 1 <= int(choice) <= 3:
            idx = int(choice) - 1
            tool_check = tool_names[idx]
            exe_cmd = ""
            if "Naabu" in tool_check:
                exe_cmd = "naabu"
            elif "Masscan" in tool_check:
                exe_cmd = "masscan"
            elif "Nmap" in tool_check:
                exe_cmd = "nmap"

            if exe_cmd in config.MISSING_TOOLS:
                utils.console.print(Align.center("[red]Narzędzie niedostępne.[/red]"))
                time.sleep(1)
            else:
                if idx == 0:  # Naabu
                    config.selected_phase2_tools[idx] ^= 1
                    if config.selected_phase2_tools[0]:
                        config.selected_phase2_tools[1] = 0
                elif idx == 1:  # Masscan
                    config.selected_phase2_tools[idx] ^= 1
                    if config.selected_phase2_tools[1]:
                        config.selected_phase2_tools[0] = 0
                else:
                    config.selected_phase2_tools[idx] ^= 1

        elif choice.lower() == "s":
            display_phase2_settings_menu(display_banner_func)
        elif choice.lower() == "q":
            sys.exit(0)
        elif choice.lower() == "b":
            return False
        elif choice == "\r":
            if any(config.selected_phase2_tools):
                # Nowa logika: Jeśli wybrano TYLKO Nmap, zapytaj o zakres
                # Indeksy: 0=Naabu, 1=Masscan, 2=Nmap
                if config.selected_phase2_tools == [0, 0, 1]:
                    utils.console.print(
                        Align.center(
                            Panel(
                                "[bold cyan]Konfiguracja Nmap (Solo Mode)[/bold cyan]",
                                border_style="cyan",
                            )
                        )
                    )

                    choice_mode = utils.ask_user_decision(
                        "Wybierz zakres skanowania:\n"
                        "[bold]D[/bold] - Default (Top 1000)\n"
                        "[bold]T[/bold] - Top X ports\n"
                        "[bold]C[/bold] - Custom range",
                        ["d", "t", "c"],
                        "d",
                    )

                    if choice_mode == "d":
                        config.NMAP_SCAN_STRATEGY = "top1000"
                    elif choice_mode == "t":
                        config.NMAP_SCAN_STRATEGY = "top-ports"
                        val = Prompt.ask(
                            "Podaj liczbę top portów (np. 100)", default="100"
                        )
                        config.NMAP_CUSTOM_PORT_RANGE = val
                    elif choice_mode == "c":
                        config.NMAP_SCAN_STRATEGY = "custom"
                        val = Prompt.ask(
                            "Podaj zakres (np. 1-65535, 80,443)", default="1-65535"
                        )
                        config.NMAP_CUSTOM_PORT_RANGE = val

                    config.USER_CUSTOMIZED_NMAP_STRATEGY = True

                return True
            else:
                utils.console.print(
                    Align.center(
                        "[yellow]Wybierz co najmniej jedno narzędzie.[/yellow]"
                    )
                )
                time.sleep(1)


def display_phase2_settings_menu(display_banner_func):
    """Wyświetla menu ustawień dla Fazy 2."""
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 2[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        naabu_rate_disp = f"[dim]{config.NAABU_RATE}[/dim]"
        if config.USER_CUSTOMIZED_NAABU_RATE:
            naabu_rate_disp = f"[bold green]{config.NAABU_RATE}[/bold green]"

        masscan_rate_disp = f"[dim]{config.MASSCAN_RATE}[/dim]"
        if config.USER_CUSTOMIZED_MASSCAN_RATE:
            masscan_rate_disp = f"[bold green]{config.MASSCAN_RATE}[/bold green]"

        nmap_scripts = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_USE_SCRIPTS
            else "[dim]NIE[/dim]"
        )
        nmap_aggressive = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_AGGRESSIVE_SCAN
            else "[dim]NIE[/dim]"
        )

        # Wyświetlanie aktualnej strategii (dla informacji)
        strat_info = config.NMAP_SCAN_STRATEGY
        if strat_info == "top1000":
            strat_info = "Top 1000"
        elif strat_info == "top-ports":
            strat_info = f"Top {config.NMAP_CUSTOM_PORT_RANGE}"
        elif strat_info == "custom":
            strat_info = f"Custom {config.NMAP_CUSTOM_PORT_RANGE}"

        excluded_ports_str = (
            ",".join(map(str, config.EXCLUDED_PORTS))
            if config.EXCLUDED_PORTS
            else "Brak"
        )

        table.add_row(
            "[bold cyan][1][/bold cyan]", f"Rate Limit (Naabu): {naabu_rate_disp}"
        )
        table.add_row(
            "[bold cyan][2][/bold cyan]", f"Rate Limit (Masscan): {masscan_rate_disp}"
        )
        table.add_row(
            "[bold cyan][3][/bold cyan]",
            f"Nmap: Domyślne Skrypty (-sC): {nmap_scripts}",
        )
        table.add_row(
            "[bold cyan][4][/bold cyan]",
            f"Nmap: Agresywny Skan (-A): {nmap_aggressive}",
        )
        table.add_row(
            "[bold cyan][5][/bold cyan]",
            f"Własne skrypty Nmap (--script): {config.NMAP_CUSTOM_SCRIPTS or 'Brak'}",
        )
        table.add_row(
            "[bold cyan][6][/bold cyan]", f"Wykluczone porty: {excluded_ports_str}"
        )
        table.add_row("", f"[dim]Aktualna strategia Nmap (Solo): {strat_info}[/dim]")

        table.add_section()
        table.add_row("[bold cyan][\\fb][/bold cyan]", "Powrót")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text("Wybierz opcję", justify="center")
        )

        if choice == "1":
            val = Prompt.ask(
                "Podaj rate limit dla Naabu", default=str(config.NAABU_RATE)
            )
            if val.isdigit():
                config.NAABU_RATE = int(val)
                config.USER_CUSTOMIZED_NAABU_RATE = True
        elif choice == "2":
            val = Prompt.ask(
                "Podaj rate limit dla Masscan", default=str(config.MASSCAN_RATE)
            )
            if val.isdigit():
                config.MASSCAN_RATE = int(val)
                config.USER_CUSTOMIZED_MASSCAN_RATE = True
        elif choice == "3":
            config.NMAP_USE_SCRIPTS = not config.NMAP_USE_SCRIPTS
        elif choice == "4":
            config.NMAP_AGGRESSIVE_SCAN = not config.NMAP_AGGRESSIVE_SCAN
        elif choice == "5":
            val = Prompt.ask(
                "Podaj nazwy skryptów (po przecinku)",
                default=config.NMAP_CUSTOM_SCRIPTS,
            )
            config.NMAP_CUSTOM_SCRIPTS = val
            config.USER_CUSTOMIZED_NMAP_SCRIPTS = True
        elif choice == "6":
            val = Prompt.ask("Podaj porty do wykluczenia (po przecinku)", default="")
            try:
                config.EXCLUDED_PORTS = [
                    int(p.strip()) for p in val.split(",") if p.strip().isdigit()
                ]
            except ValueError:
                pass
        elif choice.lower() == "b":
            break  #!/usr/bin/env python3


import os
import re
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set

from rich.align import Align
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

import config
import utils


def _sanitize_target(target: str) -> str:
    """
    Usuwa protokół (http/https), porty i ścieżki z celu, pozostawiając domenę lub IP.
    Niezbędne dla narzędzi typu Naabu/Nmap/Masscan.
    """
    # Usuń protokół
    target = re.sub(r"^https?://", "", target)
    # Usuń wszystko po pierwszym slashu (ścieżki)
    if "/" in target:
        target = target.split("/")[0]
    # Usuń port (Nmap/Naabu/Masscan zazwyczaj wolą czysty host/IP)
    if ":" in target:
        target = target.split(":")[0]
    return target


def _resolve_to_ip(target: str) -> Optional[str]:
    """Rozwiązuje nazwę hosta na IP. Zwraca None w przypadku błędu."""
    try:
        # Jeśli target to już IP, zwróć go
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _run_scan_tool(
    tool_name: str,
    command: List[str],
    targets: List[str],
    output_file: str,
    timeout: int,
) -> Optional[str]:
    """
    Uruchamia narzędzie do skanowania portów i zapisuje wynik do pliku.
    Obsługuje przekazywanie celów przez plik tymczasowy.
    """
    # Sanityzacja celów
    clean_targets = list(set([_sanitize_target(t) for t in targets if t]))

    # --- POPRAWKA DLA MASSCANA: WYMAGA IP ---
    if tool_name == "Masscan":
        ip_targets = []
        for t in clean_targets:
            ip = _resolve_to_ip(t)
            if ip:
                ip_targets.append(ip)
            else:
                utils.log_and_echo(
                    f"Masscan: Nie udało się rozwiązać IP dla {t}", "WARN"
                )

        if not ip_targets:
            utils.console.print(
                f"[bold red]Brak poprawnych adresów IP dla Masscana![/bold red]"
            )
            return None
        targets_to_write = ip_targets
    else:
        # Dla Naabu/Nmap mogą być domeny
        targets_to_write = clean_targets

    if not targets_to_write:
        utils.console.print(
            f"[bold red]Brak poprawnych celów dla {tool_name}![/bold red]"
        )
        return None

    # Tworzenie pliku tymczasowego z celami
    with tempfile.NamedTemporaryFile(
        mode="w+", delete=False, suffix="_targets.txt"
    ) as tmp_targets:
        tmp_targets.write("\n".join(targets_to_write))
        targets_file_path = tmp_targets.name

    # Modyfikacja komendy w zależności od narzędzia
    final_command = list(command)
    sudo_prefix = []

    if tool_name in ["Naabu", "Masscan", "Nmap"] and os.geteuid() != 0:
        sudo_prefix = ["sudo"]

    if tool_name == "Naabu":
        if "-host" in final_command:
            try:
                idx = final_command.index("-host")
                final_command.pop(idx)
                if idx < len(final_command):
                    final_command.pop(idx)
            except ValueError:
                pass
        final_command.extend(["-list", targets_file_path])

    elif tool_name == "Masscan":
        final_command.extend(["-iL", targets_file_path])
        # --- FIX: Obsługa interfejsu (VPN/HTB) ---
        if config.MASSCAN_INTERFACE:
            final_command.extend(["-e", config.MASSCAN_INTERFACE])

    elif tool_name == "Nmap":
        final_command.extend(["-iL", targets_file_path])

    full_command = sudo_prefix + final_command
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in full_command)
    display_cmd = cmd_str if len(cmd_str) < 100 else cmd_str[:97] + "..."

    utils.console.print(
        f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] "
        f"[dim white]{display_cmd}[/dim white]"
    )

    process = None
    try:
        status_msg = f"[bold green]Narzędzie {tool_name} pracuje...[/bold green] [dim](Może to chwilę potrwać)[/dim]"
        with utils.console.status(status_msg, spinner="dots"):
            process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = process.communicate(timeout=timeout)

        if process.returncode == 0:
            if tool_name == "Naabu" and (
                not os.path.exists(output_file) or os.path.getsize(output_file) == 0
            ):
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
        if os.path.exists(targets_file_path):
            os.remove(targets_file_path)


def start_port_scan(
    targets: List[str],
    progress_obj: Optional[Progress] = None,
    main_task_id: Optional[TaskID] = None,
) -> Dict[str, Any]:
    """
    Uruchamia skanowanie portów (Faza 2).
    """
    targets = [_sanitize_target(t) for t in targets if t]

    utils.console.print(
        Align.center(
            f"[bold green]Rozpoczynam Fazę 2 - Skanowanie Portów "
            f"({len(targets)} celów)...[/bold green]"
        )
    )

    phase2_dir = os.path.join(config.REPORT_DIR, "faza2_porty")
    os.makedirs(phase2_dir, exist_ok=True)

    scan_results = {
        "naabu_raw": "",
        "masscan_raw": "",
        "nmap_raw": "",
        "open_ports_by_host": {},
        "naabu_file": "",
        "masscan_file": "",
        "nmap_files": {},
    }

    tool_flags = (
        config.selected_phase2_tools
        if not config.AUTO_MODE
        else config.silent_selected_phase2_tools
    )

    active_tools = []
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

    # 1. Skanowanie "szybkie" (Discovery)
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
            cmd = ["naabu", "-rate", str(config.NAABU_RATE), "-o", output_file]
            if config.EXCLUDED_PORTS:
                cmd.extend(
                    ["-exclude-ports", ",".join(map(str, config.EXCLUDED_PORTS))]
                )
            cmd.extend(["-top-ports", "1000"])

        elif discovery_tool == "Masscan":
            cmd = [
                "masscan",
                "-p1-65535",
                "--rate",
                str(config.MASSCAN_RATE),
                "--wait",
                "5",  # Dodano wait, aby upewnić się, że pakiety wrócą na VPN
                "-oG",
                output_file,
            ]
            if config.EXCLUDED_PORTS:
                excluded = ",".join(map(str, config.EXCLUDED_PORTS))
                cmd.extend(["--exclude-ports", excluded])

        utils.console.print(
            f"[bold yellow]Uruchamiam szybkie skanowanie przy użyciu {discovery_tool}...[/bold yellow]"
        )

        res_file = _run_scan_tool(
            discovery_tool, cmd, targets, output_file, config.TOOL_TIMEOUT_SECONDS
        )

        if res_file and os.path.exists(res_file):
            if discovery_tool == "Naabu":
                scan_results["naabu_file"] = res_file
            elif discovery_tool == "Masscan":
                scan_results["masscan_file"] = res_file

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
                        for line in content.splitlines():
                            if "Ports:" in line and "Host:" in line:
                                try:
                                    ip_part = (
                                        line.split("Host:")[1].split("()")[0].strip()
                                    )
                                    ports_part = line.split("Ports:")[1].strip()

                                    # --- FIX PARSERA: Obsługa wielu portów po przecinku ---
                                    # Masscan -oG może zwrócić: 80/open/..., 22/open/...
                                    for port_entry in ports_part.split(","):
                                        port_str = port_entry.strip().split("/")[0]
                                        if port_str.isdigit():
                                            if ip_part not in discovered_ports_map:
                                                discovered_ports_map[ip_part] = set()
                                            discovered_ports_map[ip_part].add(
                                                int(port_str)
                                            )
                                except Exception:
                                    continue
            except Exception as e:
                utils.console.print(
                    f"[red]Błąd parsowania wyników {discovery_tool}: {e}[/red]"
                )

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    # 2. Skanowanie "głębokie" (Service Detection) - Nmap
    if "Nmap" in active_tools:
        nmap_strategy_override = None

        if discovery_tool:
            if not discovered_ports_map:
                utils.console.print(
                    "[bold red]Brak otwartych portów wykrytych w fazie szybkiej.[/bold red]"
                )
                if not config.AUTO_MODE and not config.QUIET_MODE:
                    # Fallback dla użytkownika
                    fallback = utils.ask_user_decision(
                        "Discovery (Masscan/Naabu) nic nie znalazło. Jak uruchomić Nmap?\n"
                        "[bold]D[/bold] - Default (Top 1000) - Szybciej\n"
                        "[bold]A[/bold] - All Ports (1-65535) - Dokładniej, ale wolno",
                        ["d", "a"],
                        "d",
                    )
                    if fallback == "a":
                        nmap_strategy_override = "all"
                        utils.console.print(
                            "[yellow]Wymuszono pełny skan Nmap (1-65535).[/yellow]"
                        )
                else:
                    utils.console.print(
                        "[yellow]Uruchamiam Nmap bezpośrednio (Strategia domyślna).[/yellow]"
                    )
            else:
                port_count = sum(len(p) for p in discovered_ports_map.values())
                utils.console.print(
                    f"[blue]Wykryto łącznie {port_count} portów. Nmap sprawdzi tylko te porty.[/blue]"
                )

        nmap_outfile = os.path.join(phase2_dir, "nmap_results.xml")
        nmap_outfile_txt = os.path.join(phase2_dir, "nmap_results.txt")
        all_detected_ports = set()

        if discovered_ports_map:
            for p_set in discovered_ports_map.values():
                all_detected_ports.update(p_set)

        port_arg = ""
        cmd_additions = []
        strategy_used = "Specific Ports"

        if all_detected_ports:
            sorted_ports = sorted(list(all_detected_ports))
            port_arg = ",".join(map(str, sorted_ports))
        else:
            strategy = (
                nmap_strategy_override
                if nmap_strategy_override
                else config.NMAP_SCAN_STRATEGY
            )

            if strategy == "top1000":
                strategy_used = "Top 1000 (Default)"
                pass
            elif strategy == "top-ports":
                count = config.NMAP_CUSTOM_PORT_RANGE or "1000"
                cmd_additions.extend(["--top-ports", str(count)])
                strategy_used = f"Top {count}"
            elif strategy == "custom":
                if config.NMAP_CUSTOM_PORT_RANGE:
                    port_arg = config.NMAP_CUSTOM_PORT_RANGE
                    strategy_used = f"Custom: {port_arg}"
            elif strategy == "all":
                port_arg = "-"
                strategy_used = "All Ports (1-65535)"

            utils.console.print(
                f"[blue]Nmap działa samodzielnie. Strategia: {strategy_used}[/blue]"
            )

        cmd = ["nmap"]
        if config.NMAP_AGGRESSIVE_SCAN:
            cmd.append("-A")
        else:
            cmd.extend(["-sV", "-sC"])

        if config.NMAP_CUSTOM_SCRIPTS:
            cmd.extend(["--script", config.NMAP_CUSTOM_SCRIPTS])

        if port_arg:
            cmd.extend(["-p", port_arg])

        if cmd_additions:
            cmd.extend(cmd_additions)

        cmd.extend(["-oX", nmap_outfile, "-oN", nmap_outfile_txt])

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
            config.TOOL_TIMEOUT_SECONDS * 2,
        )

        if res_file and os.path.exists(res_file):
            try:
                tree = ET.parse(res_file)
                root = tree.getroot()
                ports_found_in_xml = 0
                for host in root.findall("host"):
                    status = host.find("status")
                    if status is None or status.get("state") != "up":
                        continue

                    host_ip = None
                    for addr in host.findall("address"):
                        if addr.get("addrtype") == "ipv4":
                            host_ip = addr.get("addr")
                            break

                    if not host_ip:
                        addr = host.find("address")
                        if addr is not None:
                            host_ip = addr.get("addr")

                    if not host_ip:
                        continue

                    ports_elem = host.find("ports")
                    if ports_elem is None:
                        continue

                    if host_ip not in discovered_ports_map:
                        discovered_ports_map[host_ip] = set()

                    for port in ports_elem.findall("port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            portid = port.get("portid")
                            if portid:
                                discovered_ports_map[host_ip].add(int(portid))
                                ports_found_in_xml += 1

                if ports_found_in_xml > 0:
                    utils.console.print(
                        f"[green]Nmap: Znaleziono {ports_found_in_xml} otwartych portów (zaktualizowano).[/green]"
                    )
                else:
                    utils.console.print(
                        f"[yellow]Nmap: Przetworzono wyniki, ale nie wykryto nowych otwartych portów.[/yellow]"
                    )

            except Exception as e:
                utils.console.print(
                    f"[red]Błąd podczas parsowania XML z Nmap: {e}[/red]"
                )

            if os.path.exists(nmap_outfile_txt):
                scan_results["nmap_files"] = {"Nmap": nmap_outfile_txt}
                with open(nmap_outfile_txt, "r") as f:
                    scan_results["nmap_raw"] = f.read()
            else:
                scan_results["nmap_files"] = {"Nmap": res_file}
                with open(res_file, "r") as f:
                    scan_results["nmap_raw"] = f.read()

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    utils.console.print(Align.center("[bold green]Faza 2 zakończona.[/bold green]"))

    final_summary = {}
    for host, ports in discovered_ports_map.items():
        final_summary[host] = sorted(list(ports))
    scan_results["open_ports_by_host"] = final_summary

    return scan_results


def display_phase2_settings_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 2[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        naabu_rate_disp = f"[dim]{config.NAABU_RATE}[/dim]"
        if config.USER_CUSTOMIZED_NAABU_RATE:
            naabu_rate_disp = f"[bold green]{config.NAABU_RATE}[/bold green]"

        masscan_rate_disp = f"[dim]{config.MASSCAN_RATE}[/dim]"
        if config.USER_CUSTOMIZED_MASSCAN_RATE:
            masscan_rate_disp = f"[bold green]{config.MASSCAN_RATE}[/bold green]"

        nmap_scripts = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_USE_SCRIPTS
            else "[dim]NIE[/dim]"
        )
        nmap_aggressive = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_AGGRESSIVE_SCAN
            else "[dim]NIE[/dim]"
        )

        strat_info = config.NMAP_SCAN_STRATEGY
        if strat_info == "top1000":
            strat_info = "Top 1000"
        elif strat_info == "top-ports":
            strat_info = f"Top {config.NMAP_CUSTOM_PORT_RANGE}"
        elif strat_info == "custom":
            strat_info = f"Custom {config.NMAP_CUSTOM_PORT_RANGE}"

        excluded_ports_str = (
            ",".join(map(str, config.EXCLUDED_PORTS))
            if config.EXCLUDED_PORTS
            else "Brak"
        )

        masscan_iface_disp = (
            config.MASSCAN_INTERFACE if config.MASSCAN_INTERFACE else "[dim]Auto[/dim]"
        )

        table.add_row(
            "[bold cyan][1][/bold cyan]", f"Rate Limit (Naabu): {naabu_rate_disp}"
        )
        table.add_row(
            "[bold cyan][2][/bold cyan]", f"Rate Limit (Masscan): {masscan_rate_disp}"
        )
        table.add_row(
            "[bold cyan][3][/bold cyan]",
            f"Nmap: Domyślne Skrypty (-sC): {nmap_scripts}",
        )
        table.add_row(
            "[bold cyan][4][/bold cyan]",
            f"Nmap: Agresywny Skan (-A): {nmap_aggressive}",
        )
        table.add_row(
            "[bold cyan][5][/bold cyan]",
            f"Własne skrypty Nmap (--script): {config.NMAP_CUSTOM_SCRIPTS or 'Brak'}",
        )
        table.add_row(
            "[bold cyan][6][/bold cyan]", f"Wykluczone porty: {excluded_ports_str}"
        )
        # --- NOWA OPCJA W MENU ---
        table.add_row(
            "[bold cyan][7][/bold cyan]",
            f"Interfejs Masscan (-e): {masscan_iface_disp}",
        )
        table.add_row("", f"[dim]Aktualna strategia Nmap (Solo): {strat_info}[/dim]")

        table.add_section()
        table.add_row("[bold cyan][\\fb][/bold cyan]", "Powrót")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text("Wybierz opcję", justify="center")
        )

        if choice == "1":
            val = Prompt.ask(
                "Podaj rate limit dla Naabu", default=str(config.NAABU_RATE)
            )
            if val.isdigit():
                config.NAABU_RATE = int(val)
                config.USER_CUSTOMIZED_NAABU_RATE = True
        elif choice == "2":
            val = Prompt.ask(
                "Podaj rate limit dla Masscan", default=str(config.MASSCAN_RATE)
            )
            if val.isdigit():
                config.MASSCAN_RATE = int(val)
                config.USER_CUSTOMIZED_MASSCAN_RATE = True
        elif choice == "3":
            config.NMAP_USE_SCRIPTS = not config.NMAP_USE_SCRIPTS
        elif choice == "4":
            config.NMAP_AGGRESSIVE_SCAN = not config.NMAP_AGGRESSIVE_SCAN
        elif choice == "5":
            val = Prompt.ask(
                "Podaj nazwy skryptów (po przecinku)",
                default=config.NMAP_CUSTOM_SCRIPTS,
            )
            config.NMAP_CUSTOM_SCRIPTS = val
            config.USER_CUSTOMIZED_NMAP_SCRIPTS = True
        elif choice == "6":
            val = Prompt.ask("Podaj porty do wykluczenia (po przecinku)", default="")
            try:
                config.EXCLUDED_PORTS = [
                    int(p.strip()) for p in val.split(",") if p.strip().isdigit()
                ]
            except ValueError:
                pass
        elif choice == "7":
            val = Prompt.ask(
                "Podaj interfejs sieciowy (np. tun0, eth0) lub puste dla auto",
                default="",
            )
            config.MASSCAN_INTERFACE = val if val.strip() else None
            config.USER_CUSTOMIZED_MASSCAN_INTERFACE = True
        elif choice.lower() == "b":
            break
#!/usr/bin/env python3

import os
import re
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set

# Imports for IP retrieval (Linux specific)
try:
    import fcntl
    import struct
except ImportError:
    pass

from rich.align import Align
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

import config
import utils


def _get_interface_ip(ifname: str) -> Optional[str]:
    """
    Pobiera adres IP dla danego interfejsu sieciowego (Linux).
    Wymagane dla Masscana na tun0, aby poprawnie routował pakiety.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        return None


def _sanitize_target(target: str) -> str:
    """
    Usuwa protokół (http/https), porty i ścieżki z celu, pozostawiając domenę lub IP.
    Niezbędne dla narzędzi typu Naabu/Nmap/Masscan.
    """
    # Usuń protokół
    target = re.sub(r"^https?://", "", target)
    # Usuń wszystko po pierwszym slashu (ścieżki)
    if "/" in target:
        target = target.split("/")[0]
    # Usuń port (Nmap/Naabu/Masscan zazwyczaj wolą czysty host/IP)
    if ":" in target:
        target = target.split(":")[0]
    return target


def _resolve_to_ip(target: str) -> Optional[str]:
    """Rozwiązuje nazwę hosta na IP. Zwraca None w przypadku błędu."""
    try:
        # Jeśli target to już IP, zwróć go
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _run_scan_tool(
    tool_name: str,
    command: List[str],
    targets: List[str],
    output_file: str,
    timeout: int,
) -> Optional[str]:
    """
    Uruchamia narzędzie do skanowania portów i zapisuje wynik do pliku.
    Obsługuje przekazywanie celów przez plik tymczasowy.
    """
    # Sanityzacja celów
    clean_targets = list(set([_sanitize_target(t) for t in targets if t]))

    # --- KONFIGURACJA MASSCANA ---
    if tool_name == "Masscan":
        ip_targets = []
        for t in clean_targets:
            ip = _resolve_to_ip(t)
            if ip:
                ip_targets.append(ip)
            else:
                utils.log_and_echo(
                    f"Masscan: Nie udało się rozwiązać IP dla {t}", "WARN"
                )

        if not ip_targets:
            utils.console.print(
                f"[bold red]Brak poprawnych adresów IP dla Masscana![/bold red]"
            )
            return None
        targets_to_write = ip_targets
    else:
        # Dla Naabu/Nmap mogą być domeny
        targets_to_write = clean_targets

    if not targets_to_write:
        utils.console.print(
            f"[bold red]Brak poprawnych celów dla {tool_name}![/bold red]"
        )
        return None

    # Tworzenie pliku tymczasowego z celami
    with tempfile.NamedTemporaryFile(
        mode="w+", delete=False, suffix="_targets.txt"
    ) as tmp_targets:
        tmp_targets.write("\n".join(targets_to_write))
        targets_file_path = tmp_targets.name

    # Modyfikacja komendy w zależności od narzędzia
    final_command = list(command)
    sudo_prefix = []

    if tool_name in ["Naabu", "Masscan", "Nmap"] and os.geteuid() != 0:
        sudo_prefix = ["sudo"]

    if tool_name == "Naabu":
        if "-host" in final_command:
            try:
                idx = final_command.index("-host")
                final_command.pop(idx)
                if idx < len(final_command):
                    final_command.pop(idx)
            except ValueError:
                pass
        final_command.extend(["-list", targets_file_path])

    elif tool_name == "Masscan":
        final_command.extend(["-iL", targets_file_path])
        
        # --- AUTO-FIX DLA VPN/CTF ---
        interface_to_use = config.MASSCAN_INTERFACE
        
        # 1. Jeśli nie podano interfejsu, spróbuj wykryć tun0 (standard HTB/THM)
        if not interface_to_use:
            if os.path.exists('/sys/class/net/tun0'):
                interface_to_use = 'tun0'
                utils.console.print("[dim blue]Auto-wykryto interfejs VPN: tun0[/dim blue]")
        
        # 2. Jeśli mamy interfejs, dodaj go ORAZ pobierz jego IP dla --src-ip
        if interface_to_use:
            # Sprawdź czy flaga -e już nie została dodana ręcznie przez usera w configu (mało prawdopodobne, ale bezpieczne)
            if "-e" not in final_command:
                final_command.extend(["-e", interface_to_use])
            
            # Kluczowy fix: Masscan na tun0 często potrzebuje jawnego source-ip
            try:
                src_ip = _get_interface_ip(interface_to_use)
                if src_ip:
                    final_command.extend(["--src-ip", src_ip])
                    utils.console.print(f"[dim blue]Masscan Source IP fix: {src_ip}[/dim blue]")
            except Exception as e:
                utils.log_and_echo(f"Nie udało się pobrać IP dla {interface_to_use}: {e}", "DEBUG")

    elif tool_name == "Nmap":
        final_command.extend(["-iL", targets_file_path])

    full_command = sudo_prefix + final_command
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in full_command)
    display_cmd = cmd_str if len(cmd_str) < 100 else cmd_str[:97] + "..."

    utils.console.print(
        f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] "
        f"[dim white]{display_cmd}[/dim white]"
    )

    process = None
    try:
        status_msg = f"[bold green]Narzędzie {tool_name} pracuje...[/bold green] [dim](Może to chwilę potrwać)[/dim]"
        with utils.console.status(status_msg, spinner="dots"):
            process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = process.communicate(timeout=timeout)

        if process.returncode == 0:
            if tool_name == "Naabu" and (
                not os.path.exists(output_file) or os.path.getsize(output_file) == 0
            ):
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
        if os.path.exists(targets_file_path):
            os.remove(targets_file_path)


def start_port_scan(
    targets: List[str],
    progress_obj: Optional[Progress] = None,
    main_task_id: Optional[TaskID] = None,
) -> Dict[str, Any]:
    """
    Uruchamia skanowanie portów (Faza 2).
    """
    targets = [_sanitize_target(t) for t in targets if t]

    utils.console.print(
        Align.center(
            f"[bold green]Rozpoczynam Fazę 2 - Skanowanie Portów "
            f"({len(targets)} celów)...[/bold green]"
        )
    )

    phase2_dir = os.path.join(config.REPORT_DIR, "faza2_porty")
    os.makedirs(phase2_dir, exist_ok=True)

    scan_results = {
        "naabu_raw": "",
        "masscan_raw": "",
        "nmap_raw": "",
        "open_ports_by_host": {},
        "naabu_file": "",
        "masscan_file": "",
        "nmap_files": {},
    }

    tool_flags = (
        config.selected_phase2_tools
        if not config.AUTO_MODE
        else config.silent_selected_phase2_tools
    )

    active_tools = []
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

    # 1. Skanowanie "szybkie" (Discovery)
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
            cmd = ["naabu", "-rate", str(config.NAABU_RATE), "-o", output_file]
            if config.EXCLUDED_PORTS:
                cmd.extend(
                    ["-exclude-ports", ",".join(map(str, config.EXCLUDED_PORTS))]
                )
            cmd.extend(["-top-ports", "1000"])

        elif discovery_tool == "Masscan":
            cmd = [
                "masscan",
                "-p1-65535",
                "--rate",
                str(config.MASSCAN_RATE),
                "--wait", "5",  # Czekaj na powrót pakietów (ważne przy VPN)
                "-oG",
                output_file,
            ]
            if config.EXCLUDED_PORTS:
                excluded = ",".join(map(str, config.EXCLUDED_PORTS))
                cmd.extend(["--exclude-ports", excluded])

        utils.console.print(
            f"[bold yellow]Uruchamiam szybkie skanowanie przy użyciu {discovery_tool}...[/bold yellow]"
        )

        res_file = _run_scan_tool(
            discovery_tool, cmd, targets, output_file, config.TOOL_TIMEOUT_SECONDS
        )

        if res_file and os.path.exists(res_file):
            if discovery_tool == "Naabu":
                scan_results["naabu_file"] = res_file
            elif discovery_tool == "Masscan":
                scan_results["masscan_file"] = res_file

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
                        for line in content.splitlines():
                            if "Ports:" in line and "Host:" in line:
                                try:
                                    # Format: Host: 10.10.11.82 ()	Ports: 80/open/tcp//http//, 22/open/tcp//ssh//
                                    ip_part = line.split("Host:")[1].split("()")[0].strip()
                                    ports_part = line.split("Ports:")[1].strip()
                                    
                                    # Obsługa wielu portów po przecinku
                                    for port_entry in ports_part.split(","):
                                        port_str = port_entry.strip().split("/")[0]
                                        if port_str.isdigit():
                                            if ip_part not in discovered_ports_map:
                                                discovered_ports_map[ip_part] = set()
                                            discovered_ports_map[ip_part].add(int(port_str))
                                except Exception:
                                    continue
            except Exception as e:
                utils.console.print(
                    f"[red]Błąd parsowania wyników {discovery_tool}: {e}[/red]"
                )

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    # 2. Skanowanie "głębokie" (Service Detection) - Nmap
    if "Nmap" in active_tools:
        nmap_strategy_override = None
        
        if discovery_tool:
            if not discovered_ports_map:
                utils.console.print(
                    "[bold red]Brak otwartych portów wykrytych w fazie szybkiej.[/bold red]"
                )
                if not config.AUTO_MODE and not config.QUIET_MODE:
                    # Fallback dla użytkownika
                    fallback = utils.ask_user_decision(
                        "Discovery (Masscan/Naabu) nic nie znalazło. Jak uruchomić Nmap?\n"
                        "[bold]D[/bold] - Default (Top 1000) - Szybciej\n"
                        "[bold]A[/bold] - All Ports (1-65535) - Dokładniej, ale wolno",
                        ["d", "a"],
                        "d"
                    )
                    if fallback == "a":
                        nmap_strategy_override = "all"
                        utils.console.print("[yellow]Wymuszono pełny skan Nmap (1-65535).[/yellow]")
                else:
                    utils.console.print(
                        "[yellow]Uruchamiam Nmap bezpośrednio (Strategia domyślna).[/yellow]"
                    )
            else:
                port_count = sum(len(p) for p in discovered_ports_map.values())
                utils.console.print(
                    f"[blue]Wykryto łącznie {port_count} portów. Nmap sprawdzi tylko te porty.[/blue]"
                )

        nmap_outfile = os.path.join(phase2_dir, "nmap_results.xml")
        nmap_outfile_txt = os.path.join(phase2_dir, "nmap_results.txt")
        all_detected_ports = set()

        if discovered_ports_map:
            for p_set in discovered_ports_map.values():
                all_detected_ports.update(p_set)
        
        port_arg = ""
        cmd_additions = []
        strategy_used = "Specific Ports"

        if all_detected_ports:
            sorted_ports = sorted(list(all_detected_ports))
            port_arg = ",".join(map(str, sorted_ports))
        else:
            strategy = nmap_strategy_override if nmap_strategy_override else config.NMAP_SCAN_STRATEGY
            
            if strategy == "top1000":
                strategy_used = "Top 1000 (Default)"
                pass
            elif strategy == "top-ports":
                count = config.NMAP_CUSTOM_PORT_RANGE or "1000"
                cmd_additions.extend(["--top-ports", str(count)])
                strategy_used = f"Top {count}"
            elif strategy == "custom":
                if config.NMAP_CUSTOM_PORT_RANGE:
                    port_arg = config.NMAP_CUSTOM_PORT_RANGE
                    strategy_used = f"Custom: {port_arg}"
            elif strategy == "all":
                port_arg = "-"
                strategy_used = "All Ports (1-65535)"

            utils.console.print(
                f"[blue]Nmap działa samodzielnie. Strategia: {strategy_used}[/blue]"
            )

        cmd = ["nmap"]
        if config.NMAP_AGGRESSIVE_SCAN:
            cmd.append("-A")
        else:
            cmd.extend(["-sV", "-sC"])

        if config.NMAP_CUSTOM_SCRIPTS:
            cmd.extend(["--script", config.NMAP_CUSTOM_SCRIPTS])

        if port_arg:
            cmd.extend(["-p", port_arg])

        if cmd_additions:
            cmd.extend(cmd_additions)

        cmd.extend(["-oX", nmap_outfile, "-oN", nmap_outfile_txt])

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
            config.TOOL_TIMEOUT_SECONDS * 2,
        )

        if res_file and os.path.exists(res_file):
            try:
                tree = ET.parse(res_file)
                root = tree.getroot()
                ports_found_in_xml = 0
                for host in root.findall("host"):
                    status = host.find("status")
                    if status is None or status.get("state") != "up":
                        continue

                    host_ip = None
                    for addr in host.findall("address"):
                        if addr.get("addrtype") == "ipv4":
                            host_ip = addr.get("addr")
                            break
                    
                    if not host_ip:
                         addr = host.find("address")
                         if addr is not None:
                             host_ip = addr.get("addr")

                    if not host_ip:
                        continue

                    ports_elem = host.find("ports")
                    if ports_elem is None:
                        continue

                    if host_ip not in discovered_ports_map:
                        discovered_ports_map[host_ip] = set()

                    for port in ports_elem.findall("port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            portid = port.get("portid")
                            if portid:
                                discovered_ports_map[host_ip].add(int(portid))
                                ports_found_in_xml += 1
                
                if ports_found_in_xml > 0:
                    utils.console.print(f"[green]Nmap: Znaleziono {ports_found_in_xml} otwartych portów (zaktualizowano).[/green]")
                else:
                    utils.console.print(f"[yellow]Nmap: Przetworzono wyniki, ale nie wykryto nowych otwartych portów.[/yellow]")

            except Exception as e:
                utils.console.print(
                    f"[red]Błąd podczas parsowania XML z Nmap: {e}[/red]"
                )

            if os.path.exists(nmap_outfile_txt):
                scan_results["nmap_files"] = {"Nmap": nmap_outfile_txt}
                with open(nmap_outfile_txt, "r") as f:
                    scan_results["nmap_raw"] = f.read()
            else:
                scan_results["nmap_files"] = {"Nmap": res_file}
                with open(res_file, "r") as f:
                    scan_results["nmap_raw"] = f.read()

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    utils.console.print(Align.center("[bold green]Faza 2 zakończona.[/bold green]"))

    final_summary = {}
    for host, ports in discovered_ports_map.items():
        final_summary[host] = sorted(list(ports))
    scan_results["open_ports_by_host"] = final_summary

    return scan_results


def display_phase2_settings_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 2[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        naabu_rate_disp = f"[dim]{config.NAABU_RATE}[/dim]"
        if config.USER_CUSTOMIZED_NAABU_RATE:
            naabu_rate_disp = f"[bold green]{config.NAABU_RATE}[/bold green]"

        masscan_rate_disp = f"[dim]{config.MASSCAN_RATE}[/dim]"
        if config.USER_CUSTOMIZED_MASSCAN_RATE:
            masscan_rate_disp = f"[bold green]{config.MASSCAN_RATE}[/bold green]"

        nmap_scripts = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_USE_SCRIPTS
            else "[dim]NIE[/dim]"
        )
        nmap_aggressive = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_AGGRESSIVE_SCAN
            else "[dim]NIE[/dim]"
        )

        strat_info = config.NMAP_SCAN_STRATEGY
        if strat_info == "top1000":
            strat_info = "Top 1000"
        elif strat_info == "top-ports":
            strat_info = f"Top {config.NMAP_CUSTOM_PORT_RANGE}"
        elif strat_info == "custom":
            strat_info = f"Custom {config.NMAP_CUSTOM_PORT_RANGE}"

        excluded_ports_str = (
            ",".join(map(str, config.EXCLUDED_PORTS))
            if config.EXCLUDED_PORTS
            else "Brak"
        )
        
        masscan_iface_disp = config.MASSCAN_INTERFACE if config.MASSCAN_INTERFACE else "[dim]Auto (tun0 prio)[/dim]"

        table.add_row(
            "[bold cyan][1][/bold cyan]", f"Rate Limit (Naabu): {naabu_rate_disp}"
        )
        table.add_row(
            "[bold cyan][2][/bold cyan]", f"Rate Limit (Masscan): {masscan_rate_disp}"
        )
        table.add_row(
            "[bold cyan][3][/bold cyan]",
            f"Nmap: Domyślne Skrypty (-sC): {nmap_scripts}",
        )
        table.add_row(
            "[bold cyan][4][/bold cyan]",
            f"Nmap: Agresywny Skan (-A): {nmap_aggressive}",
        )
        table.add_row(
            "[bold cyan][5][/bold cyan]",
            f"Własne skrypty Nmap (--script): {config.NMAP_CUSTOM_SCRIPTS or 'Brak'}",
        )
        table.add_row(
            "[bold cyan][6][/bold cyan]", f"Wykluczone porty: {excluded_ports_str}"
        )
        # --- OPCJA W MENU ---
        table.add_row(
            "[bold cyan][7][/bold cyan]", f"Interfejs Masscan (-e): {masscan_iface_disp}"
        )
        table.add_row("", f"[dim]Aktualna strategia Nmap (Solo): {strat_info}[/dim]")

        table.add_section()
        table.add_row("[bold cyan][\\fb][/bold cyan]", "Powrót")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text("Wybierz opcję", justify="center")
        )

        if choice == "1":
            val = Prompt.ask(
                "Podaj rate limit dla Naabu", default=str(config.NAABU_RATE)
            )
            if val.isdigit():
                config.NAABU_RATE = int(val)
                config.USER_CUSTOMIZED_NAABU_RATE = True
        elif choice == "2":
            val = Prompt.ask(
                "Podaj rate limit dla Masscan", default=str(config.MASSCAN_RATE)
            )
            if val.isdigit():
                config.MASSCAN_RATE = int(val)
                config.USER_CUSTOMIZED_MASSCAN_RATE = True
        elif choice == "3":
            config.NMAP_USE_SCRIPTS = not config.NMAP_USE_SCRIPTS
        elif choice == "4":
            config.NMAP_AGGRESSIVE_SCAN = not config.NMAP_AGGRESSIVE_SCAN
        elif choice == "5":
            val = Prompt.ask(
                "Podaj nazwy skryptów (po przecinku)",
                default=config.NMAP_CUSTOM_SCRIPTS,
            )
            config.NMAP_CUSTOM_SCRIPTS = val
            config.USER_CUSTOMIZED_NMAP_SCRIPTS = True
        elif choice == "6":
            val = Prompt.ask("Podaj porty do wykluczenia (po przecinku)", default="")
            try:
                config.EXCLUDED_PORTS = [
                    int(p.strip()) for p in val.split(",") if p.strip().isdigit()
                ]
            except ValueError:
                pass
        elif choice == "7":
            val = Prompt.ask("Podaj interfejs sieciowy (np. tun0, eth0) lub puste dla auto", default="")
            config.MASSCAN_INTERFACE = val if val.strip() else None
            config.USER_CUSTOMIZED_MASSCAN_INTERFACE = True
        elif choice.lower() == "b":
            break#!/usr/bin/env python3

import os
import re
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set

# Importy do pobierania IP interfejsu (specyficzne dla Linuxa)
try:
    import fcntl
    import struct
except ImportError:
    pass

from rich.align import Align
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

import config
import utils


def _get_interface_ip(ifname: str) -> Optional[str]:
    """
    Pobiera adres IP dla danego interfejsu sieciowego (Linux).
    Wymagane dla Masscana na tun0, aby poprawnie routował pakiety.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 0x8915 to SIOCGIFADDR
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        return None


def _sanitize_target(target: str) -> str:
    """
    Usuwa protokół (http/https), porty i ścieżki z celu, pozostawiając domenę lub IP.
    Niezbędne dla narzędzi typu Naabu/Nmap/Masscan.
    """
    # Usuń protokół
    target = re.sub(r"^https?://", "", target)
    # Usuń wszystko po pierwszym slashu (ścieżki)
    if "/" in target:
        target = target.split("/")[0]
    # Usuń port (Nmap/Naabu/Masscan zazwyczaj wolą czysty host/IP)
    if ":" in target:
        target = target.split(":")[0]
    return target


def _resolve_to_ip(target: str) -> Optional[str]:
    """Rozwiązuje nazwę hosta na IP. Zwraca None w przypadku błędu."""
    try:
        # Jeśli target to już IP, zwróć go
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _run_scan_tool(
    tool_name: str,
    command: List[str],
    targets: List[str],
    output_file: str,
    timeout: int,
) -> Optional[str]:
    """
    Uruchamia narzędzie do skanowania portów i zapisuje wynik do pliku.
    Obsługuje przekazywanie celów przez plik tymczasowy.
    """
    # Sanityzacja celów
    clean_targets = list(set([_sanitize_target(t) for t in targets if t]))

    # --- KONFIGURACJA MASSCANA ---
    if tool_name == "Masscan":
        ip_targets = []
        for t in clean_targets:
            ip = _resolve_to_ip(t)
            if ip:
                ip_targets.append(ip)
            else:
                utils.log_and_echo(
                    f"Masscan: Nie udało się rozwiązać IP dla {t}", "WARN"
                )

        if not ip_targets:
            utils.console.print(
                f"[bold red]Brak poprawnych adresów IP dla Masscana![/bold red]"
            )
            return None
        targets_to_write = ip_targets
    else:
        # Dla Naabu/Nmap mogą być domeny
        targets_to_write = clean_targets

    if not targets_to_write:
        utils.console.print(
            f"[bold red]Brak poprawnych celów dla {tool_name}![/bold red]"
        )
        return None

    # Tworzenie pliku tymczasowego z celami
    with tempfile.NamedTemporaryFile(
        mode="w+", delete=False, suffix="_targets.txt"
    ) as tmp_targets:
        tmp_targets.write("\n".join(targets_to_write))
        targets_file_path = tmp_targets.name

    # Modyfikacja komendy w zależności od narzędzia
    final_command = list(command)
    sudo_prefix = []

    if tool_name in ["Naabu", "Masscan", "Nmap"] and os.geteuid() != 0:
        sudo_prefix = ["sudo"]

    if tool_name == "Naabu":
        if "-host" in final_command:
            try:
                idx = final_command.index("-host")
                final_command.pop(idx)
                if idx < len(final_command):
                    final_command.pop(idx)
            except ValueError:
                pass
        final_command.extend(["-list", targets_file_path])

    elif tool_name == "Masscan":
        final_command.extend(["-iL", targets_file_path])
        
        # --- AUTO-FIX DLA VPN/CTF (MANDATORY FIX) ---
        interface_to_use = getattr(config, 'MASSCAN_INTERFACE', None)
        
        # 1. Jeśli nie podano interfejsu w configu, spróbuj wykryć tun0 (standard HTB/THM)
        if not interface_to_use:
            if os.path.exists('/sys/class/net/tun0'):
                interface_to_use = 'tun0'
                # Logujemy to dyskretnie, żeby użytkownik wiedział
                if not config.QUIET_MODE:
                    utils.console.print("[dim blue]Info: Auto-wykryto interfejs VPN (tun0). Konfiguruję Masscan...[/dim blue]")
        
        # 2. Jeśli mamy interfejs, dodaj go ORAZ pobierz jego IP dla --src-ip
        if interface_to_use:
            # Dodaj flagę -e jeśli jej nie ma
            if "-e" not in final_command:
                final_command.extend(["-e", interface_to_use])
            
            # Kluczowy fix: Masscan na tun0 potrzebuje jawnego source-ip
            try:
                src_ip = _get_interface_ip(interface_to_use)
                if src_ip:
                    final_command.extend(["--src-ip", src_ip])
            except Exception as e:
                utils.log_and_echo(f"Nie udało się pobrać IP dla {interface_to_use}: {e}", "DEBUG")

    elif tool_name == "Nmap":
        final_command.extend(["-iL", targets_file_path])

    full_command = sudo_prefix + final_command
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in full_command)
    display_cmd = cmd_str if len(cmd_str) < 100 else cmd_str[:97] + "..."

    utils.console.print(
        f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] "
        f"[dim white]{display_cmd}[/dim white]"
    )

    process = None
    try:
        status_msg = f"[bold green]Narzędzie {tool_name} pracuje...[/bold green] [dim](Może to chwilę potrwać)[/dim]"
        with utils.console.status(status_msg, spinner="dots"):
            process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = process.communicate(timeout=timeout)

        if process.returncode == 0:
            if tool_name == "Naabu" and (
                not os.path.exists(output_file) or os.path.getsize(output_file) == 0
            ):
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
        if os.path.exists(targets_file_path):
            os.remove(targets_file_path)


def start_port_scan(
    targets: List[str],
    progress_obj: Optional[Progress] = None,
    main_task_id: Optional[TaskID] = None,
) -> Dict[str, Any]:
    """
    Uruchamia skanowanie portów (Faza 2).
    """
    targets = [_sanitize_target(t) for t in targets if t]

    utils.console.print(
        Align.center(
            f"[bold green]Rozpoczynam Fazę 2 - Skanowanie Portów "
            f"({len(targets)} celów)...[/bold green]"
        )
    )

    phase2_dir = os.path.join(config.REPORT_DIR, "faza2_porty")
    os.makedirs(phase2_dir, exist_ok=True)

    scan_results = {
        "naabu_raw": "",
        "masscan_raw": "",
        "nmap_raw": "",
        "open_ports_by_host": {},
        "naabu_file": "",
        "masscan_file": "",
        "nmap_files": {},
    }

    tool_flags = (
        config.selected_phase2_tools
        if not config.AUTO_MODE
        else config.silent_selected_phase2_tools
    )

    active_tools = []
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

    # 1. Skanowanie "szybkie" (Discovery)
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
            cmd = ["naabu", "-rate", str(config.NAABU_RATE), "-o", output_file]
            if config.EXCLUDED_PORTS:
                cmd.extend(
                    ["-exclude-ports", ",".join(map(str, config.EXCLUDED_PORTS))]
                )
            cmd.extend(["-top-ports", "1000"])

        elif discovery_tool == "Masscan":
            cmd = [
                "masscan",
                "-p1-65535",
                "--rate",
                str(config.MASSCAN_RATE),
                "--wait", "5",
                "-oG",
                output_file,
            ]
            if config.EXCLUDED_PORTS:
                excluded = ",".join(map(str, config.EXCLUDED_PORTS))
                cmd.extend(["--exclude-ports", excluded])

        utils.console.print(
            f"[bold yellow]Uruchamiam szybkie skanowanie przy użyciu {discovery_tool}...[/bold yellow]"
        )

        res_file = _run_scan_tool(
            discovery_tool, cmd, targets, output_file, config.TOOL_TIMEOUT_SECONDS
        )

        if res_file and os.path.exists(res_file):
            if discovery_tool == "Naabu":
                scan_results["naabu_file"] = res_file
            elif discovery_tool == "Masscan":
                scan_results["masscan_file"] = res_file

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
                        for line in content.splitlines():
                            if "Ports:" in line and "Host:" in line:
                                try:
                                    ip_part = line.split("Host:")[1].split("()")[0].strip()
                                    ports_part = line.split("Ports:")[1].strip()
                                    
                                    # Obsługa wielu portów po przecinku (fix dla formatu -oG)
                                    for port_entry in ports_part.split(","):
                                        port_str = port_entry.strip().split("/")[0]
                                        if port_str.isdigit():
                                            if ip_part not in discovered_ports_map:
                                                discovered_ports_map[ip_part] = set()
                                            discovered_ports_map[ip_part].add(int(port_str))
                                except Exception:
                                    continue
            except Exception as e:
                utils.console.print(
                    f"[red]Błąd parsowania wyników {discovery_tool}: {e}[/red]"
                )

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    # 2. Skanowanie "głębokie" (Service Detection) - Nmap
    if "Nmap" in active_tools:
        nmap_strategy_override = None
        
        if discovery_tool:
            if not discovered_ports_map:
                utils.console.print(
                    "[bold red]Brak otwartych portów wykrytych w fazie szybkiej.[/bold red]"
                )
                if not config.AUTO_MODE and not config.QUIET_MODE:
                    fallback = utils.ask_user_decision(
                        "Discovery (Masscan/Naabu) nic nie znalazło. Jak uruchomić Nmap?\n"
                        "[bold]D[/bold] - Default (Top 1000)\n"
                        "[bold]A[/bold] - All Ports (1-65535) - Wolno",
                        ["d", "a"],
                        "d"
                    )
                    if fallback == "a":
                        nmap_strategy_override = "all"
                        utils.console.print("[yellow]Wymuszono pełny skan Nmap (1-65535).[/yellow]")
                else:
                    utils.console.print(
                        "[yellow]Uruchamiam Nmap bezpośrednio (Strategia domyślna).[/yellow]"
                    )
            else:
                port_count = sum(len(p) for p in discovered_ports_map.values())
                utils.console.print(
                    f"[blue]Wykryto łącznie {port_count} portów. Nmap sprawdzi tylko te porty.[/blue]"
                )

        nmap_outfile = os.path.join(phase2_dir, "nmap_results.xml")
        nmap_outfile_txt = os.path.join(phase2_dir, "nmap_results.txt")
        all_detected_ports = set()

        if discovered_ports_map:
            for p_set in discovered_ports_map.values():
                all_detected_ports.update(p_set)
        
        port_arg = ""
        cmd_additions = []
        strategy_used = "Specific Ports"

        if all_detected_ports:
            sorted_ports = sorted(list(all_detected_ports))
            port_arg = ",".join(map(str, sorted_ports))
        else:
            strategy = nmap_strategy_override if nmap_strategy_override else config.NMAP_SCAN_STRATEGY
            
            if strategy == "top1000":
                strategy_used = "Top 1000 (Default)"
            elif strategy == "top-ports":
                count = config.NMAP_CUSTOM_PORT_RANGE or "1000"
                cmd_additions.extend(["--top-ports", str(count)])
                strategy_used = f"Top {count}"
            elif strategy == "custom":
                if config.NMAP_CUSTOM_PORT_RANGE:
                    port_arg = config.NMAP_CUSTOM_PORT_RANGE
                    strategy_used = f"Custom: {port_arg}"
            elif strategy == "all":
                port_arg = "-"
                strategy_used = "All Ports (1-65535)"

            utils.console.print(
                f"[blue]Nmap działa samodzielnie. Strategia: {strategy_used}[/blue]"
            )

        cmd = ["nmap"]
        if config.NMAP_AGGRESSIVE_SCAN:
            cmd.append("-A")
        else:
            cmd.extend(["-sV", "-sC"])

        if config.NMAP_CUSTOM_SCRIPTS:
            cmd.extend(["--script", config.NMAP_CUSTOM_SCRIPTS])

        if port_arg:
            cmd.extend(["-p", port_arg])

        if cmd_additions:
            cmd.extend(cmd_additions)

        cmd.extend(["-oX", nmap_outfile, "-oN", nmap_outfile_txt])

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
            config.TOOL_TIMEOUT_SECONDS * 2,
        )

        if res_file and os.path.exists(res_file):
            try:
                tree = ET.parse(res_file)
                root = tree.getroot()
                ports_found_in_xml = 0
                for host in root.findall("host"):
                    status = host.find("status")
                    if status is None or status.get("state") != "up":
                        continue

                    host_ip = None
                    for addr in host.findall("address"):
                        if addr.get("addrtype") == "ipv4":
                            host_ip = addr.get("addr")
                            break
                    if not host_ip:
                         addr = host.find("address")
                         if addr is not None:
                             host_ip = addr.get("addr")

                    if not host_ip:
                        continue

                    ports_elem = host.find("ports")
                    if ports_elem is None:
                        continue

                    if host_ip not in discovered_ports_map:
                        discovered_ports_map[host_ip] = set()

                    for port in ports_elem.findall("port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            portid = port.get("portid")
                            if portid:
                                discovered_ports_map[host_ip].add(int(portid))
                                ports_found_in_xml += 1
                
                if ports_found_in_xml > 0:
                    utils.console.print(f"[green]Nmap: Znaleziono {ports_found_in_xml} otwartych portów (zaktualizowano).[/green]")
                else:
                    utils.console.print(f"[yellow]Nmap: Przetworzono wyniki, ale nie wykryto nowych otwartych portów.[/yellow]")

            except Exception as e:
                utils.console.print(
                    f"[red]Błąd podczas parsowania XML z Nmap: {e}[/red]"
                )

            if os.path.exists(nmap_outfile_txt):
                scan_results["nmap_files"] = {"Nmap": nmap_outfile_txt}
                with open(nmap_outfile_txt, "r") as f:
                    scan_results["nmap_raw"] = f.read()
            else:
                scan_results["nmap_files"] = {"Nmap": res_file}
                with open(res_file, "r") as f:
                    scan_results["nmap_raw"] = f.read()

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    utils.console.print(Align.center("[bold green]Faza 2 zakończona.[/bold green]"))

    final_summary = {}
    for host, ports in discovered_ports_map.items():
        final_summary[host] = sorted(list(ports))
    scan_results["open_ports_by_host"] = final_summary

    return scan_results


def display_phase2_settings_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 2[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        naabu_rate_disp = f"[dim]{config.NAABU_RATE}[/dim]"
        if config.USER_CUSTOMIZED_NAABU_RATE:
            naabu_rate_disp = f"[bold green]{config.NAABU_RATE}[/bold green]"

        masscan_rate_disp = f"[dim]{config.MASSCAN_RATE}[/dim]"
        if config.USER_CUSTOMIZED_MASSCAN_RATE:
            masscan_rate_disp = f"[bold green]{config.MASSCAN_RATE}[/bold green]"

        nmap_scripts = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_USE_SCRIPTS
            else "[dim]NIE[/dim]"
        )
        nmap_aggressive = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_AGGRESSIVE_SCAN
            else "[dim]NIE[/dim]"
        )

        strat_info = config.NMAP_SCAN_STRATEGY
        if strat_info == "top1000":
            strat_info = "Top 1000"
        elif strat_info == "top-ports":
            strat_info = f"Top {config.NMAP_CUSTOM_PORT_RANGE}"
        elif strat_info == "custom":
            strat_info = f"Custom {config.NMAP_CUSTOM_PORT_RANGE}"

        excluded_ports_str = (
            ",".join(map(str, config.EXCLUDED_PORTS))
            if config.EXCLUDED_PORTS
            else "Brak"
        )
        
        masscan_iface_disp = getattr(config, 'MASSCAN_INTERFACE', None)
        masscan_iface_disp = masscan_iface_disp if masscan_iface_disp else "[dim]Auto (tun0)[/dim]"

        table.add_row(
            "[bold cyan][1][/bold cyan]", f"Rate Limit (Naabu): {naabu_rate_disp}"
        )
        table.add_row(
            "[bold cyan][2][/bold cyan]", f"Rate Limit (Masscan): {masscan_rate_disp}"
        )
        table.add_row(
            "[bold cyan][3][/bold cyan]",
            f"Nmap: Domyślne Skrypty (-sC): {nmap_scripts}",
        )
        table.add_row(
            "[bold cyan][4][/bold cyan]",
            f"Nmap: Agresywny Skan (-A): {nmap_aggressive}",
        )
        table.add_row(
            "[bold cyan][5][/bold cyan]",
            f"Własne skrypty Nmap (--script): {config.NMAP_CUSTOM_SCRIPTS or 'Brak'}",
        )
        table.add_row(
            "[bold cyan][6][/bold cyan]", f"Wykluczone porty: {excluded_ports_str}"
        )
        # --- OPCJA W MENU ---
        table.add_row(
            "[bold cyan][7][/bold cyan]", f"Interfejs Masscan (-e): {masscan_iface_disp}"
        )
        table.add_row("", f"[dim]Aktualna strategia Nmap (Solo): {strat_info}[/dim]")

        table.add_section()
        table.add_row("[bold cyan][\\fb][/bold cyan]", "Powrót")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text("Wybierz opcję", justify="center")
        )

        if choice == "1":
            val = Prompt.ask(
                "Podaj rate limit dla Naabu", default=str(config.NAABU_RATE)
            )
            if val.isdigit():
                config.NAABU_RATE = int(val)
                config.USER_CUSTOMIZED_NAABU_RATE = True
        elif choice == "2":
            val = Prompt.ask(
                "Podaj rate limit dla Masscan", default=str(config.MASSCAN_RATE)
            )
            if val.isdigit():
                config.MASSCAN_RATE = int(val)
                config.USER_CUSTOMIZED_MASSCAN_RATE = True
        elif choice == "3":
            config.NMAP_USE_SCRIPTS = not config.NMAP_USE_SCRIPTS
        elif choice == "4":
            config.NMAP_AGGRESSIVE_SCAN = not config.NMAP_AGGRESSIVE_SCAN
        elif choice == "5":
            val = Prompt.ask(
                "Podaj nazwy skryptów (po przecinku)",
                default=config.NMAP_CUSTOM_SCRIPTS,
            )
            config.NMAP_CUSTOM_SCRIPTS = val
            config.USER_CUSTOMIZED_NMAP_SCRIPTS = True
        elif choice == "6":
            val = Prompt.ask("Podaj porty do wykluczenia (po przecinku)", default="")
            try:
                config.EXCLUDED_PORTS = [
                    int(p.strip()) for p in val.split(",") if p.strip().isdigit()
                ]
            except ValueError:
                pass
        elif choice == "7":
            val = Prompt.ask("Podaj interfejs sieciowy (np. tun0, eth0) lub puste dla auto", default="")
            config.MASSCAN_INTERFACE = val if val.strip() else None
            config.USER_CUSTOMIZED_MASSCAN_INTERFACE = True
        elif choice.lower() == "b":
            break#!/usr/bin/env python3

import os
import re
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set

# Importy do pobierania IP interfejsu (specyficzne dla Linuxa)
try:
    import fcntl
    import struct
except ImportError:
    pass

from rich.align import Align
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

import config
import utils


def _get_interface_ip(ifname: str) -> Optional[str]:
    """
    Pobiera adres IP dla danego interfejsu sieciowego (Linux).
    Wymagane dla Masscana na tun0, aby poprawnie routował pakiety.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 0x8915 to SIOCGIFADDR
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        return None


def _sanitize_target(target: str) -> str:
    """
    Usuwa protokół (http/https), porty i ścieżki z celu, pozostawiając domenę lub IP.
    Niezbędne dla narzędzi typu Naabu/Nmap/Masscan.
    """
    # Usuń protokół
    target = re.sub(r"^https?://", "", target)
    # Usuń wszystko po pierwszym slashu (ścieżki)
    if "/" in target:
        target = target.split("/")[0]
    # Usuń port (Nmap/Naabu/Masscan zazwyczaj wolą czysty host/IP)
    if ":" in target:
        target = target.split(":")[0]
    return target


def _resolve_to_ip(target: str) -> Optional[str]:
    """Rozwiązuje nazwę hosta na IP. Zwraca None w przypadku błędu."""
    try:
        # Jeśli target to już IP, zwróć go
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _run_scan_tool(
    tool_name: str,
    command: List[str],
    targets: List[str],
    output_file: str,
    timeout: int,
) -> Optional[str]:
    """
    Uruchamia narzędzie do skanowania portów i zapisuje wynik do pliku.
    Obsługuje przekazywanie celów przez plik tymczasowy.
    """
    # Sanityzacja celów
    clean_targets = list(set([_sanitize_target(t) for t in targets if t]))

    # --- KONFIGURACJA MASSCANA ---
    if tool_name == "Masscan":
        ip_targets = []
        for t in clean_targets:
            ip = _resolve_to_ip(t)
            if ip:
                ip_targets.append(ip)
            else:
                utils.log_and_echo(
                    f"Masscan: Nie udało się rozwiązać IP dla {t}", "WARN"
                )

        if not ip_targets:
            utils.console.print(
                f"[bold red]Brak poprawnych adresów IP dla Masscana![/bold red]"
            )
            return None
        targets_to_write = ip_targets
    else:
        # Dla Naabu/Nmap mogą być domeny
        targets_to_write = clean_targets

    if not targets_to_write:
        utils.console.print(
            f"[bold red]Brak poprawnych celów dla {tool_name}![/bold red]"
        )
        return None

    # Tworzenie pliku tymczasowego z celami
    with tempfile.NamedTemporaryFile(
        mode="w+", delete=False, suffix="_targets.txt"
    ) as tmp_targets:
        tmp_targets.write("\n".join(targets_to_write))
        targets_file_path = tmp_targets.name

    # Modyfikacja komendy w zależności od narzędzia
    final_command = list(command)
    sudo_prefix = []

    if tool_name in ["Naabu", "Masscan", "Nmap"] and os.geteuid() != 0:
        sudo_prefix = ["sudo"]

    if tool_name == "Naabu":
        if "-host" in final_command:
            try:
                idx = final_command.index("-host")
                final_command.pop(idx)
                if idx < len(final_command):
                    final_command.pop(idx)
            except ValueError:
                pass
        final_command.extend(["-list", targets_file_path])

    elif tool_name == "Masscan":
        final_command.extend(["-iL", targets_file_path])
        
        # --- AUTO-FIX DLA VPN/CTF (MANDATORY FIX) ---
        interface_to_use = getattr(config, 'MASSCAN_INTERFACE', None)
        
        # 1. Jeśli nie podano interfejsu w configu, spróbuj wykryć tun0 (standard HTB/THM)
        if not interface_to_use:
            if os.path.exists('/sys/class/net/tun0'):
                interface_to_use = 'tun0'
                # Logujemy to dyskretnie, żeby użytkownik wiedział
                if not config.QUIET_MODE:
                    utils.console.print("[dim blue]Info: Auto-wykryto interfejs VPN (tun0). Konfiguruję Masscan...[/dim blue]")
        
        # 2. Jeśli mamy interfejs, dodaj go ORAZ pobierz jego IP dla --src-ip
        if interface_to_use:
            # Dodaj flagę -e jeśli jej nie ma
            if "-e" not in final_command:
                final_command.extend(["-e", interface_to_use])
            
            # Kluczowy fix: Masscan na tun0 potrzebuje jawnego source-ip
            try:
                src_ip = _get_interface_ip(interface_to_use)
                if src_ip:
                    final_command.extend(["--src-ip", src_ip])
            except Exception as e:
                utils.log_and_echo(f"Nie udało się pobrać IP dla {interface_to_use}: {e}", "DEBUG")

    elif tool_name == "Nmap":
        final_command.extend(["-iL", targets_file_path])

    full_command = sudo_prefix + final_command
    
    # --- WYŚWIETLANIE KOMENDY ---
    # Zwiększony limit znaków, aby było widać flagi dodane na końcu (-e tun0 --src-ip)
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in full_command)
    display_cmd = cmd_str if len(cmd_str) < 500 else cmd_str[:497] + "..."

    utils.console.print(
        f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] "
        f"[dim white]{display_cmd}[/dim white]"
    )

    process = None
    try:
        status_msg = f"[bold green]Narzędzie {tool_name} pracuje...[/bold green] [dim](Może to chwilę potrwać)[/dim]"
        with utils.console.status(status_msg, spinner="dots"):
            process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = process.communicate(timeout=timeout)

        if process.returncode == 0:
            if tool_name == "Naabu" and (
                not os.path.exists(output_file) or os.path.getsize(output_file) == 0
            ):
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
        if os.path.exists(targets_file_path):
            os.remove(targets_file_path)


def start_port_scan(
    targets: List[str],
    progress_obj: Optional[Progress] = None,
    main_task_id: Optional[TaskID] = None,
) -> Dict[str, Any]:
    """
    Uruchamia skanowanie portów (Faza 2).
    """
    targets = [_sanitize_target(t) for t in targets if t]

    utils.console.print(
        Align.center(
            f"[bold green]Rozpoczynam Fazę 2 - Skanowanie Portów "
            f"({len(targets)} celów)...[/bold green]"
        )
    )

    phase2_dir = os.path.join(config.REPORT_DIR, "faza2_porty")
    os.makedirs(phase2_dir, exist_ok=True)

    scan_results = {
        "naabu_raw": "",
        "masscan_raw": "",
        "nmap_raw": "",
        "open_ports_by_host": {},
        "naabu_file": "",
        "masscan_file": "",
        "nmap_files": {},
    }

    tool_flags = (
        config.selected_phase2_tools
        if not config.AUTO_MODE
        else config.silent_selected_phase2_tools
    )

    active_tools = []
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

    # 1. Skanowanie "szybkie" (Discovery)
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
            cmd = ["naabu", "-rate", str(config.NAABU_RATE), "-o", output_file]
            if config.EXCLUDED_PORTS:
                cmd.extend(
                    ["-exclude-ports", ",".join(map(str, config.EXCLUDED_PORTS))]
                )
            cmd.extend(["-top-ports", "1000"])

        elif discovery_tool == "Masscan":
            cmd = [
                "masscan",
                "-p1-65535",
                "--rate",
                str(config.MASSCAN_RATE),
                "--wait", "5",
                "-oG",
                output_file,
            ]
            if config.EXCLUDED_PORTS:
                excluded = ",".join(map(str, config.EXCLUDED_PORTS))
                cmd.extend(["--exclude-ports", excluded])

        utils.console.print(
            f"[bold yellow]Uruchamiam szybkie skanowanie przy użyciu {discovery_tool}...[/bold yellow]"
        )

        res_file = _run_scan_tool(
            discovery_tool, cmd, targets, output_file, config.TOOL_TIMEOUT_SECONDS
        )

        if res_file and os.path.exists(res_file):
            if discovery_tool == "Naabu":
                scan_results["naabu_file"] = res_file
            elif discovery_tool == "Masscan":
                scan_results["masscan_file"] = res_file

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
                        for line in content.splitlines():
                            if "Ports:" in line and "Host:" in line:
                                try:
                                    ip_part = line.split("Host:")[1].split("()")[0].strip()
                                    ports_part = line.split("Ports:")[1].strip()
                                    
                                    # Obsługa wielu portów po przecinku (fix dla formatu -oG)
                                    for port_entry in ports_part.split(","):
                                        port_str = port_entry.strip().split("/")[0]
                                        if port_str.isdigit():
                                            if ip_part not in discovered_ports_map:
                                                discovered_ports_map[ip_part] = set()
                                            discovered_ports_map[ip_part].add(int(port_str))
                                except Exception:
                                    continue
            except Exception as e:
                utils.console.print(
                    f"[red]Błąd parsowania wyników {discovery_tool}: {e}[/red]"
                )

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    # 2. Skanowanie "głębokie" (Service Detection) - Nmap
    if "Nmap" in active_tools:
        nmap_strategy_override = None
        
        if discovery_tool:
            if not discovered_ports_map:
                utils.console.print(
                    "[bold red]Brak otwartych portów wykrytych w fazie szybkiej.[/bold red]"
                )
                if not config.AUTO_MODE and not config.QUIET_MODE:
                    fallback = utils.ask_user_decision(
                        "Discovery (Masscan/Naabu) nic nie znalazło. Jak uruchomić Nmap?\n"
                        "[bold]D[/bold] - Default (Top 1000)\n"
                        "[bold]A[/bold] - All Ports (1-65535) - Wolno",
                        ["d", "a"],
                        "d"
                    )
                    if fallback == "a":
                        nmap_strategy_override = "all"
                        utils.console.print("[yellow]Wymuszono pełny skan Nmap (1-65535).[/yellow]")
                else:
                    utils.console.print(
                        "[yellow]Uruchamiam Nmap bezpośrednio (Strategia domyślna).[/yellow]"
                    )
            else:
                port_count = sum(len(p) for p in discovered_ports_map.values())
                utils.console.print(
                    f"[blue]Wykryto łącznie {port_count} portów. Nmap sprawdzi tylko te porty.[/blue]"
                )

        nmap_outfile = os.path.join(phase2_dir, "nmap_results.xml")
        nmap_outfile_txt = os.path.join(phase2_dir, "nmap_results.txt")
        all_detected_ports = set()

        if discovered_ports_map:
            for p_set in discovered_ports_map.values():
                all_detected_ports.update(p_set)
        
        port_arg = ""
        cmd_additions = []
        strategy_used = "Specific Ports"

        if all_detected_ports:
            sorted_ports = sorted(list(all_detected_ports))
            port_arg = ",".join(map(str, sorted_ports))
        else:
            strategy = nmap_strategy_override if nmap_strategy_override else config.NMAP_SCAN_STRATEGY
            
            if strategy == "top1000":
                strategy_used = "Top 1000 (Default)"
            elif strategy == "top-ports":
                count = config.NMAP_CUSTOM_PORT_RANGE or "1000"
                cmd_additions.extend(["--top-ports", str(count)])
                strategy_used = f"Top {count}"
            elif strategy == "custom":
                if config.NMAP_CUSTOM_PORT_RANGE:
                    port_arg = config.NMAP_CUSTOM_PORT_RANGE
                    strategy_used = f"Custom: {port_arg}"
            elif strategy == "all":
                port_arg = "-"
                strategy_used = "All Ports (1-65535)"

            utils.console.print(
                f"[blue]Nmap działa samodzielnie. Strategia: {strategy_used}[/blue]"
            )

        cmd = ["nmap"]
        if config.NMAP_AGGRESSIVE_SCAN:
            cmd.append("-A")
        else:
            cmd.extend(["-sV", "-sC"])

        if config.NMAP_CUSTOM_SCRIPTS:
            cmd.extend(["--script", config.NMAP_CUSTOM_SCRIPTS])

        if port_arg:
            cmd.extend(["-p", port_arg])

        if cmd_additions:
            cmd.extend(cmd_additions)

        cmd.extend(["-oX", nmap_outfile, "-oN", nmap_outfile_txt])

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
            config.TOOL_TIMEOUT_SECONDS * 2,
        )

        if res_file and os.path.exists(res_file):
            try:
                tree = ET.parse(res_file)
                root = tree.getroot()
                ports_found_in_xml = 0
                for host in root.findall("host"):
                    status = host.find("status")
                    if status is None or status.get("state") != "up":
                        continue

                    host_ip = None
                    for addr in host.findall("address"):
                        if addr.get("addrtype") == "ipv4":
                            host_ip = addr.get("addr")
                            break
                    if not host_ip:
                         addr = host.find("address")
                         if addr is not None:
                             host_ip = addr.get("addr")

                    if not host_ip:
                        continue

                    ports_elem = host.find("ports")
                    if ports_elem is None:
                        continue

                    if host_ip not in discovered_ports_map:
                        discovered_ports_map[host_ip] = set()

                    for port in ports_elem.findall("port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            portid = port.get("portid")
                            if portid:
                                discovered_ports_map[host_ip].add(int(portid))
                                ports_found_in_xml += 1
                
                if ports_found_in_xml > 0:
                    utils.console.print(f"[green]Nmap: Znaleziono {ports_found_in_xml} otwartych portów (zaktualizowano).[/green]")
                else:
                    utils.console.print(f"[yellow]Nmap: Przetworzono wyniki, ale nie wykryto nowych otwartych portów.[/yellow]")

            except Exception as e:
                utils.console.print(
                    f"[red]Błąd podczas parsowania XML z Nmap: {e}[/red]"
                )

            if os.path.exists(nmap_outfile_txt):
                scan_results["nmap_files"] = {"Nmap": nmap_outfile_txt}
                with open(nmap_outfile_txt, "r") as f:
                    scan_results["nmap_raw"] = f.read()
            else:
                scan_results["nmap_files"] = {"Nmap": res_file}
                with open(res_file, "r") as f:
                    scan_results["nmap_raw"] = f.read()

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    utils.console.print(Align.center("[bold green]Faza 2 zakończona.[/bold green]"))

    final_summary = {}
    for host, ports in discovered_ports_map.items():
        final_summary[host] = sorted(list(ports))
    scan_results["open_ports_by_host"] = final_summary

    return scan_results


def display_phase2_settings_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 2[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        naabu_rate_disp = f"[dim]{config.NAABU_RATE}[/dim]"
        if config.USER_CUSTOMIZED_NAABU_RATE:
            naabu_rate_disp = f"[bold green]{config.NAABU_RATE}[/bold green]"

        masscan_rate_disp = f"[dim]{config.MASSCAN_RATE}[/dim]"
        if config.USER_CUSTOMIZED_MASSCAN_RATE:
            masscan_rate_disp = f"[bold green]{config.MASSCAN_RATE}[/bold green]"

        nmap_scripts = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_USE_SCRIPTS
            else "[dim]NIE[/dim]"
        )
        nmap_aggressive = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_AGGRESSIVE_SCAN
            else "[dim]NIE[/dim]"
        )

        strat_info = config.NMAP_SCAN_STRATEGY
        if strat_info == "top1000":
            strat_info = "Top 1000"
        elif strat_info == "top-ports":
            strat_info = f"Top {config.NMAP_CUSTOM_PORT_RANGE}"
        elif strat_info == "custom":
            strat_info = f"Custom {config.NMAP_CUSTOM_PORT_RANGE}"

        excluded_ports_str = (
            ",".join(map(str, config.EXCLUDED_PORTS))
            if config.EXCLUDED_PORTS
            else "Brak"
        )
        
        masscan_iface_disp = getattr(config, 'MASSCAN_INTERFACE', None)
        masscan_iface_disp = masscan_iface_disp if masscan_iface_disp else "[dim]Auto (tun0)[/dim]"

        table.add_row(
            "[bold cyan][1][/bold cyan]", f"Rate Limit (Naabu): {naabu_rate_disp}"
        )
        table.add_row(
            "[bold cyan][2][/bold cyan]", f"Rate Limit (Masscan): {masscan_rate_disp}"
        )
        table.add_row(
            "[bold cyan][3][/bold cyan]",
            f"Nmap: Domyślne Skrypty (-sC): {nmap_scripts}",
        )
        table.add_row(
            "[bold cyan][4][/bold cyan]",
            f"Nmap: Agresywny Skan (-A): {nmap_aggressive}",
        )
        table.add_row(
            "[bold cyan][5][/bold cyan]",
            f"Własne skrypty Nmap (--script): {config.NMAP_CUSTOM_SCRIPTS or 'Brak'}",
        )
        table.add_row(
            "[bold cyan][6][/bold cyan]", f"Wykluczone porty: {excluded_ports_str}"
        )
        # --- OPCJA W MENU ---
        table.add_row(
            "[bold cyan][7][/bold cyan]", f"Interfejs Masscan (-e): {masscan_iface_disp}"
        )
        table.add_row("", f"[dim]Aktualna strategia Nmap (Solo): {strat_info}[/dim]")

        table.add_section()
        table.add_row("[bold cyan][\\fb][/bold cyan]", "Powrót")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text("Wybierz opcję", justify="center")
        )

        if choice == "1":
            val = Prompt.ask(
                "Podaj rate limit dla Naabu", default=str(config.NAABU_RATE)
            )
            if val.isdigit():
                config.NAABU_RATE = int(val)
                config.USER_CUSTOMIZED_NAABU_RATE = True
        elif choice == "2":
            val = Prompt.ask(
                "Podaj rate limit dla Masscan", default=str(config.MASSCAN_RATE)
            )
            if val.isdigit():
                config.MASSCAN_RATE = int(val)
                config.USER_CUSTOMIZED_MASSCAN_RATE = True
        elif choice == "3":
            config.NMAP_USE_SCRIPTS = not config.NMAP_USE_SCRIPTS
        elif choice == "4":
            config.NMAP_AGGRESSIVE_SCAN = not config.NMAP_AGGRESSIVE_SCAN
        elif choice == "5":
            val = Prompt.ask(
                "Podaj nazwy skryptów (po przecinku)",
                default=config.NMAP_CUSTOM_SCRIPTS,
            )
            config.NMAP_CUSTOM_SCRIPTS = val
            config.USER_CUSTOMIZED_NMAP_SCRIPTS = True
        elif choice == "6":
            val = Prompt.ask("Podaj porty do wykluczenia (po przecinku)", default="")
            try:
                config.EXCLUDED_PORTS = [
                    int(p.strip()) for p in val.split(",") if p.strip().isdigit()
                ]
            except ValueError:
                pass
        elif choice == "7":
            val = Prompt.ask("Podaj interfejs sieciowy (np. tun0, eth0) lub puste dla auto", default="")
            config.MASSCAN_INTERFACE = val if val.strip() else None
            config.USER_CUSTOMIZED_MASSCAN_INTERFACE = True
        elif choice.lower() == "b":
            break#!/usr/bin/env python3

import os
import re
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set

# Importy do pobierania IP interfejsu (specyficzne dla Linuxa)
try:
    import fcntl
    import struct
except ImportError:
    pass

from rich.align import Align
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

import config
import utils


def _get_interface_ip(ifname: str) -> Optional[str]:
    """
    Pobiera adres IP dla danego interfejsu sieciowego (Linux).
    Wymagane dla Masscana na tun0, aby poprawnie routował pakiety.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 0x8915 to SIOCGIFADDR
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        return None


def _sanitize_target(target: str) -> str:
    """
    Usuwa protokół (http/https), porty i ścieżki z celu, pozostawiając domenę lub IP.
    Niezbędne dla narzędzi typu Naabu/Nmap/Masscan.
    """
    # Usuń protokół
    target = re.sub(r"^https?://", "", target)
    # Usuń wszystko po pierwszym slashu (ścieżki)
    if "/" in target:
        target = target.split("/")[0]
    # Usuń port (Nmap/Naabu/Masscan zazwyczaj wolą czysty host/IP)
    if ":" in target:
        target = target.split(":")[0]
    return target


def _resolve_to_ip(target: str) -> Optional[str]:
    """Rozwiązuje nazwę hosta na IP. Zwraca None w przypadku błędu."""
    try:
        # Jeśli target to już IP, zwróć go
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _run_scan_tool(
    tool_name: str,
    command: List[str],
    targets: List[str],
    output_file: str,
    timeout: int,
) -> Optional[str]:
    """
    Uruchamia narzędzie do skanowania portów i zapisuje wynik do pliku.
    Obsługuje przekazywanie celów przez plik tymczasowy.
    """
    # Sanityzacja celów
    clean_targets = list(set([_sanitize_target(t) for t in targets if t]))

    # --- KONFIGURACJA MASSCANA ---
    if tool_name == "Masscan":
        ip_targets = []
        for t in clean_targets:
            ip = _resolve_to_ip(t)
            if ip:
                ip_targets.append(ip)
            else:
                utils.log_and_echo(
                    f"Masscan: Nie udało się rozwiązać IP dla {t}", "WARN"
                )

        if not ip_targets:
            utils.console.print(
                f"[bold red]Brak poprawnych adresów IP dla Masscana![/bold red]"
            )
            return None
        targets_to_write = ip_targets
    else:
        # Dla Naabu/Nmap mogą być domeny
        targets_to_write = clean_targets

    if not targets_to_write:
        utils.console.print(
            f"[bold red]Brak poprawnych celów dla {tool_name}![/bold red]"
        )
        return None

    # Tworzenie pliku tymczasowego z celami
    with tempfile.NamedTemporaryFile(
        mode="w+", delete=False, suffix="_targets.txt"
    ) as tmp_targets:
        tmp_targets.write("\n".join(targets_to_write))
        targets_file_path = tmp_targets.name

    # Modyfikacja komendy w zależności od narzędzia
    final_command = list(command)
    sudo_prefix = []

    if tool_name in ["Naabu", "Masscan", "Nmap"] and os.geteuid() != 0:
        sudo_prefix = ["sudo"]

    if tool_name == "Naabu":
        if "-host" in final_command:
            try:
                idx = final_command.index("-host")
                final_command.pop(idx)
                if idx < len(final_command):
                    final_command.pop(idx)
            except ValueError:
                pass
        final_command.extend(["-list", targets_file_path])

    elif tool_name == "Masscan":
        final_command.extend(["-iL", targets_file_path])
        
        # --- AUTO-FIX DLA VPN/CTF ---
        interface_to_use = getattr(config, 'MASSCAN_INTERFACE', None)
        
        if not interface_to_use:
            if os.path.exists('/sys/class/net/tun0'):
                interface_to_use = 'tun0'
                if not config.QUIET_MODE:
                    utils.console.print("[dim blue]Info: Auto-wykryto interfejs VPN (tun0). Konfiguruję Masscan...[/dim blue]")
        
        if interface_to_use:
            if "-e" not in final_command:
                final_command.extend(["-e", interface_to_use])
            
            try:
                src_ip = _get_interface_ip(interface_to_use)
                if src_ip:
                    final_command.extend(["--src-ip", src_ip])
            except Exception as e:
                utils.log_and_echo(f"Nie udało się pobrać IP dla {interface_to_use}: {e}", "DEBUG")

    elif tool_name == "Nmap":
        final_command.extend(["-iL", targets_file_path])

    full_command = sudo_prefix + final_command
    
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in full_command)
    display_cmd = cmd_str if len(cmd_str) < 500 else cmd_str[:497] + "..."

    utils.console.print(
        f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] "
        f"[dim white]{display_cmd}[/dim white]"
    )

    process = None
    try:
        status_msg = f"[bold green]Narzędzie {tool_name} pracuje...[/bold green] [dim](Timeout: {timeout}s)[/dim]"
        with utils.console.status(status_msg, spinner="dots"):
            process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = process.communicate(timeout=timeout)

        if process.returncode == 0:
            if tool_name == "Naabu" and (
                not os.path.exists(output_file) or os.path.getsize(output_file) == 0
            ):
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
        
        # --- ZMIANA: Obsługa "zawieszonego" Masscana ---
        if tool_name == "Masscan" and os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            utils.console.print(
                f"[yellow]Masscan przekroczył czas i został zatrzymany, ale plik wyników istnieje. Używam znalezionych danych.[/yellow]"
            )
            return output_file
        # -----------------------------------------------

        utils.console.print(f"[bold red]Limit czasu dla {tool_name} minął![/bold red]")
        return None
    except Exception as e:
        utils.console.print(f"[bold red]Wyjątek przy {tool_name}: {e}[/bold red]")
        return None
    finally:
        if os.path.exists(targets_file_path):
            os.remove(targets_file_path)


def start_port_scan(
    targets: List[str],
    progress_obj: Optional[Progress] = None,
    main_task_id: Optional[TaskID] = None,
) -> Dict[str, Any]:
    """
    Uruchamia skanowanie portów (Faza 2).
    """
    targets = [_sanitize_target(t) for t in targets if t]

    utils.console.print(
        Align.center(
            f"[bold green]Rozpoczynam Fazę 2 - Skanowanie Portów "
            f"({len(targets)} celów)...[/bold green]"
        )
    )

    phase2_dir = os.path.join(config.REPORT_DIR, "faza2_porty")
    os.makedirs(phase2_dir, exist_ok=True)

    scan_results = {
        "naabu_raw": "",
        "masscan_raw": "",
        "nmap_raw": "",
        "open_ports_by_host": {},
        "naabu_file": "",
        "masscan_file": "",
        "nmap_files": {},
    }

    tool_flags = (
        config.selected_phase2_tools
        if not config.AUTO_MODE
        else config.silent_selected_phase2_tools
    )

    active_tools = []
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

    # 1. Skanowanie "szybkie" (Discovery)
    discovery_tool = None
    if "Naabu" in active_tools:
        discovery_tool = "Naabu"
    elif "Masscan" in active_tools:
        discovery_tool = "Masscan"

    discovered_ports_map: Dict[str, Set[int]] = {}

    if discovery_tool:
        output_file = os.path.join(phase2_dir, f"{discovery_tool.lower()}_results.txt")
        cmd = []
        timeout_val = config.TOOL_TIMEOUT_SECONDS

        if discovery_tool == "Naabu":
            cmd = ["naabu", "-rate", str(config.NAABU_RATE), "-o", output_file]
            if config.EXCLUDED_PORTS:
                cmd.extend(
                    ["-exclude-ports", ",".join(map(str, config.EXCLUDED_PORTS))]
                )
            cmd.extend(["-top-ports", "1000"])

        elif discovery_tool == "Masscan":
            cmd = [
                "masscan",
                "-p1-65535",
                "--rate",
                str(config.MASSCAN_RATE),
                "--wait", "0", # Wyłączamy wait w poleceniu, polegamy na timeoucie Pythona
                "-oG",
                output_file,
            ]
            if config.EXCLUDED_PORTS:
                excluded = ",".join(map(str, config.EXCLUDED_PORTS))
                cmd.extend(["--exclude-ports", excluded])
            
            # --- ZMIANA: Dynamiczny timeout dla Masscana ---
            # Obliczamy: (Liczba portów / Rate) + Margines 120s
            estimated_duration = (65535 / max(1, config.MASSCAN_RATE)) + 120
            timeout_val = int(estimated_duration)
            utils.console.print(f"[dim blue]Obliczony limit czasu dla Masscan: {timeout_val}s[/dim blue]")
            # ---------------------------------------------

        utils.console.print(
            f"[bold yellow]Uruchamiam szybkie skanowanie przy użyciu {discovery_tool}...[/bold yellow]"
        )

        res_file = _run_scan_tool(
            discovery_tool, cmd, targets, output_file, timeout_val
        )

        if res_file and os.path.exists(res_file):
            if discovery_tool == "Naabu":
                scan_results["naabu_file"] = res_file
            elif discovery_tool == "Masscan":
                scan_results["masscan_file"] = res_file

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
                        for line in content.splitlines():
                            if "Ports:" in line and "Host:" in line:
                                try:
                                    ip_part = line.split("Host:")[1].split("()")[0].strip()
                                    ports_part = line.split("Ports:")[1].strip()
                                    
                                    for port_entry in ports_part.split(","):
                                        port_str = port_entry.strip().split("/")[0]
                                        if port_str.isdigit():
                                            if ip_part not in discovered_ports_map:
                                                discovered_ports_map[ip_part] = set()
                                            discovered_ports_map[ip_part].add(int(port_str))
                                except Exception:
                                    continue
            except Exception as e:
                utils.console.print(
                    f"[red]Błąd parsowania wyników {discovery_tool}: {e}[/red]"
                )

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    # 2. Skanowanie "głębokie" (Service Detection) - Nmap
    if "Nmap" in active_tools:
        nmap_strategy_override = None
        
        if discovery_tool:
            if not discovered_ports_map:
                utils.console.print(
                    "[bold red]Brak otwartych portów wykrytych w fazie szybkiej.[/bold red]"
                )
                if not config.AUTO_MODE and not config.QUIET_MODE:
                    fallback = utils.ask_user_decision(
                        "Discovery (Masscan/Naabu) nic nie znalazło. Jak uruchomić Nmap?\n"
                        "[bold]D[/bold] - Default (Top 1000)\n"
                        "[bold]A[/bold] - All Ports (1-65535) - Wolno",
                        ["d", "a"],
                        "d"
                    )
                    if fallback == "a":
                        nmap_strategy_override = "all"
                        utils.console.print("[yellow]Wymuszono pełny skan Nmap (1-65535).[/yellow]")
                else:
                    utils.console.print(
                        "[yellow]Uruchamiam Nmap bezpośrednio (Strategia domyślna).[/yellow]"
                    )
            else:
                port_count = sum(len(p) for p in discovered_ports_map.values())
                utils.console.print(
                    f"[blue]Wykryto łącznie {port_count} portów. Nmap sprawdzi tylko te porty.[/blue]"
                )

        nmap_outfile = os.path.join(phase2_dir, "nmap_results.xml")
        nmap_outfile_txt = os.path.join(phase2_dir, "nmap_results.txt")
        all_detected_ports = set()

        if discovered_ports_map:
            for p_set in discovered_ports_map.values():
                all_detected_ports.update(p_set)
        
        port_arg = ""
        cmd_additions = []
        strategy_used = "Specific Ports"

        if all_detected_ports:
            sorted_ports = sorted(list(all_detected_ports))
            port_arg = ",".join(map(str, sorted_ports))
        else:
            strategy = nmap_strategy_override if nmap_strategy_override else config.NMAP_SCAN_STRATEGY
            
            if strategy == "top1000":
                strategy_used = "Top 1000 (Default)"
            elif strategy == "top-ports":
                count = config.NMAP_CUSTOM_PORT_RANGE or "1000"
                cmd_additions.extend(["--top-ports", str(count)])
                strategy_used = f"Top {count}"
            elif strategy == "custom":
                if config.NMAP_CUSTOM_PORT_RANGE:
                    port_arg = config.NMAP_CUSTOM_PORT_RANGE
                    strategy_used = f"Custom: {port_arg}"
            elif strategy == "all":
                port_arg = "-"
                strategy_used = "All Ports (1-65535)"

            utils.console.print(
                f"[blue]Nmap działa samodzielnie. Strategia: {strategy_used}[/blue]"
            )

        cmd = ["nmap"]
        if config.NMAP_AGGRESSIVE_SCAN:
            cmd.append("-A")
        else:
            cmd.extend(["-sV", "-sC"])

        if config.NMAP_CUSTOM_SCRIPTS:
            cmd.extend(["--script", config.NMAP_CUSTOM_SCRIPTS])

        if port_arg:
            cmd.extend(["-p", port_arg])

        if cmd_additions:
            cmd.extend(cmd_additions)

        cmd.extend(["-oX", nmap_outfile, "-oN", nmap_outfile_txt])

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
            config.TOOL_TIMEOUT_SECONDS * 2,
        )

        if res_file and os.path.exists(res_file):
            try:
                tree = ET.parse(res_file)
                root = tree.getroot()
                ports_found_in_xml = 0
                for host in root.findall("host"):
                    status = host.find("status")
                    if status is None or status.get("state") != "up":
                        continue

                    host_ip = None
                    for addr in host.findall("address"):
                        if addr.get("addrtype") == "ipv4":
                            host_ip = addr.get("addr")
                            break
                    if not host_ip:
                         addr = host.find("address")
                         if addr is not None:
                             host_ip = addr.get("addr")

                    if not host_ip:
                        continue

                    ports_elem = host.find("ports")
                    if ports_elem is None:
                        continue

                    if host_ip not in discovered_ports_map:
                        discovered_ports_map[host_ip] = set()

                    for port in ports_elem.findall("port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            portid = port.get("portid")
                            if portid:
                                discovered_ports_map[host_ip].add(int(portid))
                                ports_found_in_xml += 1
                
                if ports_found_in_xml > 0:
                    utils.console.print(f"[green]Nmap: Znaleziono {ports_found_in_xml} otwartych portów (zaktualizowano).[/green]")
                else:
                    utils.console.print(f"[yellow]Nmap: Przetworzono wyniki, ale nie wykryto nowych otwartych portów.[/yellow]")

            except Exception as e:
                utils.console.print(
                    f"[red]Błąd podczas parsowania XML z Nmap: {e}[/red]"
                )

            if os.path.exists(nmap_outfile_txt):
                scan_results["nmap_files"] = {"Nmap": nmap_outfile_txt}
                with open(nmap_outfile_txt, "r") as f:
                    scan_results["nmap_raw"] = f.read()
            else:
                scan_results["nmap_files"] = {"Nmap": res_file}
                with open(res_file, "r") as f:
                    scan_results["nmap_raw"] = f.read()

        if progress_obj and main_task_id is not None:
            progress_obj.update(main_task_id, advance=1)

    utils.console.print(Align.center("[bold green]Faza 2 zakończona.[/bold green]"))

    final_summary = {}
    for host, ports in discovered_ports_map.items():
        final_summary[host] = sorted(list(ports))
    scan_results["open_ports_by_host"] = final_summary

    return scan_results


def display_phase2_settings_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 2[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        naabu_rate_disp = f"[dim]{config.NAABU_RATE}[/dim]"
        if config.USER_CUSTOMIZED_NAABU_RATE:
            naabu_rate_disp = f"[bold green]{config.NAABU_RATE}[/bold green]"

        masscan_rate_disp = f"[dim]{config.MASSCAN_RATE}[/dim]"
        if config.USER_CUSTOMIZED_MASSCAN_RATE:
            masscan_rate_disp = f"[bold green]{config.MASSCAN_RATE}[/bold green]"

        nmap_scripts = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_USE_SCRIPTS
            else "[dim]NIE[/dim]"
        )
        nmap_aggressive = (
            "[bold green]TAK[/bold green]"
            if config.NMAP_AGGRESSIVE_SCAN
            else "[dim]NIE[/dim]"
        )

        strat_info = config.NMAP_SCAN_STRATEGY
        if strat_info == "top1000":
            strat_info = "Top 1000"
        elif strat_info == "top-ports":
            strat_info = f"Top {config.NMAP_CUSTOM_PORT_RANGE}"
        elif strat_info == "custom":
            strat_info = f"Custom {config.NMAP_CUSTOM_PORT_RANGE}"

        excluded_ports_str = (
            ",".join(map(str, config.EXCLUDED_PORTS))
            if config.EXCLUDED_PORTS
            else "Brak"
        )
        
        masscan_iface_disp = getattr(config, 'MASSCAN_INTERFACE', None)
        masscan_iface_disp = masscan_iface_disp if masscan_iface_disp else "[dim]Auto (tun0)[/dim]"

        table.add_row(
            "[bold cyan][1][/bold cyan]", f"Rate Limit (Naabu): {naabu_rate_disp}"
        )
        table.add_row(
            "[bold cyan][2][/bold cyan]", f"Rate Limit (Masscan): {masscan_rate_disp}"
        )
        table.add_row(
            "[bold cyan][3][/bold cyan]",
            f"Nmap: Domyślne Skrypty (-sC): {nmap_scripts}",
        )
        table.add_row(
            "[bold cyan][4][/bold cyan]",
            f"Nmap: Agresywny Skan (-A): {nmap_aggressive}",
        )
        table.add_row(
            "[bold cyan][5][/bold cyan]",
            f"Własne skrypty Nmap (--script): {config.NMAP_CUSTOM_SCRIPTS or 'Brak'}",
        )
        table.add_row(
            "[bold cyan][6][/bold cyan]", f"Wykluczone porty: {excluded_ports_str}"
        )
        # --- OPCJA W MENU ---
        table.add_row(
            "[bold cyan][7][/bold cyan]", f"Interfejs Masscan (-e): {masscan_iface_disp}"
        )
        table.add_row("", f"[dim]Aktualna strategia Nmap (Solo): {strat_info}[/dim]")

        table.add_section()
        table.add_row("[bold cyan][\\fb][/bold cyan]", "Powrót")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text("Wybierz opcję", justify="center")
        )

        if choice == "1":
            val = Prompt.ask(
                "Podaj rate limit dla Naabu", default=str(config.NAABU_RATE)
            )
            if val.isdigit():
                config.NAABU_RATE = int(val)
                config.USER_CUSTOMIZED_NAABU_RATE = True
        elif choice == "2":
            val = Prompt.ask(
                "Podaj rate limit dla Masscan", default=str(config.MASSCAN_RATE)
            )
            if val.isdigit():
                config.MASSCAN_RATE = int(val)
                config.USER_CUSTOMIZED_MASSCAN_RATE = True
        elif choice == "3":
            config.NMAP_USE_SCRIPTS = not config.NMAP_USE_SCRIPTS
        elif choice == "4":
            config.NMAP_AGGRESSIVE_SCAN = not config.NMAP_AGGRESSIVE_SCAN
        elif choice == "5":
            val = Prompt.ask(
                "Podaj nazwy skryptów (po przecinku)",
                default=config.NMAP_CUSTOM_SCRIPTS,
            )
            config.NMAP_CUSTOM_SCRIPTS = val
            config.USER_CUSTOMIZED_NMAP_SCRIPTS = True
        elif choice == "6":
            val = Prompt.ask("Podaj porty do wykluczenia (po przecinku)", default="")
            try:
                config.EXCLUDED_PORTS = [
                    int(p.strip()) for p in val.split(",") if p.strip().isdigit()
                ]
            except ValueError:
                pass
        elif choice == "7":
            val = Prompt.ask("Podaj interfejs sieciowy (np. tun0, eth0) lub puste dla auto", default="")
            config.MASSCAN_INTERFACE = val if val.strip() else None
            config.USER_CUSTOMIZED_MASSCAN_INTERFACE = True
        elif choice.lower() == "b":
            break