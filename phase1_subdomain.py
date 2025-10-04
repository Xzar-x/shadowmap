# /usr/local/share/shadowmap/phase1_subdomain.py

import json
import os
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple

from rich.align import Align
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

# Importy z naszego projektu
import config
import utils


def start_phase1_scan() -> Tuple[Dict[str, str], List[Dict[str, Any]], List[str]]:
    """
    Uruchamia skanowanie Fazy 1 w celu odkrycia subdomen i ich weryfikacji.
    """
    utils.console.print(
        Align.center(
            f"[bold green]Rozpoczynam Fazę 1 - Odkrywanie Subdomen dla "
            f"{config.ORIGINAL_TARGET}...[/bold green]"
        )
    )

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
        # Filtruj narzędzia, które są dostępne
        tool_names = ["Subfinder", "Assetfinder", "Findomain", "Puredns (bruteforce)"]
        enabled_tools_indices = [
            i for i, enabled in enumerate(config.selected_phase1_tools) if enabled
        ]
        
        available_tools_count = 0
        for i in enabled_tools_indices:
            tool_exe = config.TOOL_EXECUTABLE_MAP.get(tool_names[i])
            if tool_exe and tool_exe not in config.MISSING_TOOLS:
                 # Pomiń pasywne dla IP
                if not (config.TARGET_IS_IP and i < 3):
                    available_tools_count += 1

        task1 = progress.add_task(
            "[green]Faza 1 (Subdomeny)[/green]", total=available_tools_count or 1
        )

        current_wordlist_p1 = config.WORDLIST_PHASE1
        if config.SAFE_MODE and not config.USER_CUSTOMIZED_WORDLIST_PHASE1:
            current_wordlist_p1 = config.SMALL_WORDLIST_PHASE1

        shuffled_path = utils.shuffle_wordlist(current_wordlist_p1, config.REPORT_DIR)
        if shuffled_path:
            current_wordlist_p1 = shuffled_path
            config.TEMP_FILES_TO_CLEAN.append(shuffled_path)

        phase1_dir = os.path.join(config.REPORT_DIR, "faza1_subdomain_scanning")

        puredns_rate = config.PUREDNS_RATE_LIMIT
        if config.SAFE_MODE and not config.USER_CUSTOMIZED_PUREDNS_RATE_LIMIT:
            puredns_rate = 50

        puredns_cmd = [
            "puredns",
            "bruteforce",
            current_wordlist_p1,
            config.CLEAN_DOMAIN_TARGET,
            "--resolvers",
            config.RESOLVERS_FILE,
            "--rate-limit",
            str(puredns_rate),
            "-t", str(config.THREADS), # ZMIANA: Dodano liczbę wątków
            "-q",
        ]

        tool_configurations: List[Dict[str, Any]] = [
            {
                "name": "Subfinder",
                "cmd_template": [
                    "subfinder",
                    "-d",
                    config.CLEAN_DOMAIN_TARGET,
                    "-silent",
                ],
            },
            {
                "name": "Assetfinder",
                "cmd_template": [
                    "assetfinder",
                    "--subs-only",
                    config.CLEAN_DOMAIN_TARGET,
                ],
            },
            {
                "name": "Findomain",
                "cmd_template": [
                    "findomain",
                    "--target",
                    config.CLEAN_DOMAIN_TARGET,
                    "-q",
                ],
            },
            {"name": "Puredns", "cmd_template": puredns_cmd, "display_name": "Puredns (bruteforce)"},
        ]

        tasks_to_run = []
        for i, tool_cfg in enumerate(tool_configurations):
            tool_display_name = tool_cfg.get("display_name", tool_cfg["name"])
            tool_exe = config.TOOL_EXECUTABLE_MAP.get(tool_display_name)
            
            if config.selected_phase1_tools[i] and tool_exe and tool_exe not in config.MISSING_TOOLS:
                is_passive = tool_cfg["name"] in ["Subfinder", "Assetfinder", "Findomain"]
                if config.TARGET_IS_IP and is_passive:
                    continue
                output_path = os.path.join(
                    phase1_dir, f"{tool_cfg['name'].lower()}_results.txt"
                )
                tasks_to_run.append(
                    (tool_cfg["name"], tool_cfg["cmd_template"], output_path)
                )

        if not tasks_to_run:
            msg = "Brak dostępnych narzędzi do uruchomienia, pomijam Fazę 1."
            utils.console.print(Align.center(msg, style="bold yellow"))
            progress.update(task1, completed=1)
            return {}, [], []

        output_files: Dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=config.THREADS) as executor:
            futures: Dict[Future, str] = {
                executor.submit(
                    utils.execute_tool_command,
                    name,
                    cmd,
                    out,
                    config.TOOL_TIMEOUT_SECONDS,
                ): name
                for name, cmd, out in tasks_to_run
            }
            for future in as_completed(futures):
                tool_name = futures[future]
                result_file = future.result()
                if result_file:
                    output_files[tool_name] = result_file
                progress.update(task1, advance=1)

    utils.console.print(Align.center("Integracja wyników...", style="bold green"))
    unique_subdomains_file = os.path.join(
        config.REPORT_DIR, "all_subdomains_unique.txt"
    )
    config.TEMP_FILES_TO_CLEAN.append(unique_subdomains_file)
    all_lines: List[str] = []
    for f_path in output_files.values():
        if os.path.exists(f_path):
            with open(f_path, "r", encoding="utf-8") as f:
                all_lines.extend(f.readlines())

    domain_part = f".{config.CLEAN_DOMAIN_TARGET}"
    unique_lines_set: set[str] = set()
    for line in all_lines:
        clean_line = line.strip().lower()
        if clean_line and (
            domain_part in clean_line or clean_line == config.CLEAN_DOMAIN_TARGET
        ):
            unique_lines_set.add(clean_line)
    unique_lines = sorted(list(unique_lines_set))

    with open(unique_subdomains_file, "w", encoding="utf-8") as f:
        f.write("\n".join(unique_lines))

    active_urls_meta: List[Dict[str, Any]] = []
    status_msg = "[bold green]Weryfikuję subdomeny (HTTPX)...[/bold green]"
    if "httpx" not in config.MISSING_TOOLS:
        with utils.console.status(status_msg):
            httpx_output_file = os.path.join(config.REPORT_DIR, "httpx_results_phase1.txt")
            httpx_rate_limit = config.HTTPX_P1_RATE_LIMIT
            if config.SAFE_MODE and not config.USER_CUSTOMIZED_HTTPX_P1_RATE_LIMIT:
                httpx_rate_limit = 10
            httpx_command = [
                "httpx",
                "-l",
                unique_subdomains_file,
                "-silent",
                "-fc",
                "404",
                "-json",
                "-irh",
                "-rate-limit",
                str(httpx_rate_limit),
            ]
            current_ua = config.CUSTOM_HEADER or utils.user_agent_rotator.get()
            httpx_command.extend(["-H", f"User-Agent: {current_ua}"])
            if config.SAFE_MODE:
                httpx_command.extend(["-p", "80,443,8000,8080,8443"])
                for header in utils.get_random_browser_headers():
                    httpx_command.extend(["-H", header])
            if (
                os.path.exists(unique_subdomains_file)
                and os.path.getsize(unique_subdomains_file) > 0
            ):
                httpx_result_file = utils.execute_tool_command(
                    "Httpx (Faza 1)",
                    httpx_command,
                    httpx_output_file,
                    config.TOOL_TIMEOUT_SECONDS,
                )
                if httpx_result_file:
                    output_files["Httpx"] = httpx_result_file
                    with open(httpx_result_file, "r", encoding="utf-8") as f:
                        for line in f:
                            if not line.strip():
                                continue
                            try:
                                data = json.loads(line)
                                url = data.get("url")
                                if url:
                                    headers = {
                                        k.lower(): v
                                        for k, v in data.get("header", {}).items()
                                    }
                                    last_mod = headers.get("last-modified")
                                    result_obj: Dict[str, Any] = {
                                        "url": url,
                                        "status_code": data.get("status_code"),
                                    }
                                    if last_mod:
                                        result_obj["last_modified"] = last_mod
                                    active_urls_meta.append(result_obj)
                            except (json.JSONDecodeError, TypeError):
                                continue
    else:
        utils.console.print(Align.center("[yellow]Ostrzeżenie: httpx nie jest dostępny. Pomijam weryfikację subdomen.[/yellow]"))


    sorted_active_urls = sorted(active_urls_meta, key=lambda x: x["url"])
    return output_files, sorted_active_urls, unique_lines


def display_phase1_tool_selection_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(
                Panel.fit("[bold magenta]Faza 1: Odkrywanie Subdomen[/bold magenta]")
            )
        )
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
            "Subfinder",
            "Assetfinder",
            "Findomain",
            "Puredns (bruteforce)",
        ]
        for i, tool_name in enumerate(tool_names):
            tool_exe = config.TOOL_EXECUTABLE_MAP.get(tool_name)
            is_missing = tool_exe and tool_exe in config.MISSING_TOOLS
            
            status = (
                "[bold green]✓[/bold green]"
                if config.selected_phase1_tools[i]
                else "[bold red]✗[/bold red]"
            )
            
            row_style = ""
            display_name = f"{status} {tool_name}"
            
            if is_missing:
                display_name = f"[dim]✗ {tool_name} (niedostępne)[/dim]"
                row_style = "dim"
            elif config.TARGET_IS_IP and i < 3:
                display_name = f"[dim]{status} {tool_name} (pominięto dla IP)[/dim]"
                row_style = "dim"

            table.add_row(f"[bold cyan][{i+1}][/bold cyan]", display_name, style=row_style)


        table.add_section()
        table.add_row(
            "[bold cyan][\fs][/bold cyan]",
            "[bold magenta]Ustawienia Fazy 1[/bold magenta]",
        )
        table.add_row("[bold cyan][\fb][/bold cyan]", "Powrót do menu głównego")
        table.add_row("[bold cyan][\fq][/bold cyan]", "Wyjdź")

        utils.console.print(Align.center(table))
        prompt_txt = Text.from_markup(
            "[bold cyan]Wybierz opcję i naciśnij Enter[/bold cyan]",
            justify="center",
        )
        choice = utils.get_single_char_input_with_prompt(prompt_txt)

        if choice.isdigit() and 1 <= int(choice) <= 4:
            idx = int(choice) - 1
            tool_exe = config.TOOL_EXECUTABLE_MAP.get(tool_names[idx])
            
            if tool_exe and tool_exe in config.MISSING_TOOLS:
                utils.console.print(Align.center("[red]To narzędzie nie jest zainstalowane.[/red]"))
                time.sleep(1)
            elif config.TARGET_IS_IP and idx < 3:
                msg = "[yellow]Nie można włączyć narzędzi pasywnych dla IP.[/yellow]"
                utils.console.print(Align.center(msg, style="bold"))
                time.sleep(1)
            else:
                config.selected_phase1_tools[idx] ^= 1
        elif choice.lower() == "s":
            display_phase1_settings_menu(display_banner_func)
        elif choice.lower() == "q":
            sys.exit(0)
        elif choice.lower() == "b":
            return False
        elif choice == "\r":
            active_and_available = False
            for i, selected in enumerate(config.selected_phase1_tools):
                if selected:
                    tool_exe = config.TOOL_EXECUTABLE_MAP.get(tool_names[i])
                    if tool_exe and tool_exe not in config.MISSING_TOOLS:
                        active_and_available = True
                        break
            if active_and_available:
                return True
            else:
                msg = "[bold yellow]Wybierz co najmniej jedno dostępne narzędzie.[/bold yellow]"
                utils.console.print(Align.center(msg))
                time.sleep(1)
        else:
            utils.console.print(
                Align.center("[bold yellow]Nieprawidłowa opcja.[/bold yellow]")
            )
            time.sleep(0.5)


def display_phase1_settings_menu(display_banner_func):
    """Wyświetla rozbudowane menu ustawień specyficznych dla Fazy 1."""
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 1[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        wordlist_disp = (
            f"[bold green]{config.WORDLIST_PHASE1} (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_WORDLIST_PHASE1
            else (
                f"[bold yellow]{config.SMALL_WORDLIST_PHASE1} "
                f"(Safe Mode)[/bold yellow]"
                if config.SAFE_MODE
                else f"[dim]{config.WORDLIST_PHASE1}[/dim]"
            )
        )
        resolvers_disp = (
            f"[bold green]{config.RESOLVERS_FILE} (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_RESOLVERS
            else f"[dim]{config.RESOLVERS_FILE}[/dim]"
        )
        threads_disp = (
            f"[bold green]{config.THREADS} (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_THREADS
            else f"[dim]{config.THREADS}[/dim]"
        )
        ua_disp = (
            f"[bold green]{config.CUSTOM_HEADER} (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_USER_AGENT and config.CUSTOM_HEADER
            else "[dim]Domyślny (losowy)[/dim]"
        )
        puredns_rate_disp = (
            f"[bold green]{config.PUREDNS_RATE_LIMIT} (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_PUREDNS_RATE_LIMIT
            else (
                "[bold yellow]50 (Safe Mode)[/bold yellow]"
                if config.SAFE_MODE
                else f"[dim]{config.PUREDNS_RATE_LIMIT}[/dim]"
            )
        )
        httpx_rate_disp = (
            f"[bold green]{config.HTTPX_P1_RATE_LIMIT} (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_HTTPX_P1_RATE_LIMIT
            else (
                "[bold yellow]10 (Safe Mode)[/bold yellow]"
                if config.SAFE_MODE
                else f"[dim]{config.HTTPX_P1_RATE_LIMIT}[/dim]"
            )
        )
        safe_status = (
            "[bold green]✓[/bold green]"
            if config.SAFE_MODE
            else "[bold red]✗[/bold red]"
        )

        table.add_row("[bold cyan][1][/bold cyan]", f"[{safe_status}] Tryb bezpieczny")
        table.add_row(
            "[bold cyan][2][/bold cyan]",
            f"Lista słów (Puredns): {wordlist_disp}",
        )
        table.add_row(
            "[bold cyan][3][/bold cyan]", f"Plik resolverów: {resolvers_disp}"
        )
        table.add_row("[bold cyan][4][/bold cyan]", f"Wątki: {threads_disp}")
        table.add_row("[bold cyan][5][/bold cyan]", f"User-Agent (Httpx): {ua_disp}")
        table.add_row(
            "[bold cyan][6][/bold cyan]",
            f"Rate Limit (Puredns): {puredns_rate_disp}",
        )
        table.add_row(
            "[bold cyan][7][/bold cyan]",
            f"Rate Limit (Httpx): {httpx_rate_disp}",
        )
        table.add_section()
        table.add_row("[bold cyan][\fb][/bold cyan]", "Powrót do menu Fazy 1")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center")
        )

        if choice == "1":
            config.SAFE_MODE = not config.SAFE_MODE
            utils.handle_safe_mode_tor_check()
        elif choice == "2":
            prompt = "[bold cyan]Podaj ścieżkę do listy słów[/bold cyan]"
            new_path = Prompt.ask(prompt, default=config.WORDLIST_PHASE1)
            if os.path.isfile(new_path):
                config.WORDLIST_PHASE1 = new_path
                config.USER_CUSTOMIZED_WORDLIST_PHASE1 = True
            else:
                utils.console.print(
                    Align.center("[bold red]Plik nie istnieje.[/bold red]")
                )
                time.sleep(1)
        elif choice == "3":
            prompt = "[bold cyan]Podaj ścieżkę do pliku resolverów[/bold cyan]"
            new_path = Prompt.ask(prompt, default=config.RESOLVERS_FILE)
            if os.path.isfile(new_path):
                config.RESOLVERS_FILE = new_path
                config.USER_CUSTOMIZED_RESOLVERS = True
            else:
                utils.console.print(
                    Align.center("[bold red]Plik nie istnieje.[/bold red]")
                )
                time.sleep(1)
        elif choice == "4":
            prompt = "[bold cyan]Podaj liczbę wątków[/bold cyan]"
            new_threads = Prompt.ask(prompt, default=str(config.THREADS))
            if new_threads.isdigit():
                config.THREADS = int(new_threads)
                config.USER_CUSTOMIZED_THREADS = True
        elif choice == "5":
            prompt = "[bold cyan]Podaj własny User-Agent[/bold cyan]"
            new_ua = Prompt.ask(prompt, default=config.CUSTOM_HEADER)
            config.CUSTOM_HEADER = new_ua
            config.USER_CUSTOMIZED_USER_AGENT = bool(new_ua)
        elif choice == "6":
            prompt = "[bold cyan]Podaj rate limit dla Puredns[/bold cyan]"
            new_rate = Prompt.ask(prompt, default=str(config.PUREDNS_RATE_LIMIT))
            if new_rate.isdigit():
                config.PUREDNS_RATE_LIMIT = int(new_rate)
                config.USER_CUSTOMIZED_PUREDNS_RATE_LIMIT = True
        elif choice == "7":
            prompt = "[bold cyan]Podaj rate limit dla Httpx[/bold cyan]"
            new_rate = Prompt.ask(prompt, default=str(config.HTTPX_P1_RATE_LIMIT))
            if new_rate.isdigit():
                config.HTTPX_P1_RATE_LIMIT = int(new_rate)
                config.USER_CUSTOMIZED_HTTPX_P1_RATE_LIMIT = True
        elif choice.lower() == "b":
            break

