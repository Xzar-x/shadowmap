# /usr/local/share/shadowmap/phase1_subdomain.py

import json
import os
import subprocess
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

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


def _execute_tool_command(
    tool_name: str, command_parts: List[str], output_file: str, timeout: int
) -> Optional[str]:
    cmd_str = " ".join(command_parts)
    utils.console.print(
        f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] [dim white]{cmd_str}[/dim white]"
    )
    try:
        process = subprocess.run(
            command_parts,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            check=False,
            encoding="utf-8",
            errors="ignore",
        )

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(process.stdout)

        if process.stderr:
            utils.log_and_echo(
                f"Komunikaty z STDERR dla '{tool_name}':\n{process.stderr.strip()}",
                "DEBUG",
            )

        if process.returncode == 0:
            utils.console.print(
                f"[bold green]✅ {tool_name} zakończył skanowanie.[/bold green]"
            )
        else:
            utils.log_and_echo(
                f"Narzędzie {tool_name} zakończyło z błędem ({process.returncode}).",
                "WARN",
            )
        return output_file

    except Exception as e:
        utils.log_and_echo(f"BŁĄD: Ogólny błąd wykonania '{cmd_str}': {e}", "ERROR")
        utils.console.print(
            Align.center(f"[bold red]❌ BŁĄD: {tool_name}: {e}[/bold red]")
        )
        return None


def start_phase1_scan() -> Tuple[Dict[str, str], List[Dict[str, Any]], List[str]]:
    """
    Uruchamia skanowanie Fazy 1 w celu odkrycia subdomen i wzbogacenia ich o dane.
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
        BarColumn(), MofNCompleteColumn(), "•", TimeElapsedColumn(),
        console=utils.console, transient=True,
    ) as progress:
        task1_total = sum(
            1 for i, en in enumerate(config.selected_phase1_tools)
            if en and not (config.TARGET_IS_IP and i < 3)
        )
        task1 = progress.add_task(
            "[green]Faza 1 (Subdomeny)[/green]", total=task1_total or 1
        )

        current_wordlist_p1 = config.WORDLIST_PHASE1
        if config.SAFE_MODE:
            if not config.USER_CUSTOMIZED_WORDLIST_PHASE1:
                current_wordlist_p1 = config.SMALL_WORDLIST_PHASE1
            if not config.USER_CUSTOMIZED_USER_AGENT and not config.CUSTOM_HEADER:
                config.CUSTOM_HEADER = utils.get_random_user_agent_header()

            shuffled_path = utils.shuffle_wordlist(
                current_wordlist_p1, config.REPORT_DIR
            )
            if shuffled_path:
                current_wordlist_p1 = shuffled_path
                config.TEMP_FILES_TO_CLEAN.append(shuffled_path)

        phase1_dir = os.path.join(config.REPORT_DIR, "faza1_subdomain_scanning")

        puredns_base_cmd = [
            "puredns", "bruteforce", current_wordlist_p1,
            config.CLEAN_DOMAIN_TARGET, "--resolvers", config.RESOLVERS_FILE,
        ]
        tool_configurations = [
            {"name": "Subfinder", "cmd_template": [
                "subfinder", "-d", config.CLEAN_DOMAIN_TARGET, "-silent"]},
            {"name": "Assetfinder", "cmd_template": [
                "assetfinder", "--subs-only", config.CLEAN_DOMAIN_TARGET]},
            {"name": "Findomain", "cmd_template": [
                "findomain", "--target", config.CLEAN_DOMAIN_TARGET, "-q"]},
            {"name": "Puredns", "cmd_template": puredns_base_cmd + [
                "--rate-limit", "1000", "-q"]},
        ]

        if config.SAFE_MODE:
            tool_configurations[3]["cmd_template"] = puredns_base_cmd + [
                "--rate-limit", "50", "-q"]

        tasks_to_run = []
        for i, tool_cfg in enumerate(tool_configurations):
            if config.selected_phase1_tools[i]:
                if config.TARGET_IS_IP and tool_cfg["name"] in [
                    "Subfinder", "Assetfinder", "Findomain"
                ]:
                    continue
                output_path = os.path.join(
                    phase1_dir, f"{tool_cfg['name'].lower()}_results.txt"
                )
                tasks_to_run.append(
                    (tool_cfg["name"], tool_cfg["cmd_template"], output_path)
                )

        if not tasks_to_run:
            utils.console.print(
                Align.center("Nie wybrano narzędzi, pomijam.", style="bold yellow")
            )
            return {}, [], []

        output_files_collected: Dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=config.THREADS) as executor:
            futures: Dict[Future, str] = {
                executor.submit(
                    _execute_tool_command, name, cmd, out, config.TOOL_TIMEOUT_SECONDS
                ): name for name, cmd, out in tasks_to_run
            }
            for future in as_completed(futures):
                tool_name = futures[future]
                if result_file := future.result():
                    output_files_collected[tool_name] = result_file
                progress.update(task1, advance=1)

    utils.console.print(Align.center("Integracja wyników...", style="bold green"))
    unique_subdomains_file = os.path.join(
        config.REPORT_DIR, "all_subdomains_unique.txt"
    )
    config.TEMP_FILES_TO_CLEAN.append(unique_subdomains_file)
    all_lines = []
    for f_path in output_files_collected.values():
        if os.path.exists(f_path):
            with open(f_path, "r", encoding="utf-8") as f:
                all_lines.extend(f.readlines())

    domain_part = f".{config.CLEAN_DOMAIN_TARGET}"
    unique_lines = sorted(
        list(set(
            line.strip().lower() for line in all_lines if line.strip() and (
                domain_part in line.lower() or
                line.strip().lower() == config.CLEAN_DOMAIN_TARGET
            )
        ))
    )

    with open(unique_subdomains_file, "w", encoding="utf-8") as f:
        f.write("\n".join(unique_lines))

    active_urls_with_metadata = []
    status_msg = "[bold green]Weryfikuję subdomeny (HTTPX)...[/bold green]"
    with utils.console.status(status_msg):
        httpx_output_file = os.path.join(config.REPORT_DIR, "httpx_results_phase1.txt")
        httpx_command = [
            "httpx", "-l", unique_subdomains_file,
            "-silent", "-fc", "404", "-json", "-irh",
        ]

        if config.SAFE_MODE:
            httpx_command.extend(["-p", "80,443,8000,8080,8443", "-rate-limit", "10"])
            for header in utils.get_random_browser_headers():
                httpx_command.extend(["-H", header])
        if config.CUSTOM_HEADER:
            httpx_command.extend(["-H", f"User-Agent: {config.CUSTOM_HEADER}"])
        elif not config.SAFE_MODE:
            ua_header = f"User-Agent: {utils.get_random_user_agent_header()}"
            httpx_command.extend(["-H", ua_header])

        if os.path.exists(unique_subdomains_file) and os.path.getsize(unique_subdomains_file) > 0:
            httpx_result_file = _execute_tool_command(
                "Httpx (Faza 1)", httpx_command,
                httpx_output_file, config.TOOL_TIMEOUT_SECONDS
            )
            if httpx_result_file:
                output_files_collected["Httpx"] = httpx_result_file
                with open(httpx_result_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            if url := data.get("url"):
                                headers = {k.lower(): v for k, v in data.get("header", {}).items()}
                                last_mod = headers.get("last-modified")

                                result_obj = {
                                    "url": url, "status_code": data.get("status_code"),
                                }
                                if last_mod:
                                    result_obj["last_modified"] = last_mod
                                active_urls_with_metadata.append(result_obj)

                        except (json.JSONDecodeError, TypeError):
                            continue

    sorted_active_urls = sorted(active_urls_with_metadata, key=lambda x: x["url"])
    return output_files_collected, sorted_active_urls, unique_lines


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
            "[bold green]WŁĄCZONY[/bold green]" if config.SAFE_MODE
            else "[bold red]WYŁĄCZONY[/bold red]"
        )
        utils.console.print(
            Align.center(f"Cel: [bold green]{config.ORIGINAL_TARGET}[/bold green] | "
                         f"Tryb bezpieczny: {safe_mode_status}")
        )

        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        tool_names = ["Subfinder", "Assetfinder", "Findomain", "Puredns (bruteforce)"]
        for i, tool_name in enumerate(tool_names):
            status = ("[bold green]✓[/bold green]" if config.selected_phase1_tools[i]
                      else "[bold red]✗[/bold red]")
            if config.TARGET_IS_IP and i < 3:
                table.add_row(f"[{i+1}]",
                              f"[dim]{status}[/dim] [dim]{tool_name} (pominięto dla IP)[/dim]")
            else:
                table.add_row(f"[{i+1}]", f"{status} {tool_name}")

        table.add_section()
        table.add_row("[\fs]", "[bold magenta]Ustawienia Fazy 1[/bold magenta]")
        table.add_row("[\fb]", "Powrót do menu głównego")
        table.add_row("[\fq]", "Wyjdź")

        utils.console.print(Align.center(table))
        prompt_txt = Text.from_markup(
            "[bold cyan]Wybierz opcję i naciśnij Enter, aby rozpocząć[/bold cyan]",
            justify="center"
        )
        choice = utils.get_single_char_input_with_prompt(prompt_txt)

        if choice.isdigit() and 1 <= int(choice) <= 4:
            idx = int(choice) - 1
            if config.TARGET_IS_IP and idx < 3:
                msg = "[bold yellow]Nie można włączyć narzędzi pasywnych dla IP.[/bold yellow]"
                utils.console.print(Align.center(msg))
            else:
                config.selected_phase1_tools[idx] ^= 1
        elif choice.lower() == "s":
            display_phase1_settings_menu(display_banner_func)
        elif choice.lower() == "q":
            sys.exit(0)
        elif choice.lower() == "b":
            return False
        elif choice == "\r":
            if any(config.selected_phase1_tools):
                return True
            else:
                msg = "[bold yellow]Wybierz co najmniej jedno narzędzie.[/bold yellow]"
                utils.console.print(Align.center(msg))
        else:
            utils.console.print(
                Align.center("[bold yellow]Nieprawidłowa opcja.[/bold yellow]")
            )
        time.sleep(0.1)


def display_phase1_settings_menu(display_banner_func):
    """Wyświetla menu ustawień specyficznych dla Fazy 1."""
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 1[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        wordlist_display = f"[dim]{config.WORDLIST_PHASE1}[/dim]"
        if config.USER_CUSTOMIZED_WORDLIST_PHASE1:
            wordlist_display = (f"[bold green]{config.WORDLIST_PHASE1} (Użytkownika)[/bold green]")
        elif config.SAFE_MODE:
            wordlist_display = (f"[bold yellow]{config.SMALL_WORDLIST_PHASE1} (Safe Mode)[/bold yellow]")

        resolvers_display = f"[dim]{config.RESOLVERS_FILE}[/dim]"
        if config.USER_CUSTOMIZED_RESOLVERS:
            resolvers_display = (f"[bold green]{config.RESOLVERS_FILE} (Użytkownika)[/bold green]")

        table.add_row("[1]", f"Lista słów (Puredns): {wordlist_display}")
        table.add_row("[2]", f"Plik resolverów (Puredns): {resolvers_display}")
        table.add_section()
        table.add_row("[\fb]", "Powrót do menu Fazy 1")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center")
        )

        if choice == "1":
            new_path = Prompt.ask(
                "[bold cyan]Podaj ścieżkę do listy słów[/bold cyan]",
                default=config.WORDLIST_PHASE1,
            )
            if os.path.isfile(new_path):
                config.WORDLIST_PHASE1 = new_path
                config.USER_CUSTOMIZED_WORDLIST_PHASE1 = True
            else:
                utils.console.print(Align.center("[bold red]Plik nie istnieje.[/bold red]"))
                time.sleep(1)
        elif choice == "2":
            new_path = Prompt.ask(
                "[bold cyan]Podaj ścieżkę do pliku resolverów[/bold cyan]",
                default=config.RESOLVERS_FILE,
            )
            if os.path.isfile(new_path):
                config.RESOLVERS_FILE = new_path
                config.USER_CUSTOMIZED_RESOLVERS = True
            else:
                utils.console.print(Align.center("[bold red]Plik nie istnieje.[/bold red]"))
                time.sleep(1)
        elif choice.lower() == "b":
            break

