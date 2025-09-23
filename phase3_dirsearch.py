#!/usr/bin/env python3

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
# --- Wyciszenie ostrzeżeń o nieweryfikowanym HTTPS ---
import urllib3
from rich.align import Align
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from urllib3.exceptions import InsecureRequestWarning

# Importy z naszego projektu
import config
import utils

urllib3.disable_warnings(InsecureRequestWarning)
# --- Koniec wyciszania ---

# --- Wzorce regularne ---
ansi_escape_pattern = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
DIRSEARCH_RESULT_PATTERN = re.compile(
    r"^\[\d{2}:\d{2}:\d{2}\]\s+"
    r"(\d{3})\s+"
    r"(?:-\s*\d+B\s*-\s*)?"
    r"(https?://\S+)"
    r"(?:\s*->\s*(https?://\S+))?"
    r"(?:.*$|$)"
)
GENERIC_URL_PATTERN = re.compile(r"(https?://[^\s/$.?#].[^\s]*)")


def _detect_wildcard_response(target_url: str) -> Dict[str, Any]:
    wildcard_params: Dict[str, Any] = {}
    random_path = f"{uuid.uuid4().hex[:8]}-{uuid.uuid4().hex[:8]}"
    test_url = f"{target_url.rstrip('/')}/{random_path}"

    try:
        session = requests.Session()
        headers_list = utils.get_random_browser_headers()
        headers = {h.split(": ")[0]: h.split(": ")[1] for h in headers_list}
        headers["User-Agent"] = utils.user_agent_rotator.get()

        res = session.get(
            test_url, headers=headers, verify=False, timeout=15, allow_redirects=False
        )

        if res.is_redirect and (final_url := res.headers.get("Location")):
            if final_url.startswith("/"):
                base_url = "/".join(target_url.split("/")[:3])
                final_url = f"{base_url}{final_url}"
            res = session.get(final_url, headers=headers, verify=False, timeout=15)

        if res.status_code in [200, 301, 302, 401, 403]:
            wildcard_params["status"] = res.status_code
            wildcard_params["size"] = len(res.content)
            utils.log_and_echo(
                f"Wykryto wildcard dla {target_url}: "
                f"Status={res.status_code}, Rozmiar={len(res.content)}", "DEBUG",
            )
        else:
            utils.log_and_echo(
                f"Brak wildcard dla {target_url} (Status: {res.status_code}).", "DEBUG"
            )

    except requests.RequestException as e:
        utils.log_and_echo(f"Błąd detekcji wildcard dla {target_url}: {e}", "WARN")

    return wildcard_params


def _parse_tool_output_line(
    line: str, tool_name: str, base_url: Optional[str] = None
) -> Optional[str]:
    cleaned = ansi_escape_pattern.sub("", line).strip()
    if not cleaned or ":: Progress:" in cleaned or "Target: " in cleaned:
        return None

    full_url = None
    if tool_name == "Feroxbuster":
        match = re.match(r"^\s*(\d{3})\s+\S+\s+\S+l\s+\S+w\s+\S+c\s+(https?:\/\/\S+)", cleaned)
        if match: full_url = match.group(2)
    elif tool_name == "Dirsearch":
        match = DIRSEARCH_RESULT_PATTERN.match(cleaned)
        if match: full_url = match.group(3) or match.group(2)
    elif tool_name in ["Ffuf", "Gobuster"]:
        path = cleaned.split()[0].strip()
        if base_url and not path.isdigit() and not path.startswith("http"):
            full_url = f"{base_url.rstrip('/')}{'/' if not path.startswith('/') else ''}{path}"

    if not full_url and (generic_match := GENERIC_URL_PATTERN.search(cleaned)):
        full_url = generic_match.group(1)

    return full_url.strip().rstrip("/") if full_url else None


def _run_and_parse_dir_tool(
    tool_name: str, command: List[str], target_url: str, timeout: int
) -> Tuple[str, List[str]]:
    results: Set[str] = set()
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in command)
    utils.console.print(
        f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] [dim white]{cmd_str}[/dim white]"
    )
    try:
        process = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="ignore"
        )
        for line in process.stdout.splitlines():
            if parsed_url := _parse_tool_output_line(line, tool_name, target_url):
                results.add(parsed_url)
        if process.returncode == 0:
            utils.console.print(
                f"[bold green]✅ {tool_name} zakończył. Znaleziono {len(results)} URLi.[/bold green]"
            )
        else:
            utils.log_and_echo(f"{tool_name} zakończył z błędem.", "WARN")
    except subprocess.TimeoutExpired:
        utils.log_and_echo(f"{tool_name} przekroczył limit czasu.", "WARN")
    except Exception as e:
        utils.log_and_echo(f"Błąd wykonania {tool_name}: {e}", "ERROR")

    return tool_name, sorted(list(results))


def _handle_waf_block_detection(
    executor: ThreadPoolExecutor, futures: Dict[Future, str]
) -> str:
    """Obsługuje interakcję z użytkownikiem po wykryciu blokady WAF."""
    panel_msg = (
        "[bold red]WYKRYTO BLOKADĘ WAF/IPS![/bold red]\n"
        "[yellow]Odpowiedzi serwera przestały być spójne. Skan wstrzymany.[/yellow]"
    )
    utils.console.print(
        Align.center(
            Panel(panel_msg, title="[bold red]KRYTYCZNE OSTRZEŻENIE[/bold red]")
        )
    )

    for future in futures:
        future.cancel()
    executor.shutdown(wait=False, cancel_futures=True)

    choice = Prompt.ask(
        "[bold cyan]Wybierz akcję[/bold cyan]",
        choices=["i", "q"], default="q",
        console=utils.console,
    )
    # i = Zignoruj i kontynuuj (niezalecane)
    # q = Zatrzymaj fazę i wróć do menu
    return "stop" if choice == "q" else "continue"


def start_dir_search(
    urls: List[str],
    progress_obj: Optional[Progress] = None,
    main_task_id: Optional[TaskID] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:

    results_by_tool: Dict[str, List[str]] = {
        "Ffuf": [], "Feroxbuster": [], "Dirsearch": [], "Gobuster": [],
    }

    current_wordlist = config.WORDLIST_PHASE3
    if config.SAFE_MODE and not config.USER_CUSTOMIZED_WORDLIST_PHASE3:
        shuffled_path = utils.shuffle_wordlist(config.SMALL_WORDLIST_PHASE3, config.REPORT_DIR)
        current_wordlist = shuffled_path or config.SMALL_WORDLIST_PHASE3
        if shuffled_path:
            config.TEMP_FILES_TO_CLEAN.append(current_wordlist)

    tool_configs = [
        {"name": "Ffuf", "enabled": config.selected_phase3_tools[0], "base_cmd": [
            "ffuf", "-recursion", "-recursion-depth", str(config.RECURSION_DEPTH_P3)]},
        {"name": "Feroxbuster", "enabled": config.selected_phase3_tools[1],
            "base_cmd": ["feroxbuster", "--no-state"]},
        {"name": "Dirsearch", "enabled": config.selected_phase3_tools[2],
            "base_cmd": ["dirsearch", "--full-url"]},
        {"name": "Gobuster", "enabled": config.selected_phase3_tools[3],
            "base_cmd": ["gobuster", "dir", "--no-progress"]},
    ]

    waf_monitors: Dict[str, utils.WafHealthMonitor] = {}
    if config.WAF_CHECK_ENABLED and config.SAFE_MODE:
        unique_hosts = {"/".join(url.split("/")[:3]) for url in urls}
        for host in unique_hosts:
            monitor = utils.WafHealthMonitor(host)
            monitor.start()
            waf_monitors[host] = monitor

    try:
        with ThreadPoolExecutor(max_workers=config.THREADS) as executor:
            futures_map: Dict[Future, str] = {}
            for url in urls:
                validated_url = url if url.startswith(("http://", "https://")) else f"https://{url}"
                wildcard = _detect_wildcard_response(validated_url)

                for cfg in tool_configs:
                    if cfg["enabled"]:
                        cmd = list(cfg["base_cmd"])
                        threads = "1" if config.SAFE_MODE else str(config.THREADS)
                        ua_header = f"User-Agent: {utils.user_agent_rotator.get()}"

                        if cfg["name"] == "Ffuf":
                            cmd.extend(["-w", f"{current_wordlist}:FUZZ", "-t", threads])
                            if config.SAFE_MODE: cmd.extend(["-p", "0.5-2.5"])  # Jitter
                            cmd.extend(["-H", ua_header])
                            if size := wildcard.get("size"): cmd.extend(["-fs", str(size)])
                            if status := wildcard.get("status"): cmd.extend(["-fc", str(status)])

                        elif cfg["name"] == "Feroxbuster":
                            cmd.extend(["-w", current_wordlist, "-t", threads])
                            cmd.extend(["-a", utils.user_agent_rotator.get()])
                            if size := wildcard.get("size"): cmd.extend(["-S", str(size)])
                            if status := wildcard.get("status"): cmd.extend(["-C", str(status)])

                        elif cfg["name"] == "Dirsearch":
                            cmd.extend(["-w", current_wordlist, "-t", threads])
                            if config.SAFE_MODE: cmd.extend(["--delay", "1-2.5"])
                            if status := wildcard.get("status"): cmd.extend(["--exclude-status", str(status)])

                        elif cfg["name"] == "Gobuster":
                            cmd.extend(["-w", current_wordlist, "-t", threads])
                            if config.SAFE_MODE: cmd.extend(["--delay", "1500ms"])
                            if status := wildcard.get("status"): cmd.extend(["-b", str(status)])

                        final_url = f"{validated_url}/FUZZ" if cfg["name"] == "Ffuf" else validated_url
                        cmd.extend(["-u", final_url])
                        future = executor.submit(
                            _run_and_parse_dir_tool, cfg["name"], cmd,
                            validated_url, config.TOOL_TIMEOUT_SECONDS
                        )
                        futures_map[future] = url

            for future in as_completed(futures_map):
                host_target = "/".join(futures_map[future].split("/")[:3])
                if monitor := waf_monitors.get(host_target):
                    if monitor.is_blocked_event.is_set():
                        if _handle_waf_block_detection(executor, futures_map) == "stop":
                            break

                try:
                    tool_name, tool_results = future.result()
                    results_by_tool[tool_name].extend(tool_results)
                except Exception as e:
                    utils.log_and_echo(f"Błąd w wątku Fazy 3: {e}", "ERROR")
                if progress_obj and main_task_id is not None:
                    progress_obj.update(main_task_id, advance=1)
    finally:
        for monitor in waf_monitors.values():
            monitor.stop()

    all_found_urls = {url for url_list in results_by_tool.values() for url in url_list}
    final_results = {
        "results_by_tool": results_by_tool,
        "all_dirsearch_results": sorted(list(all_found_urls)),
    }

    verified_data = []
    if all_found_urls:
        utils.console.print(Align.center("[bold cyan]Weryfikuję URL-e (HTTPX)...[/bold cyan]"))
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, dir=config.REPORT_DIR, suffix=".txt", prefix="p3_"
        ) as temp_f:
            temp_f.write("\n".join(all_found_urls))
            temp_file_path = temp_f.name
        config.TEMP_FILES_TO_CLEAN.append(temp_file_path)

        httpx_output_file = os.path.join(config.REPORT_DIR, "httpx_results_phase3.txt")
        httpx_command = ["httpx", "-l", temp_file_path, "-silent", "-json", "-status-code"]

        from phase1_subdomain import _execute_tool_command
        if httpx_result_file := _execute_tool_command(
            "Httpx (P3)", httpx_command, httpx_output_file, config.TOOL_TIMEOUT_SECONDS
        ):
            if os.path.exists(httpx_result_file):
                with open(httpx_result_file, "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            if "url" in data and "status_code" in data:
                                verified_data.append(
                                    {"url": data["url"], "status_code": data["status_code"]}
                                )
                        except json.JSONDecodeError: continue

    utils.log_and_echo(f"Ukończono fazę 3. Znaleziono {len(all_found_urls)} URLi.", "INFO")
    return final_results, verified_data


def display_phase3_tool_selection_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold magenta]Faza 3: Wyszukiwanie Katalogów[/bold magenta]"))
        )
        safe_mode_status = ("[bold green]WŁĄCZONY[/bold green]" if config.SAFE_MODE
                            else "[bold red]WYŁĄCZONY[/bold red]")
        utils.console.print(
            Align.center(f"Cel: [bold green]{config.ORIGINAL_TARGET}[/bold green] | "
                         f"Tryb bezpieczny: {safe_mode_status}")
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        for i, tool_name in enumerate(["Ffuf", "Feroxbuster", "Dirsearch", "Gobuster"]):
            status = ("[bold green]✓[/bold green]" if config.selected_phase3_tools[i]
                      else "[bold red]✗[/bold red]")
            table.add_row(f"[{i+1}]", f"{status} {tool_name}")

        table.add_section()
        table.add_row("[\fs]", "[bold magenta]Ustawienia Fazy 3[/bold magenta]")
        table.add_row("[\fb]", "Powrót do menu")
        table.add_row("[\fq]", "Wyjdź")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text.from_markup("[bold cyan]Wybierz opcję i naciśnij Enter[/bold cyan]", justify="center")
        )

        if choice.isdigit() and 1 <= int(choice) <= 4:
            config.selected_phase3_tools[int(choice) - 1] ^= 1
        elif choice.lower() == "s":
            display_phase3_settings_menu(display_banner_func)
        elif choice.lower() == "q":
            sys.exit(0)
        elif choice.lower() == "b":
            return False
        elif choice == "\r":
            if any(config.selected_phase3_tools):
                return True
            else:
                utils.console.print(Align.center("[bold yellow]Wybierz co najmniej jedno narzędzie.[/bold yellow]"))
        else:
            utils.console.print(Align.center("[bold yellow]Nieprawidłowa opcja.[/bold yellow]"))
        time.sleep(0.1)


def display_phase3_settings_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 3[/bold cyan]")))
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        wordlist_display = (f"[bold green]{config.WORDLIST_PHASE3}[/bold green]"
                            if config.USER_CUSTOMIZED_WORDLIST_PHASE3
                            else f"[bold yellow]{config.SMALL_WORDLIST_PHASE3} (Safe Mode)[/bold yellow]"
                            if config.SAFE_MODE else f"[dim]{config.WORDLIST_PHASE3}[/dim]")

        safe_mode_status = ("[bold green]✓[/bold green]" if config.SAFE_MODE else "[bold red]✗[/bold red]")
        waf_check_status = ("[bold green]✓[/bold green]" if config.WAF_CHECK_ENABLED else "[bold red]✗[/bold red]")

        table.add_row("[1]", f"[{safe_mode_status}] Tryb bezpieczny")
        table.add_row("[2]", f"Lista słów: {wordlist_display}")
        table.add_row("[3]", f"Głębokość rekursji (Ffuf): {config.RECURSION_DEPTH_P3}")
        table.add_row("[4]", f"[{waf_check_status}] Włącz monitor blokad WAF (w Safe Mode)")
        table.add_section()
        table.add_row("[\fb]", "Powrót do menu Fazy 3")
        utils.console.print(Align.center(table))

        choice = utils.get_single_char_input_with_prompt(
            Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center")
        )
        if choice == "1":
            config.SAFE_MODE = not config.SAFE_MODE
            utils.handle_safe_mode_tor_check()
        elif choice == "2":
            new_path = Prompt.ask(
                "[bold cyan]Podaj nową ścieżkę do listy słów[/bold cyan]",
                default=config.WORDLIST_PHASE3,
            )
            if os.path.isfile(new_path):
                config.WORDLIST_PHASE3 = new_path
                config.USER_CUSTOMIZED_WORDLIST_PHASE3 = True
            else:
                utils.console.print(Align.center("[bold red]Plik nie istnieje.[/bold red]"))
                time.sleep(1)
        elif choice == "3":
            new_depth = Prompt.ask(
                "[bold cyan]Podaj głębokość rekursji[/bold cyan]",
                default=str(config.RECURSION_DEPTH_P3),
            )
            if new_depth.isdigit():
                config.RECURSION_DEPTH_P3 = int(new_depth)
                config.USER_CUSTOMIZED_RECURSION_DEPTH_P3 = True
        elif choice == "4":
            config.WAF_CHECK_ENABLED = not config.WAF_CHECK_ENABLED
        elif choice.lower() == "b":
            break
