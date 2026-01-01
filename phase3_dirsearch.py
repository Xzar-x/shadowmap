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
import urllib3
from rich.align import Align
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from urllib3.exceptions import InsecureRequestWarning

import config
import utils

urllib3.disable_warnings(InsecureRequestWarning)

# --- Wzorce regularne ---
ansi_escape_pattern = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
DIRSEARCH_RESULT_PATTERN = re.compile(
    r"^\[\d{2}:\d{2}:\d{2}\]\s+"
    r"(\d{3})\s+"
    r"(?:-\s*(\d+)(B|KB|MB)\s*-\s*)?"
    r"(https?://\S+)"
    r"(?:\s*->\s*(https?://\S+))?"
    r"(?:.*$|$)"
)
GENERIC_URL_PATTERN = re.compile(r"(https?://[^\s/$.?#].[^\s]*)")


def _select_wordlist_based_on_tech(
    detected_technologies: List[str],
) -> str:
    """
    Analizuje technologie i pyta użytkownika o użycie specjalistycznej listy.
    """
    if not detected_technologies:
        return config.WORDLIST_PHASE3

    msg = "[bold cyan]Analizuję technologie pod kątem listy słów...[/bold cyan]"
    utils.console.print(Align.center(msg))

    for tech in detected_technologies:
        tech_lower = tech.split(" ")[0].lower()

        if tech_lower in config.TECH_SPECIFIC_WORDLISTS:
            wordlist_path = config.TECH_SPECIFIC_WORDLISTS[tech_lower]
            if os.path.exists(wordlist_path):
                file_name = os.path.basename(wordlist_path)

                question = (
                    f"Wykryto [bold yellow]{tech}[/bold yellow].\n"
                    f"Użyć listy [bold green]{file_name}[/bold green]?"
                )

                choice = utils.ask_user_decision(
                    question, choices=["y", "n"], default="y"
                )

                if choice == "y":
                    msg = (
                        f"Wybrano listę dla '{tech}': "
                        f"[bold green]{file_name}[/bold green]"
                    )
                    utils.log_and_echo(msg, "INFO")
                    utils.console.print(Align.center(msg))
                    return wordlist_path
                else:
                    msg = "[yellow]Odrzucono. Używam domyślnej listy.[/yellow]"
                    utils.console.print(Align.center(msg, style="bold"))
                    return config.WORDLIST_PHASE3
            else:
                msg = (
                    f"Wykryto '{tech}', ale lista "
                    f"[bold red]{wordlist_path}[/bold red] nie istnieje."
                )
                utils.log_and_echo(msg, "WARN")
                utils.console.print(Align.center(msg))

    msg = "[yellow]Brak dedykowanej listy. Używam domyślnej.[/yellow]"
    utils.console.print(Align.center(msg, style="bold"))
    return config.WORDLIST_PHASE3


def _detect_wildcard_response(target_url: str) -> Dict[str, Any]:
    wildcard_params: Dict[str, Any] = {}
    random_path = f"{uuid.uuid4().hex[:8]}-{uuid.uuid4().hex[:8]}"
    test_url = f"{target_url.rstrip('/')}/{random_path}"

    try:
        session = requests.Session()
        headers_list = utils.get_random_browser_headers()
        headers = {h.split(": ")[0]: h.split(": ")[1] for h in headers_list}

        # ZMIANA: Użycie globalnego UA (rotator lub custom)
        headers["User-Agent"] = utils.user_agent_rotator.get()

        response = session.get(
            test_url,
            headers=headers,
            verify=False,
            timeout=15,
            allow_redirects=False,
        )

        if response.is_redirect:
            final_url = response.headers.get("Location")
            if final_url:
                if final_url.startswith("/"):
                    base_url = "/".join(target_url.split("/")[:3])
                    final_url = f"{base_url}{final_url}"
                response = session.get(
                    final_url, headers=headers, verify=False, timeout=15
                )

        status_code = response.status_code
        content_length = len(response.content)

        if status_code in [200, 301, 302, 401, 403]:
            wildcard_params["status"] = status_code
            wildcard_params["size"] = content_length
            msg = (
                f"Wykryto wildcard dla {target_url}: "
                f"Status={status_code}, Rozmiar={content_length}"
            )
            utils.log_and_echo(msg, "DEBUG")
        else:
            msg = f"Brak wildcard dla {target_url} (Status: {status_code})."
            utils.log_and_echo(msg, "DEBUG")

    except requests.RequestException as e:
        msg = f"Błąd detekcji wildcard dla {target_url}: {e}"
        utils.log_and_echo(msg, "WARN")

    return wildcard_params


def _parse_tool_output_line(
    line: str, tool_name: str, base_url: Optional[str] = None
) -> Optional[str]:
    cleaned_line = ansi_escape_pattern.sub("", line).strip()
    if not cleaned_line or ":: Progress:" in cleaned_line or "Target: " in cleaned_line:
        return None

    full_url = None
    if tool_name == "Feroxbuster":
        parts = cleaned_line.split()
        if (
            len(parts) >= 6
            and parts[0].isdigit()
            and parts[2].endswith("l")
            and parts[4].endswith("c")
        ):
            url = parts[-1]
            if url.startswith("http"):
                full_url = url
    elif tool_name == "Dirsearch":
        match = DIRSEARCH_RESULT_PATTERN.match(cleaned_line)
        if match:
            full_url = match.group(5) or match.group(4)
    elif tool_name in ["Ffuf", "Gobuster"]:
        parts = cleaned_line.split()
        path = parts[0].strip()
        if base_url and not path.isdigit() and not path.startswith("http"):
            full_url = (
                f"{base_url.rstrip('/')}"
                f"{'/' if not path.startswith('/') else ''}{path}"
            )

    if not full_url:
        generic_match = GENERIC_URL_PATTERN.search(cleaned_line)
        if generic_match:
            full_url = generic_match.group(1)

    if full_url:
        try:
            path_part = full_url.split("?")[0].split("#")[0]
            if "." in path_part:
                extension = path_part.split(".")[-1].lower()
                if extension in config.IGNORED_EXTENSIONS:
                    return None
        except Exception:
            pass

    return full_url.strip().rstrip("/") if full_url else None


def _run_and_parse_dir_tool(
    tool_name: str, command: List[str], target_url: str, timeout: int
) -> Tuple[str, List[str]]:
    results: Set[str] = set()
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in command)
    utils.console.print(
        f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] "
        f"[dim white]{cmd_str}[/dim white]"
    )

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="ignore",
        )

        phase3_dir = os.path.join(config.REPORT_DIR, "faza3_dirsearch")
        sanitized_target = re.sub(r"https?://", "", target_url).replace("/", "_")
        sanitized_target = sanitized_target.replace(":", "_")
        raw_output_file = os.path.join(
            phase3_dir, f"{tool_name.lower()}_{sanitized_target}.txt"
        )

        with open(raw_output_file, "w", encoding="utf-8") as f:
            f.write(f"--- Raw output for {tool_name} on {target_url} ---\n\n")
            f.write(process.stdout)
            if process.stderr:
                f.write("\n\n--- STDERR ---\n\n")
                f.write(process.stderr)

        for line in process.stdout.splitlines():
            parsed_url = _parse_tool_output_line(line, tool_name, base_url=target_url)
            if parsed_url:
                results.add(parsed_url)

        if process.returncode == 0:
            msg = f"✅ {tool_name} zakończył. Znaleziono {len(results)} URLi."
            utils.console.print(f"[bold green]{msg}[/bold green]")
        else:
            msg = f"{tool_name} zakończył z błędem " f"(kod: {process.returncode})."
            utils.log_and_echo(msg, "WARN")

    except subprocess.TimeoutExpired:
        msg = f"{tool_name} przekroczył limit czasu ({timeout}s)."
        utils.log_and_echo(msg, "WARN")
    except Exception as e:
        utils.log_and_echo(f"Błąd wykonania {tool_name}: {e}", "ERROR")

    return tool_name, sorted(list(results))


def _handle_waf_block_detection(
    executor: ThreadPoolExecutor, futures: Dict[Future, str]
):
    """Obsługuje interakcję z użytkownikiem po wykryciu blokady WAF."""
    panel_text = (
        "[bold red]WYKRYTO BLOKADĘ WAF/IPS![/bold red]\n"
        "[yellow]Odpowiedzi serwera są niespójne. Skan wstrzymano.[/yellow]"
    )
    utils.console.print(
        Align.center(
            Panel(
                panel_text,
                title="[bold red]KRYTYCZNE OSTRZEŻENIE[/bold red]",
            )
        )
    )

    for future in futures:
        future.cancel()
    executor.shutdown(wait=False, cancel_futures=True)

    choice = Prompt.ask(
        "[bold cyan]Wybierz akcję[/bold cyan]",
        choices=["s", "i", "q"],
        default="q",
        console=utils.console,
    )
    if choice == "q":
        return "stop"
    return "continue"


def start_dir_search(
    urls: List[str],
    technologies: List[str],
    progress_obj: Optional[Progress] = None,
    main_task_id: Optional[TaskID] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    results_by_tool: Dict[str, List[str]] = {
        "Ffuf": [],
        "Feroxbuster": [],
        "Dirsearch": [],
        "Gobuster": [],
    }

    if config.USER_CUSTOMIZED_WORDLIST_PHASE3:
        wordlist = config.WORDLIST_PHASE3
        msg = f"[yellow]Używam listy słów użytkownika: {wordlist}[/yellow]"
        utils.console.print(Align.center(msg))
    else:
        wordlist = _select_wordlist_based_on_tech(technologies)

    if config.SAFE_MODE:
        if wordlist == config.DEFAULT_WORDLIST_PHASE3:
            wordlist = config.SMALL_WORDLIST_PHASE3
        shuffled_path = utils.shuffle_wordlist(wordlist, config.REPORT_DIR)
        if shuffled_path:
            wordlist = shuffled_path
            config.TEMP_FILES_TO_CLEAN.append(shuffled_path)

    tool_configs: List[Dict[str, Any]] = [
        {
            "name": "Ffuf",
            "enabled": config.selected_phase3_tools[0],
            "base_cmd": ["ffuf"],
        },
        {
            "name": "Feroxbuster",
            "enabled": config.selected_phase3_tools[1],
            "base_cmd": ["feroxbuster", "--no-state"],
        },
        {
            "name": "Dirsearch",
            "enabled": config.selected_phase3_tools[2],
            "base_cmd": ["dirsearch", "--full-url"],
        },
        {
            "name": "Gobuster",
            "enabled": config.selected_phase3_tools[3],
            "base_cmd": ["gobuster", "dir", "--no-progress"],
        },
    ]

    waf_monitors: Dict[str, Optional[utils.WafHealthMonitor]] = {}
    if config.WAF_CHECK_ENABLED:
        min_i, max_i = (
            (
                config.WAF_CHECK_INTERVAL_MIN_SAFE,
                config.WAF_CHECK_INTERVAL_MAX_SAFE,
            )
            if config.SAFE_MODE
            else (
                config.WAF_CHECK_INTERVAL_MIN_NORMAL,
                config.WAF_CHECK_INTERVAL_MAX_NORMAL,
            )
        )
        msg = f"Monitor WAF aktywny (interwał: {min_i}-{max_i}s)"
        utils.log_and_echo(msg, "INFO")
        unique_hosts = {"/".join(url.split("/")[:3]) for url in urls}
        for host in unique_hosts:
            new_monitor = utils.WafHealthMonitor(
                host, interval_min=min_i, interval_max=max_i
            )
            new_monitor.start()
            waf_monitors[host] = new_monitor

    try:
        with ThreadPoolExecutor(max_workers=config.THREADS) as executor:
            futures_map: Dict[Future, str] = {}
            for url in urls:
                v_url = url
                if not url.startswith(("http://", "https://")):
                    v_url = f"https://{url}"
                wildcard = _detect_wildcard_response(v_url)

                for cfg in tool_configs:
                    if not cfg["enabled"]:
                        continue
                    cmd = list(cfg["base_cmd"])
                    threads = "1" if config.SAFE_MODE else str(config.THREADS)

                    # ZMIANA: Pobranie globalnego UA (może być custom)
                    current_ua = utils.user_agent_rotator.get()

                    if cfg["name"] == "Ffuf":
                        cmd.extend(["-w", f"{wordlist}:FUZZ", "-t", threads])
                        if config.RECURSION_DEPTH_P3 > 0:
                            cmd.extend(
                                [
                                    "-recursion",
                                    "-recursion-depth",
                                    str(config.RECURSION_DEPTH_P3),
                                ]
                            )
                        if config.SAFE_MODE:
                            cmd.extend(["-p", "0.5-2.5"])

                        cmd.extend(["-H", f"User-Agent: {current_ua}"])

                        if wc_size := wildcard.get("size"):
                            cmd.extend(["-fs", str(wc_size)])
                        if wc_status := wildcard.get("status"):
                            cmd.extend(["-fc", str(wc_status)])
                        cmd.extend(["-u", f"{v_url}/FUZZ"])

                    elif cfg["name"] == "Feroxbuster":
                        cmd.extend(["-w", wordlist, "-t", threads, "-u", v_url])
                        if config.RECURSION_DEPTH_P3 > 0:
                            cmd.extend(["--depth", str(config.RECURSION_DEPTH_P3)])
                        else:
                            cmd.append("--no-recursion")

                        cmd.extend(["-a", current_ua])

                        if not config.FEROXBUSTER_SMART_FILTER:
                            cmd.append("--dont-filter")
                        elif wc_size := wildcard.get("size"):
                            cmd.extend(["-S", str(wc_size)])

                    elif cfg["name"] == "Dirsearch":
                        cmd.extend(["-w", wordlist, "-t", threads, "-u", v_url])
                        if config.RECURSION_DEPTH_P3 > 0:
                            cmd.extend(
                                [
                                    "-r",
                                    "--max-recursion-depth",
                                    str(config.RECURSION_DEPTH_P3),
                                ]
                            )
                        if config.SAFE_MODE:
                            cmd.extend(["--delay", "1-2.5"])

                        # ZMIANA: Dodanie UA dla Dirsearch
                        cmd.extend(["-H", f"User-Agent: {current_ua}"])

                        if not config.DIRSEARCH_SMART_FILTER:
                            cmd.append("--exclude-sizes=0B")
                        elif wc_status := wildcard.get("status"):
                            if wc_status != 200:
                                cmd.extend(["--exclude-status", str(wc_status)])
                            if wc_size := wildcard.get("size"):
                                cmd.extend(["--exclude-lengths", str(wc_size)])

                    elif cfg["name"] == "Gobuster":
                        cmd.extend(["-w", wordlist, "-t", threads, "-k", "-u", v_url])
                        if config.SAFE_MODE:
                            cmd.extend(["--delay", "1500ms"])

                        # ZMIANA: Dodanie UA dla Gobuster
                        cmd.extend(["-a", current_ua])

                        wc_status = wildcard.get("status")
                        if wc_status and wc_status != 404:
                            cmd.extend(["-b", str(wc_status)])

                    future = executor.submit(
                        _run_and_parse_dir_tool,
                        cfg["name"],
                        cmd,
                        v_url,
                        config.TOOL_TIMEOUT_SECONDS,
                    )
                    futures_map[future] = url

            for future in as_completed(futures_map):
                url_target = futures_map[future]
                host_target = "/".join(url_target.split("/")[:3])

                # Użyj nazwy `check_monitor` aby uniknąć konfliktu z `monitor` z definicji klasy
                check_monitor = waf_monitors.get(host_target)
                if check_monitor and check_monitor.is_blocked_event.is_set():
                    action = _handle_waf_block_detection(executor, futures_map)
                    if action == "stop":
                        break
                try:
                    tool_name, tool_results = future.result()
                    results_by_tool[tool_name].extend(tool_results)
                except Exception as e:
                    utils.log_and_echo(f"Błąd w wątku Fazy 3: {e}", "ERROR")
                if progress_obj and main_task_id is not None:
                    progress_obj.update(main_task_id, advance=1)
    finally:
        for m_val in waf_monitors.values():
            if m_val:
                m_val.stop()

    all_found_urls = {url for url_list in results_by_tool.values() for url in url_list}
    final_results = {
        "results_by_tool": results_by_tool,
        "all_dirsearch_results": sorted(list(all_found_urls)),
    }

    verified_data = []
    if all_found_urls:
        msg = "[cyan]Weryfikuję URL-e (HTTPX)...[/cyan]"
        utils.console.print(Align.center(msg))
        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            dir=config.REPORT_DIR,
            suffix=".txt",
            prefix="p3_",
        ) as temp_f:
            temp_f.write("\n".join(all_found_urls))
            temp_file_path = temp_f.name
        config.TEMP_FILES_TO_CLEAN.append(temp_file_path)

        httpx_output_file = os.path.join(config.REPORT_DIR, "httpx_results_phase3.txt")
        httpx_command = [
            "httpx",
            "-l",
            temp_file_path,
            "-silent",
            "-json",
            "-status-code",
        ]

        # ZMIANA: Zawsze ustawiaj UA, nawet jeśli nie Safe Mode
        httpx_ua = utils.user_agent_rotator.get()
        httpx_command.extend(["-H", f"User-Agent: {httpx_ua}"])

        if config.SAFE_MODE:
            httpx_command.extend(["-rate-limit", "10"])
            for header in utils.get_random_browser_headers():
                httpx_command.extend(["-H", header])

        httpx_result_file = utils.execute_tool_command(
            "Httpx (P3)",
            httpx_command,
            httpx_output_file,
            config.TOOL_TIMEOUT_SECONDS,
        )

        if httpx_result_file and os.path.exists(httpx_result_file):
            with open(httpx_result_file, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        if "url" in data and "status_code" in data:
                            verified_data.append(
                                {
                                    "url": data["url"],
                                    "status_code": data["status_code"],
                                }
                            )
                    except json.JSONDecodeError:
                        continue

    msg = (
        f"Faza 3: Znaleziono {len(all_found_urls)} URLi. "
        f"Zweryfikowano {len(verified_data)}."
    )
    utils.log_and_echo(msg, "INFO")
    return final_results, verified_data


def display_phase3_tool_selection_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        title = "[bold magenta]Faza 3: Wyszukiwanie Katalogów[/bold magenta]"
        utils.console.print(Align.center(Panel.fit(title)))
        utils.console.print(
            Align.center(f"Cel: [bold green]{config.ORIGINAL_TARGET}[/bold green]")
        )
        safe_mode = (
            "[bold green]WŁĄCZONY[/bold green]"
            if config.SAFE_MODE
            else "[bold red]WYŁĄCZONY[/bold red]"
        )
        utils.console.print(Align.center(f"Tryb bezpieczny: {safe_mode}"))

        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        tool_names = ["Ffuf", "Feroxbuster", "Dirsearch", "Gobuster"]
        for i, tool_name in enumerate(tool_names):
            status = (
                "[bold green]✓[/bold green]"
                if config.selected_phase3_tools[i]
                else "[bold red]✗[/bold red]"
            )
            table.add_row(f"[bold cyan][{i+1}][/bold cyan]", f"{status} {tool_name}")

        table.add_section()
        table.add_row(
            "[bold cyan][\fs][/bold cyan]",
            "[bold magenta]Ustawienia Fazy 3[/bold magenta]",
        )
        table.add_row("[bold cyan][\fb][/bold cyan]", "Powrót do menu")
        table.add_row("[bold cyan][\fq][/bold cyan]", "Wyjdź")

        utils.console.print(Align.center(table))
        prompt_text = Text.from_markup(
            "[bold cyan]Wybierz opcję i naciśnij Enter[/bold cyan]",
            justify="center",
        )
        choice = utils.get_single_char_input_with_prompt(prompt_text)

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
                utils.console.print(
                    Align.center(
                        "[yellow]Wybierz co najmniej jedno narzędzie.[/yellow]"
                    )
                )
        else:
            utils.console.print(Align.center("[yellow]Nieprawidłowa opcja.[/yellow]"))
        time.sleep(0.1)


def display_phase3_settings_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 3[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        wordlist_disp = (
            f"[bold green]{config.WORDLIST_PHASE3} (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_WORDLIST_PHASE3
            else (
                f"[bold yellow]{config.SMALL_WORDLIST_PHASE3} "
                f"(Safe Mode)[/bold yellow]"
                if config.SAFE_MODE
                else f"[dim]{config.WORDLIST_PHASE3}[/dim]"
            )
        )
        depth_disp = (
            f"[bold green]{config.RECURSION_DEPTH_P3} (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_RECURSION_DEPTH_P3
            else f"[dim]{config.RECURSION_DEPTH_P3}[/dim]"
        )
        ignored_ext_str = ", ".join(config.IGNORED_EXTENSIONS)
        ignored_ext_disp = (
            f"[bold green]{ignored_ext_str} (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_IGNORED_EXTENSIONS
            else f"[dim]{ignored_ext_str}[/dim]"
        )
        dirsearch_filter = (
            "[bold green]✓[/bold green]"
            if config.DIRSEARCH_SMART_FILTER
            else "[bold red]✗[/bold red]"
        )
        ferox_filter = (
            "[bold green]✓[/bold green]"
            if config.FEROXBUSTER_SMART_FILTER
            else "[bold red]✗[/bold red]"
        )
        waf_check = (
            "[bold green]✓[/bold green]"
            if config.WAF_CHECK_ENABLED
            else "[bold red]✗[/bold red]"
        )
        safe_mode = (
            "[bold green]✓[/bold green]"
            if config.SAFE_MODE
            else "[bold red]✗[/bold red]"
        )

        table.add_row("[bold cyan][1][/bold cyan]", f"[{safe_mode}] Tryb bezpieczny")
        table.add_row("[bold cyan][2][/bold cyan]", f"Lista słów: {wordlist_disp}")
        table.add_row("[bold cyan][3][/bold cyan]", f"Głębokość rekursji: {depth_disp}")
        table.add_row(
            "[bold cyan][4][/bold cyan]",
            f"[{dirsearch_filter}] Inteligentne filtrowanie Dirsearch",
        )
        table.add_row(
            "[bold cyan][5][/bold cyan]",
            f"[{ferox_filter}] Inteligentne filtrowanie Feroxbuster",
        )
        table.add_row("[bold cyan][6][/bold cyan]", f"[{waf_check}] Monitor blokad WAF")
        table.add_row(
            "[bold cyan][7][/bold cyan]",
            f"Ignorowane rozszerzenia: {ignored_ext_disp}",
        )
        table.add_section()
        table.add_row("[bold cyan][\fb][/bold cyan]", "Powrót do menu Fazy 3")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center")
        )

        if choice == "1":
            config.SAFE_MODE = not config.SAFE_MODE
            utils.handle_safe_mode_tor_check()
        elif choice == "2":
            new_path = Prompt.ask(
                "[bold cyan]Podaj ścieżkę do listy słów[/bold cyan]",
                default=config.WORDLIST_PHASE3,
            )
            if os.path.isfile(new_path):
                config.WORDLIST_PHASE3 = new_path
                config.USER_CUSTOMIZED_WORDLIST_PHASE3 = True
            else:
                utils.console.print(
                    Align.center("[bold red]Plik nie istnieje.[/bold red]")
                )
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
            config.DIRSEARCH_SMART_FILTER = not config.DIRSEARCH_SMART_FILTER
        elif choice == "5":
            config.FEROXBUSTER_SMART_FILTER = not config.FEROXBUSTER_SMART_FILTER
        elif choice == "6":
            config.WAF_CHECK_ENABLED = not config.WAF_CHECK_ENABLED
        elif choice == "7":
            current_ext_str = ",".join(config.IGNORED_EXTENSIONS)
            new_ext_str = Prompt.ask(
                "[bold cyan]Podaj ignorowane rozszerzenia "
                "(po przecinku)[/bold cyan]",
                default=current_ext_str,
            )
            config.IGNORED_EXTENSIONS = [
                ext.strip().lower() for ext in new_ext_str.split(",") if ext.strip()
            ]
            config.USER_CUSTOMIZED_IGNORED_EXTENSIONS = True
        elif choice.lower() == "b":
            break
