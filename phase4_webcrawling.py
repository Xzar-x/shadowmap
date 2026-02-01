#!/usr/bin/env python3

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, cast
from urllib.parse import urlparse

from rich.align import Align
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

# Importy z naszego projektu
import config
import utils


def _parse_katana_json_output(json_file_path: str) -> List[str]:
    """
    Parsuje plik JSON wygenerowany przez Katana.
    Katana z -jsonl generuje JSONL (jedna linia = jeden obiekt).
    Format: {"timestamp": "...", "request": {...}, "response": {...}, "endpoint": "http://..."}
    """
    results: Set[str] = set()

    if not os.path.exists(json_file_path):
        return []

    try:
        with open(json_file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    # Katana może używać różnych kluczy w zależności od wersji
                    url = (
                        obj.get("endpoint")
                        or obj.get("url")
                        or obj.get("request", {}).get("endpoint", "")
                    )
                    if url and url.startswith("http"):
                        results.add(url.strip())
                except json.JSONDecodeError:
                    # Fallback: jeśli linia wygląda jak URL
                    if line.startswith("http"):
                        results.add(line)
                    continue
    except Exception as e:
        utils.log_and_echo(f"Błąd parsowania JSON Katana: {e}", "WARN")

    return list(results)


def _run_and_parse_crawl_tool(
    tool_name: str,
    command: List[str],
    target_url: str,
    timeout: int,
    input_text: Optional[str] = None,
    json_output_file: Optional[str] = None,
) -> List[str]:
    """
    Uruchamia narzędzie do web crawlingu i parsuje jego output.
    Obsługuje również narzędzia wymagające danych na STDIN (input_text).
    Preferuje JSON output dla większej precyzji (Enterprise Grade).
    """
    results: Set[str] = set()
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in command)

    # Logowanie z informacją o pipingu, jeśli występuje
    log_cmd = cmd_str
    if input_text:
        log_cmd = f'echo "{input_text.strip()}" | {cmd_str}'

    utils.console.print(
        f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] "
        f"[dim white]{log_cmd}[/dim white]"
    )

    try:
        # Uruchomienie procesu z opcjonalnym inputem
        process = subprocess.run(
            command,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="ignore",
        )

        if process.stderr:
            # Loguj błędy, ale nie panikuj, crawlery często rzucają warningami
            utils.log_and_echo(
                f"STDERR ({tool_name}): {process.stderr[:200]}...", "DEBUG"
            )

        # ENTERPRISE: Preferuj parsowanie JSON jeśli dostępne (Katana)
        if (
            json_output_file
            and os.path.exists(json_output_file)
            and tool_name == "Katana"
        ):
            json_results = _parse_katana_json_output(json_output_file)
            for url in json_results:
                if utils.is_target_in_scope(url):
                    results.add(url)
            utils.log_and_echo(
                f"{tool_name}: Sparsowano {len(json_results)} wyników z JSON", "DEBUG"
            )
        else:
            # Fallback do parsowania regex
            output_lines = process.stdout.splitlines()

            for line in output_lines:
                line = line.strip()
                if not line:
                    continue

                # Usuń kody kolorów ANSI
                ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
                clean_line = ansi_escape.sub("", line)

                found_url = ""

                if tool_name == "ParamSpider":
                    # ParamSpider zwraca: [green]URL[/green] lub po prostu URL
                    if clean_line.startswith("http"):
                        found_url = clean_line

                elif tool_name == "LinkFinder":
                    # LinkFinder: zazwyczaj " Link: http..." lub po prostu w outputcie
                    if "http" in clean_line:
                        match = re.search(r"(https?://[\w\.-]+\S+)", clean_line)
                        if match:
                            found_url = match.group(1)

                elif tool_name in ["Katana", "Hakrawler", "Gauplus"]:
                    # Te narzędzia zazwyczaj wypluwają czyste URL-e
                    if clean_line.startswith("http"):
                        found_url = clean_line

                # --- KLUCZOWE: FILTROWANIE ZAKRESU (SCOPE) ---
                if found_url:
                    # Normalizacja
                    found_url = found_url.strip()

                    # Sprawdź, czy URL jest w zakresie
                    if utils.is_target_in_scope(found_url):
                        results.add(found_url)

    except subprocess.TimeoutExpired:
        utils.console.print(f"[yellow]Timeout dla {tool_name} na {target_url}[/yellow]")
    except Exception as e:
        utils.console.print(f"[red]Błąd uruchamiania {tool_name}: {e}[/red]")

    return sorted(list(results))


def start_web_crawl(
    targets: List[str],
    progress_obj: Optional[Progress] = None,
    main_task_id: Optional[TaskID] = None,
) -> Dict[str, Any]:
    """
    Główna funkcja Fazy 4.
    """
    utils.console.print(
        Align.center("[bold green]Rozpoczynam Fazę 4 - Web Crawling[/bold green]")
    )

    # Globalny kontener na wyniki
    all_crawled_urls: Set[str] = set()
    parameters_found: Set[str] = set()
    js_files_found: Set[str] = set()
    api_endpoints_found: Set[str] = set()
    interesting_paths_found: Set[str] = set()

    # Pobierz globalny User-Agent (uwzględnia flagę custom)
    current_ua = utils.user_agent_rotator.get()

    tools_to_run: List[Dict[str, Any]] = []

    # 1. Katana - ENTERPRISE: JSON output dla precyzyjnego parsowania
    if config.selected_phase4_tools[0]:
        base_cmd = ["katana", "-silent", "-jc", "-jsonl"]  # JSONL output
        # Dodaj UA
        base_cmd.extend(["-H", f"User-Agent: {current_ua}"])

        if config.CRAWL_DEPTH_P4 > 1:
            base_cmd.extend(["-d", str(config.CRAWL_DEPTH_P4)])

        if config.USE_HEADLESS_BROWSER:
            base_cmd.append("-headless")

        tools_to_run.append(
            {
                "name": "Katana",
                "cmd_template": base_cmd,
                "use_stdin": False,
                "arg_format": ["-u", "TARGET"],
                "use_json_output": True,  # Flag dla JSON output
            }
        )

    # 2. Hakrawler
    if config.selected_phase4_tools[1]:
        base_cmd = ["hakrawler", "-subs"]
        # Dodaj UA
        base_cmd.extend(["-h", f"User-Agent: {current_ua}"])

        if config.CRAWL_DEPTH_P4 > 1:
            base_cmd.extend(["-d", str(config.CRAWL_DEPTH_P4)])

        tools_to_run.append(
            {
                "name": "Hakrawler",
                "cmd_template": base_cmd,
                "use_stdin": True,
                "arg_format": [],
            }
        )

    # 3. ParamSpider
    if config.selected_phase4_tools[2]:
        base_cmd = ["paramspider"]
        tools_to_run.append(
            {
                "name": "ParamSpider",
                "cmd_template": base_cmd,
                "use_stdin": False,
                "arg_format": ["-d", "DOMAIN"],
            }
        )

    # 4. LinkFinder
    if config.selected_phase4_tools[3]:
        base_cmd = ["linkfinder", "-o", "cli"]
        tools_to_run.append(
            {
                "name": "LinkFinder",
                "cmd_template": base_cmd,
                "use_stdin": False,
                "arg_format": ["-i", "TARGET"],
            }
        )

    # 5. Gauplus
    if config.selected_phase4_tools[4]:
        base_cmd = ["gauplus", "-t", str(config.THREADS), "--random-agent"]
        if config.USER_CUSTOMIZED_USER_AGENT:
            pass

        tools_to_run.append(
            {
                "name": "Gauplus",
                "cmd_template": base_cmd,
                "use_stdin": True,
                "arg_format": [],
            }
        )

    # Wykonanie zadań
    with ThreadPoolExecutor(max_workers=config.THREADS) as executor:
        futures_map = {}

        for target in targets:
            parsed = urlparse(target)
            domain = parsed.netloc or target

            for tool in tools_to_run:
                tool_name = cast(str, tool.get("name"))
                cmd_template = cast(List[str], tool.get("cmd_template"))
                use_stdin = cast(bool, tool.get("use_stdin"))
                arg_format = cast(List[str], tool.get("arg_format"))
                use_json_output = tool.get("use_json_output", False)

                exe_name = config.TOOL_EXECUTABLE_MAP.get(tool_name)

                if tool_name == "LinkFinder" and "linkfinder" in config.MISSING_TOOLS:
                    continue
                if tool_name == "ParamSpider" and "paramspider" in config.MISSING_TOOLS:
                    continue

                if exe_name and exe_name in config.MISSING_TOOLS:
                    continue

                cmd = cmd_template.copy()
                input_str = None
                json_output_file = None

                # ENTERPRISE: Generowanie ścieżki JSON dla narzędzi wspierających
                if use_json_output:
                    phase4_dir = os.path.join(config.REPORT_DIR, "faza4_webcrawling")
                    os.makedirs(phase4_dir, exist_ok=True)
                    sanitized_target = (
                        re.sub(r"https?://", "", target)
                        .replace("/", "_")
                        .replace(":", "_")
                    )
                    json_output_file = os.path.join(
                        phase4_dir,
                        f"{tool_name.lower()}_{sanitized_target}_{uuid.uuid4().hex[:8]}.jsonl",
                    )
                    # Dodaj flagę output do komendy Katana
                    if tool_name == "Katana":
                        cmd.extend(["-o", json_output_file])

                if arg_format:
                    for arg in arg_format:
                        if arg == "TARGET":
                            cmd.append(target)
                        elif arg == "DOMAIN":
                            cmd.append(domain)
                        else:
                            cmd.append(arg)

                if use_stdin:
                    input_str = target

                future = executor.submit(
                    _run_and_parse_crawl_tool,
                    tool_name,
                    cmd,
                    target,
                    config.TOOL_TIMEOUT_SECONDS,
                    input_str,
                    json_output_file,  # ENTERPRISE: Przekazanie ścieżki JSON
                )
                futures_map[future] = tool_name

        for future in as_completed(futures_map):
            t_name = futures_map[future]
            try:
                urls = future.result()
                all_crawled_urls.update(urls)

                for u in urls:
                    u_lower = u.lower()
                    if "=" in u:
                        parameters_found.add(u)
                    if u_lower.endswith(".js"):
                        js_files_found.add(u)
                    if "api" in u_lower or "/v1/" in u_lower or "graphql" in u_lower:
                        api_endpoints_found.add(u)

                    interesting_keywords = [
                        "admin",
                        "login",
                        "config",
                        "env",
                        "dashboard",
                        "secret",
                    ]
                    if any(k in u_lower for k in interesting_keywords):
                        interesting_paths_found.add(u)

            except Exception as e:
                utils.log_and_echo(f"Błąd przetwarzania wyników {t_name}: {e}", "ERROR")

            if progress_obj and main_task_id is not None:
                progress_obj.update(main_task_id, advance=1)

    results = {
        "all_urls": sorted(list(all_crawled_urls)),
        "parameters": sorted(list(parameters_found)),
        "js_files": sorted(list(js_files_found)),
        "api_endpoints": sorted(list(api_endpoints_found)),
        "interesting_paths": sorted(list(interesting_paths_found)),
    }

    utils.log_and_echo(
        f"Faza 4 zakończona. Znaleziono łącznie {len(all_crawled_urls)} unikalnych URLi.",
        "INFO",
    )
    return results


def display_phase4_tool_selection_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(
                Panel.fit(
                    "[bold magenta]Faza 4: Web Crawling & Discovery[/bold magenta]"
                )
            )
        )
        utils.console.print(
            Align.center(f"Cel: [bold green]{config.ORIGINAL_TARGET}[/bold green]")
        )

        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        tool_names = [
            "Katana (Aktywny crawler)",
            "Hakrawler (Aktywny crawler)",
            "ParamSpider (Parametry)",
            "LinkFinder (Analiza JS)",
            "Gauplus (Pasywne z archiwów)",
        ]

        for i, tool_name in enumerate(tool_names):
            idx = i
            is_selected = config.selected_phase4_tools[idx]

            executable = ""
            if "Katana" in tool_name:
                executable = "katana"
            elif "Hakrawler" in tool_name:
                executable = "hakrawler"
            elif "ParamSpider" in tool_name:
                executable = "paramspider"
            elif "LinkFinder" in tool_name:
                executable = "linkfinder"
            elif "Gauplus" in tool_name:
                executable = "gauplus"

            is_missing = executable in config.MISSING_TOOLS

            status_icon = (
                "[bold green]✓[/bold green]"
                if is_selected
                else "[bold red]✗[/bold red]"
            )
            display_str = f"{status_icon} {tool_name}"

            style = ""
            if is_missing:
                display_str = f"[dim]✗ {tool_name} (niedostępne)[/dim]"
                style = "dim"

            table.add_row(f"[bold cyan][{i+1}][/bold cyan]", display_str, style=style)

        table.add_section()
        table.add_row(
            "[bold cyan][\fs][/bold cyan]",
            "[bold magenta]Ustawienia Fazy 4[/bold magenta]",
        )
        table.add_row("[bold cyan][\fb][/bold cyan]", "Powrót do menu")
        table.add_row("[bold cyan][\fq][/bold cyan]", "Wyjdź")

        utils.console.print(Align.center(table))
        prompt = Text.from_markup(
            "[bold cyan]Wybierz opcję[/bold cyan]", justify="center"
        )
        choice = utils.get_single_char_input_with_prompt(prompt)

        if choice.isdigit() and 1 <= int(choice) <= 5:
            idx = int(choice) - 1
            tool_n = tool_names[idx]
            executable = ""
            if "Katana" in tool_n:
                executable = "katana"
            elif "Hakrawler" in tool_n:
                executable = "hakrawler"
            elif "ParamSpider" in tool_n:
                executable = "paramspider"
            elif "LinkFinder" in tool_n:
                executable = "linkfinder"
            elif "Gauplus" in tool_n:
                executable = "gauplus"

            if executable in config.MISSING_TOOLS:
                utils.console.print(Align.center("[red]Narzędzie niedostępne.[/red]"))
                time.sleep(1)
            else:
                config.selected_phase4_tools[idx] ^= 1

        elif choice.lower() == "s":
            display_phase4_settings_menu(display_banner_func)
        elif choice.lower() == "q":
            sys.exit(0)
        elif choice.lower() == "b":
            return False
        elif choice == "\r":
            if any(config.selected_phase4_tools):
                return True
            else:
                utils.console.print(
                    Align.center(
                        "[yellow]Wybierz co najmniej jedno narzędzie.[/yellow]"
                    )
                )
                time.sleep(1)


def display_phase4_settings_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 4[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        depth_val = (
            f"[bold green]{config.CRAWL_DEPTH_P4}[/bold green]"
            if config.USER_CUSTOMIZED_CRAWL_DEPTH_P4
            else f"[dim]{config.CRAWL_DEPTH_P4}[/dim]"
        )
        headless_val = (
            "[bold green]TAK[/bold green]"
            if config.USE_HEADLESS_BROWSER
            else "[dim]NIE[/dim]"
        )
        threads_val = (
            f"[bold green]{config.THREADS}[/bold green]"
            if config.USER_CUSTOMIZED_THREADS
            else f"[dim]{config.THREADS}[/dim]"
        )

        ua_val = config.CUSTOM_HEADER or "Domyślny (losowy)"
        if config.USER_CUSTOMIZED_USER_AGENT:
            ua_disp = f"[bold green]{ua_val} (Użytkownika)[/bold green]"
        else:
            ua_disp = f"[dim]{ua_val}[/dim]"

        table.add_row(
            "[bold cyan][1][/bold cyan]", f"Głębokość crawlowania: {depth_val}"
        )
        table.add_row(
            "[bold cyan][2][/bold cyan]", f"Headless Browser (Katana): {headless_val}"
        )
        table.add_row("[bold cyan][3][/bold cyan]", f"Wątki: {threads_val}")
        table.add_row("[bold cyan][4][/bold cyan]", f"User-Agent: {ua_disp}")

        table.add_section()
        table.add_row("[bold cyan][\fb][/bold cyan]", "Powrót")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text("Wybierz opcję", justify="center")
        )

        if choice == "1":
            val = Prompt.ask(
                "Podaj głębokość (1-5)", default=str(config.CRAWL_DEPTH_P4)
            )
            if val.isdigit():
                config.CRAWL_DEPTH_P4 = int(val)
                config.USER_CUSTOMIZED_CRAWL_DEPTH_P4 = True
        elif choice == "2":
            config.USE_HEADLESS_BROWSER = not config.USE_HEADLESS_BROWSER
            config.USER_CUSTOMIZED_USE_HEADLESS = True
        elif choice == "3":
            val = Prompt.ask("Liczba wątków", default=str(config.THREADS))
            if val.isdigit():
                config.THREADS = int(val)
                config.USER_CUSTOMIZED_THREADS = True
        elif choice == "4":
            new_ua = Prompt.ask("Podaj User-Agent", default=config.CUSTOM_HEADER)
            if new_ua:
                config.CUSTOM_HEADER = new_ua
                config.USER_CUSTOMIZED_USER_AGENT = True
        elif choice.lower() == "b":
            break
