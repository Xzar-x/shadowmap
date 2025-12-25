#!/usr/bin/env python3

import os
import re
import subprocess
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set
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


def _run_and_parse_crawl_tool(
    tool_name: str, command: List[str], target_url: str, timeout: int
) -> List[str]:
    """
    Uruchamia narzędzie do web crawlingu i parsuje jego output.
    """
    results: Set[str] = set()
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in command)
    utils.console.print(
        f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] "
        f"[dim white]{cmd_str}[/dim white]"
    )

    try:
        # ParamSpider i niektóre narzędzia mogą wymagać uruchomienia w shellu,
        # ale subprocess.run z listą argumentów jest bezpieczniejszy.
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="ignore",
        )

        phase4_dir = os.path.join(config.REPORT_DIR, "faza4_webcrawling")
        sanitized_target = re.sub(r"https?://", "", target_url).replace("/", "_")
        sanitized_target = sanitized_target.replace(":", "_")
        raw_output_file = os.path.join(
            phase4_dir, f"{tool_name.lower()}_{sanitized_target}.txt"
        )

        with open(raw_output_file, "w", encoding="utf-8") as f:
            f.write(f"--- Raw output for {tool_name} on {target_url} ---\n\n")
            f.write(process.stdout)
            if process.stderr:
                f.write("\n\n--- STDERR ---\n\n")
                f.write(process.stderr)

        # Parsowanie wyników
        # Większość narzędzi zwraca jeden URL na linię
        url_pattern = re.compile(r"https?://[^\s\"'<>]+")

        # Wstępne filtrowanie linii, aby usunąć logi narzędzi (np. [INF], [ERR])
        lines = process.stdout.splitlines()

        # Specjalna obsługa LinkFinder
        if tool_name == "LinkFinder":
            ep_pattern = r"^(?!\[\+\]|\[i\]|\[!\])(?:'|\")?(/[a-zA-Z0-9_./-]+)"
            endpoint_pattern = re.compile(ep_pattern)
            for line in lines:
                clean_line = line.strip()
                # Szukaj pełnych URLi
                url_match = url_pattern.search(clean_line)
                if url_match:
                    found_urls = [url_match.group(0)]
                else:
                    found_urls = []

                # Szukaj endpointów względnych (LinkFinder często je zwraca)
                if not found_urls:
                    endpoint_match = endpoint_pattern.search(clean_line)
                    if endpoint_match:
                        # Buduj pełny URL na podstawie celu
                        base_url = "/".join(
                            target_url.split("/")[:3]
                        )  # protokół + domena
                        full_url = f"{base_url}{endpoint_match.group(1)}"
                        found_urls.append(full_url)

                for url in found_urls:
                    results.add(url.strip().strip("'\"").rstrip("/"))

        # Obsługa ParamSpider (może zwracać linie typu [Active] url)
        elif tool_name == "ParamSpider":
            for line in lines:
                match = url_pattern.search(line)
                if match:
                    results.add(match.group(0))

        # Standardowa obsługa (Katana, Hakrawler, Gauplus)
        else:
            found_urls = url_pattern.findall(process.stdout)
            for url in found_urls:
                stripped_url = url.strip().strip("'\"").rstrip("/")
                if stripped_url:
                    results.add(stripped_url)

        if process.returncode == 0:
            msg = (
                f"✅ {tool_name} zakończył dla {target_url}. "
                f"Znaleziono {len(results)} URLi."
            )
            utils.console.print(f"[bold green]{msg}[/bold green]")
        else:
            # Niektóre narzędzia zwracają non-zero jeśli nic nie znajdą lub mają warningi
            msg = (
                f"{tool_name} dla {target_url} zakończył z kodem {process.returncode}."
            )
            utils.log_and_echo(msg, "DEBUG")

    except subprocess.TimeoutExpired:
        msg = f"'{tool_name}' dla {target_url} przekroczył limit czasu."
        utils.log_and_echo(msg, "WARN")
    except Exception as e:
        msg = f"Błąd wykonania '{tool_name}' dla {target_url}: {e}"
        utils.log_and_echo(msg, "ERROR")

    return sorted(list(results))


def _categorize_urls(urls: List[str]) -> Dict[str, List[str]]:
    """
    Kategoryzuje listę URL-i na podstawie słów kluczowych i wzorców.
    """
    categorized: Dict[str, List[str]] = {
        "parameters": [],
        "js_files": [],
        "api_endpoints": [],
        "interesting_paths": [],
        "all_urls": sorted(list(set(urls))),
    }
    api_keywords = ["api", "rest", "graphql", "rpc", "json", "xml", "v1", "v2"]
    interesting_ext = [
        ".json",
        ".xml",
        ".yml",
        ".yaml",
        ".conf",
        ".config",
        ".bak",
        ".old",
        ".zip",
        ".tar.gz",
        ".sql",
        ".db",
        ".env",
    ]
    interesting_kws = [
        "swagger",
        "openapi",
        "debug",
        "test",
        "backup",
        "dump",
        "admin",
        "dashboard",
        "panel",
    ]

    for url in categorized["all_urls"]:
        url_lower = url.lower()
        if "?" in url and "=" in url:
            categorized["parameters"].append(url)
        if url_lower.endswith(".js") or ".js?" in url_lower:
            categorized["js_files"].append(url)
        if any(keyword in url_lower for keyword in api_keywords):
            categorized["api_endpoints"].append(url)
        if any(url_lower.endswith(ext) for ext in interesting_ext) or any(
            kw in url_lower for kw in interesting_kws
        ):
            categorized["interesting_paths"].append(url)

    for key in categorized:
        if key != "all_urls":
            categorized[key] = sorted(list(set(categorized[key])))

    return categorized


def start_web_crawl(
    urls: List[str],
    progress_obj: Optional[Progress] = None,
    main_task_id: Optional[TaskID] = None,
) -> Dict[str, List[str]]:
    """
    Uruchamia Fazę 4: Web Crawling, agreguje i kategoryzuje wyniki.
    """
    msg = f"Rozpoczynam Fazę 4 - Web Crawling dla {len(urls)} celów."
    utils.log_and_echo(msg, "INFO")
    all_found_urls: Set[str] = set()

    # Konfiguracja podstawowa narzędzi
    # Kolejność w config.selected_phase4_tools:
    # 0: Katana, 1: Hakrawler, 2: ParamSpider, 3: LinkFinder, 4: Gauplus
    tool_configs: List[Dict[str, Any]] = [
        {
            "name": "Katana",
            "enabled": config.selected_phase4_tools[0],
            "cmd_template": [
                "katana",
                "-silent",
                "-nc",  # No color (wg help.txt)
                "-d",
                str(config.CRAWL_DEPTH_P4),
                "-jc",  # JS crawl (wg help.txt)
                "-kf",
                "all",  # Known files (wg help.txt, warto dodać)
            ],
        },
        {
            "name": "Hakrawler",
            "enabled": config.selected_phase4_tools[1],
            "cmd_template": [
                "hakrawler",
                "-d",
                str(config.CRAWL_DEPTH_P4),
                "-insecure",
            ],
        },
        {
            "name": "ParamSpider",
            "enabled": config.selected_phase4_tools[2],
            "cmd_template": ["paramspider", "-s"],  # -s stream (wg help.txt)
        },
        {
            "name": "LinkFinder",
            "enabled": config.selected_phase4_tools[3],
            "cmd_template": ["linkfinder", "-d"],  # -d domain mode
        },
        {
            "name": "Gauplus",
            "enabled": config.selected_phase4_tools[4],
            "cmd_template": ["gauplus", "-t", "50", "-random-agent"],
        },
    ]

    # Dostosowanie do Safe Mode
    if config.SAFE_MODE:
        for cfg in tool_configs:
            if cfg["name"] == "Katana":
                # Katana w safe mode: headless, wolniej, limit rate
                if config.USE_HEADLESS_BROWSER:
                    cfg["cmd_template"].append("-headless")
                if config.AUTO_FORM_FILL:
                    cfg["cmd_template"].append(
                        "-aff"
                    )  # Automatic form fill (wg help.txt)
                cfg["cmd_template"].extend(["-rl", "10"])  # Rate limit
            if cfg["name"] == "Gauplus":
                # Zmniejszamy wątki dla Gauplus w Safe Mode
                if "-t" in cfg["cmd_template"]:
                    idx = cfg["cmd_template"].index("-t")
                    cfg["cmd_template"][idx + 1] = "5"

    # Obsługa Proxy (zgodnie z help.txt)
    if config.PROXY:
        for cfg in tool_configs:
            if cfg["name"] in ["Katana", "Hakrawler"]:
                cfg["cmd_template"].extend(["-proxy", config.PROXY])
            if cfg["name"] == "ParamSpider":
                # ParamSpider używa --proxy (zgodnie z help.txt)
                cfg["cmd_template"].extend(["--proxy", config.PROXY])

    with ThreadPoolExecutor(max_workers=config.THREADS) as executor:
        futures: List[Future] = []
        for url in urls:
            # Wyciągamy domenę dla narzędzi, które jej wymagają
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            if not domain:
                domain = url  # Fallback

            for cfg in tool_configs:
                if cfg["enabled"]:
                    cmd = list(cfg["cmd_template"])
                    current_ua = utils.user_agent_rotator.get()

                    # Specyficzne flagi wejściowe dla każdego narzędzia
                    if cfg["name"] == "Katana":
                        cmd.extend(["-H", f"User-Agent: {current_ua}"])
                        # Katana używa -u dla inputu (zgodnie z help.txt)
                        cmd.extend(["-u", url])

                    elif cfg["name"] == "Hakrawler":
                        cmd.extend(["-header", f"User-Agent: {current_ua}"])
                        # Hakrawler zazwyczaj używa -url dla inputu (nie -u)
                        cmd.extend(["-url", url])

                    elif cfg["name"] == "ParamSpider":
                        # ParamSpider wymaga domeny (-d), a nie URL
                        cmd.extend(["-d", domain])

                    elif cfg["name"] == "LinkFinder":
                        # LinkFinder używa -i dla inputu (URL lub plik)
                        cmd.extend(["-i", url])

                    elif cfg["name"] == "Gauplus":
                        # Gauplus przyjmuje domenę jako argument pozycyjny
                        cmd.append(domain)

                    futures.append(
                        executor.submit(
                            _run_and_parse_crawl_tool,
                            cfg["name"],
                            cmd,
                            url,
                            config.TOOL_TIMEOUT_SECONDS,
                        )
                    )

        for future in as_completed(futures):
            try:
                all_found_urls.update(future.result())
            except Exception as e:
                utils.log_and_echo(f"Błąd w wątku crawlera: {e}", "ERROR")
            if progress_obj and main_task_id is not None:
                progress_obj.update(main_task_id, advance=1)

    final_results = _categorize_urls(list(all_found_urls))
    count = len(final_results["all_urls"])
    msg = f"Ukończono fazę 4. Znaleziono {count} unikalnych URLi."
    utils.log_and_echo(msg, "INFO")
    return final_results


def display_phase4_tool_selection_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        title = "[bold magenta]Faza 4: Web Crawling & Discovery[/bold magenta]"
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
            "Katana (Aktywny crawler)",
            "Hakrawler (Aktywny crawler)",
            "ParamSpider (Parametry)",
            "LinkFinder (Analiza JS)",
            "Gauplus (Pasywne z archiwów)",
        ]
        for i, tool_name in enumerate(tool_names):
            # Sprawdzenie dostępności narzędzia w systemie
            # Pobieramy nazwę binarki z mapy w configu (bez opisu w nawiasie)
            base_name = tool_names[i].split(" (")[0]
            tool_exe = config.TOOL_EXECUTABLE_MAP.get(
                tool_name
            )  # Tu może być potrzebna korekta klucza
            # Fallback jeśli klucz w mapie nie pasuje idealnie do wyświetlanej nazwy
            if not tool_exe:
                # Próba dopasowania po fragmencie
                for key, val in config.TOOL_EXECUTABLE_MAP.items():
                    if base_name in key:
                        tool_exe = val
                        break

            is_missing = tool_exe and tool_exe in config.MISSING_TOOLS

            status = (
                "[bold green]✓[/bold green]"
                if config.selected_phase4_tools[i]
                else "[bold red]✗[/bold red]"
            )

            display_name = f"{status} {tool_name}"
            row_style = ""

            if is_missing:
                display_name = f"[dim]✗ {tool_name} (niedostępne)[/dim]"
                row_style = "dim"

            table.add_row(
                f"[bold cyan][{i+1}][/bold cyan]", display_name, style=row_style
            )

        table.add_section()
        table.add_row(
            "[bold cyan][\fs][/bold cyan]",
            "[bold magenta]Zmień ustawienia Fazy 4[/bold magenta]",
        )
        table.add_row("[bold cyan][\fb][/bold cyan]", "Powrót do menu głównego")
        table.add_row("[bold cyan][\fq][/bold cyan]", "Wyjdź")
        utils.console.print(Align.center(table))
        utils.console.print(
            Align.center("[bold cyan]Rekomendacja: Włącz Katana i Gauplus.[/bold cyan]")
        )
        prompt_text = Text.from_markup(
            "[bold cyan]Wybierz opcję i naciśnij Enter[/bold cyan]",
            justify="center",
        )
        choice = utils.get_single_char_input_with_prompt(prompt_text)

        if choice.isdigit() and 1 <= int(choice) <= 5:
            idx = int(choice) - 1
            # Sprawdzenie czy narzędzie jest dostępne przed włączeniem
            base_name = tool_names[idx].split(" (")[0]
            tool_exe = None
            for key, val in config.TOOL_EXECUTABLE_MAP.items():
                if base_name in key:
                    tool_exe = val
                    break

            if tool_exe and tool_exe in config.MISSING_TOOLS:
                utils.console.print(
                    Align.center("[red]To narzędzie nie jest zainstalowane.[/red]")
                )
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
                msg = "[bold yellow]Wybierz co najmniej jedno narzędzie.[/bold yellow]"
                utils.console.print(Align.center(msg))
                time.sleep(1)
        else:
            utils.console.print(
                Align.center("[bold yellow]Nieprawidłowa opcja.[/bold yellow]")
            )
        time.sleep(0.1)


def display_phase4_settings_menu(display_banner_func):
    """Wyświetla i obsługuje menu ustawień specyficznych dla Fazy 4."""
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 4[/bold cyan]"))
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        # Przygotowanie wyświetlanych wartości
        proxy_display = (
            f"[bold green]{config.PROXY} (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_PROXY and config.PROXY
            else f"[dim]{config.PROXY or 'Brak'}[/dim]"
        )
        threads_display = (
            f"[bold green]{config.THREADS} (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_THREADS
            else f"[dim]{config.THREADS}[/dim]"
        )
        timeout_display = (
            f"[bold green]{config.TOOL_TIMEOUT_SECONDS}s (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_TIMEOUT
            else f"[dim]{config.TOOL_TIMEOUT_SECONDS}s[/dim]"
        )
        depth_display = (
            f"[bold green]{config.CRAWL_DEPTH_P4} (Użytkownika)[/bold green]"
            if config.USER_CUSTOMIZED_CRAWL_DEPTH_P4
            else f"[dim]{config.CRAWL_DEPTH_P4}[/dim]"
        )
        safe_status = (
            "[bold green]✓[/bold green]"
            if config.SAFE_MODE
            else "[bold red]✗[/bold red]"
        )
        aff_status = (
            "[bold green]✓[/bold green]"
            if config.AUTO_FORM_FILL
            else "[bold red]✗[/bold red]"
        )
        headless_status = (
            "[bold green]✓[/bold green]"
            if config.USE_HEADLESS_BROWSER
            else "[bold red]✗[/bold red]"
        )

        # Dodawanie wierszy do tabeli
        table.add_row("[bold cyan][1][/bold cyan]", f"[{safe_status}] Tryb bezpieczny")
        table.add_row(
            "[bold cyan][2][/bold cyan]",
            f"Głębokość crawlera: {depth_display}",
        )
        table.add_row(
            "[bold cyan][3][/bold cyan]",
            f"[{aff_status}] Wypełnianie formularzy (Katana -aff)",
        )
        table.add_row(
            "[bold cyan][4][/bold cyan]",
            f"[{headless_status}] Przeglądarka headless (Katana -headless)",
        )
        table.add_row("[bold cyan][5][/bold cyan]", f"Proxy: {proxy_display}")
        table.add_row("[bold cyan][6][/bold cyan]", f"Liczba wątków: {threads_display}")
        table.add_row(
            "[bold cyan][7][/bold cyan]",
            f"Limit czasu narzędzia: {timeout_display}",
        )
        table.add_section()
        table.add_row("[bold cyan][\fb][/bold cyan]", "Powrót do menu Fazy 4")

        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(
            Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center")
        )

        # Obsługa wyboru użytkownika
        if choice == "1":
            config.SAFE_MODE = not config.SAFE_MODE
            utils.handle_safe_mode_tor_check()
        elif choice == "2":
            prompt_text = "[bold cyan]Podaj głębokość crawlera (np. 2)[/bold cyan]"
            new_depth = Prompt.ask(prompt_text, default=str(config.CRAWL_DEPTH_P4))
            if new_depth.isdigit():
                config.CRAWL_DEPTH_P4 = int(new_depth)
                config.USER_CUSTOMIZED_CRAWL_DEPTH_P4 = True
        elif choice == "3":
            config.AUTO_FORM_FILL = not config.AUTO_FORM_FILL
            config.USER_CUSTOMIZED_AUTO_FORM_FILL = True
        elif choice == "4":
            config.USE_HEADLESS_BROWSER = not config.USE_HEADLESS_BROWSER
            config.USER_CUSTOMIZED_USE_HEADLESS = True
        elif choice == "5":
            prompt_text = "[bold cyan]Podaj adres proxy (puste, by usunąć)[/bold cyan]"
            new_proxy = Prompt.ask(prompt_text, default=config.PROXY or "")
            config.PROXY = new_proxy if new_proxy else None
            config.USER_CUSTOMIZED_PROXY = bool(new_proxy)
        elif choice == "6":
            prompt_text = "[bold cyan]Podaj liczbę wątków[/bold cyan]"
            new_threads = Prompt.ask(prompt_text, default=str(config.THREADS))
            if new_threads.isdigit():
                config.THREADS = int(new_threads)
                config.USER_CUSTOMIZED_THREADS = True
        elif choice == "7":
            prompt_text = "[bold cyan]Podaj limit czasu (w sekundach)[/bold cyan]"
            new_timeout = Prompt.ask(
                prompt_text, default=str(config.TOOL_TIMEOUT_SECONDS)
            )
            if new_timeout.isdigit():
                config.TOOL_TIMEOUT_SECONDS = int(new_timeout)
                config.USER_CUSTOMIZED_TIMEOUT = True
        elif choice.lower() == "b":
            break
