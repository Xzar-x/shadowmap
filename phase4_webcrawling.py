#!/usr/bin/env python3

import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set

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
    Uruchamia narzędzie do web crawlingu i parsuje jego output w poszukiwaniu URL-i.
    """
    results: Set[str] = set()
    cmd_str = " ".join(f'"{p}"' if " " in p else p for p in command)
    utils.console.print(
        f"[bold cyan]Uruchamiam {tool_name}:[/bold cyan] [dim white]{cmd_str}[/dim white]"
    )

    try:
        process = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="ignore",
        )

        url_pattern = re.compile(r'https?://[^\s"\'<>]+')
        found_urls = url_pattern.findall(process.stdout)

        if tool_name == "LinkFinder":
            endpoint_pattern = re.compile(r"^(?!\[\+\]|\[i\]|\[!\])(?:'|\")?(/[a-zA-Z0-9_./-]+)")
            for line in process.stdout.splitlines():
                if url_match := url_pattern.search(line.strip()):
                    found_urls.append(url_match.group(0))
                elif endpoint_match := endpoint_pattern.search(line.strip()):
                    base_url = "/".join(target_url.split("/")[:3])
                    found_urls.append(f"{base_url}{endpoint_match.group(1)}")

        for url in found_urls:
            if stripped_url := url.strip().strip("'\"").rstrip("/"):
                results.add(stripped_url)

        if process.returncode == 0:
            msg = f"✅ {tool_name} zakończył dla {target_url}. Znaleziono {len(results)} URLi."
            utils.console.print(f"[bold green]{msg}[/bold green]")
        else:
            msg = f"{tool_name} dla {target_url} zakończył z błędem."
            utils.log_and_echo(msg, "WARN")

    except subprocess.TimeoutExpired:
        msg = f"Komenda '{tool_name}' dla {target_url} przekroczyła limit czasu."
        utils.log_and_echo(msg, "WARN")
    except Exception as e:
        msg = f"Ogólny błąd wykonania '{tool_name}' dla {target_url}: {e}"
        utils.log_and_echo(msg, "ERROR")

    return sorted(list(results))


def _categorize_urls(urls: List[str]) -> Dict[str, List[str]]:
    """
    Kategoryzuje listę URL-i na podstawie słów kluczowych i wzorców.
    """
    categorized: Dict[str, List[str]] = {
        "parameters": [], "js_files": [], "api_endpoints": [],
        "interesting_paths": [], "all_urls": sorted(list(set(urls))),
    }
    api_keywords = ["api", "rest", "graphql", "rpc", "json", "xml"]
    interesting_ext = [
        ".json", ".xml", ".yml", ".yaml", ".conf", ".config",
        ".bak", ".old", ".zip", ".tar.gz", ".sql",
    ]
    interesting_kws = ["swagger", "openapi", "debug", "test", "backup", "dump", "admin"]

    for url in categorized["all_urls"]:
        if "?" in url and "=" in url:
            categorized["parameters"].append(url)
        if url.endswith(".js"):
            categorized["js_files"].append(url)
        if any(keyword in url.lower() for keyword in api_keywords):
            categorized["api_endpoints"].append(url)
        if any(url.endswith(ext) for ext in interesting_ext) or \
           any(kw in url.lower() for kw in interesting_kws):
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
    utils.log_and_echo(f"Rozpoczynam Fazę 4 - Web Crawling dla {len(urls)} celów.", "INFO")
    all_found_urls: Set[str] = set()

    tool_configs = [
        {"name": "Katana", "enabled": config.selected_phase4_tools[0], "cmd_template": [
            "katana", "-silent", "-d", str(config.CRAWL_DEPTH_P4), "-jc"]},
        {"name": "Hakrawler", "enabled": config.selected_phase4_tools[1], "cmd_template": [
            "hakrawler", "-d", str(config.CRAWL_DEPTH_P4), "-insecure"]},
        {"name": "ParamSpider", "enabled": config.selected_phase4_tools[2],
            "cmd_template": ["paramspider", "-s"]},
        {"name": "LinkFinder", "enabled": config.selected_phase4_tools[3],
            "cmd_template": ["linkfinder", "-d"]},
        {"name": "Gauplus", "enabled": config.selected_phase4_tools[4],
            "cmd_template": ["gauplus", "-t", "50", "-random-agent"]},
    ]

    if config.SAFE_MODE:
        for cfg in tool_configs:
            if cfg["name"] == "Katana" and config.USE_HEADLESS_BROWSER:
                cfg["cmd_template"].append("-headless")
                if config.AUTO_FORM_FILL:
                    cfg["cmd_template"].append("-aff")

    if config.PROXY:
        for cfg in tool_configs:
            if cfg["name"] in ["Katana", "Hakrawler"]:
                cfg["cmd_template"].extend(["-proxy", config.PROXY])
            if cfg["name"] == "ParamSpider":
                cfg["cmd_template"].extend(["--proxy", config.PROXY])

    with ThreadPoolExecutor(max_workers=config.THREADS) as executor:
        futures = []
        for url in urls:
            for cfg in tool_configs:
                if cfg["enabled"]:
                    cmd = list(cfg["cmd_template"])
                    current_ua = utils.user_agent_rotator.get()
                    if cfg["name"] == "Katana":
                        cmd.extend(["-H", f"User-Agent: {current_ua}"])
                    elif cfg["name"] == "Hakrawler":
                        cmd.extend(["-header", f"User-Agent: {current_ua}"])

                    if cfg["name"] in ["ParamSpider", "LinkFinder"]:
                        key = "-i" if cfg["name"] == "LinkFinder" else "-d"
                        cmd.extend([key, url])
                    elif cfg["name"] == "Gauplus":
                        if domain_match := re.search(r"https?://([^/]+)", url):
                            cmd.append(domain_match.group(1))
                        else:
                            continue
                    else:  # Katana, Hakrawler
                        cmd.extend(["-u", url])

                    futures.append(executor.submit(
                        _run_and_parse_crawl_tool, cfg["name"], cmd, url,
                        config.TOOL_TIMEOUT_SECONDS
                    ))

        for future in as_completed(futures):
            try:
                all_found_urls.update(future.result())
            except Exception as e:
                utils.log_and_echo(f"Błąd w wątku crawlera: {e}", "ERROR")
            if progress_obj and main_task_id is not None:
                progress_obj.update(main_task_id, advance=1)

    final_results = _categorize_urls(list(all_found_urls))
    msg = f"Ukończono fazę 4. Znaleziono {len(final_results['all_urls'])} unikalnych URLi."
    utils.log_and_echo(msg, "INFO")
    return final_results


def display_phase4_tool_selection_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(
            Align.center(Panel.fit("[bold magenta]Faza 4: Web Crawling & Discovery[/bold magenta]"))
        )
        safe_mode_status = ("[bold green]WŁĄCZONY[/bold green]" if config.SAFE_MODE
                            else "[bold red]WYŁĄCZONY[/bold red]")
        utils.console.print(
            Align.center(f"Cel: [bold green]{config.ORIGINAL_TARGET}[/bold green] | "
                         f"Tryb bezpieczny: {safe_mode_status}")
        )
        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        tool_names = [
            "Katana (Aktywny crawler)", "Hakrawler (Aktywny crawler)",
            "ParamSpider (Parametry)", "LinkFinder (Analiza JS)",
            "Gauplus (Pasywne z archiwów)",
        ]
        for i, tool_name in enumerate(tool_names):
            status = ("[bold green]✓[/bold green]" if config.selected_phase4_tools[i]
                      else "[bold red]✗[/bold red]")
            table.add_row(f"[{i+1}]", f"{status} {tool_name}")
        table.add_section()
        table.add_row("[\fs]", "[bold magenta]Zmień ustawienia Fazy 4[/bold magenta]")
        table.add_row("[\fb]", "Powrót do menu głównego")
        table.add_row("[\fq]", "Wyjdź")
        utils.console.print(Align.center(table))
        utils.console.print(
            Align.center("[bold cyan]Rekomendacja: Włącz Katana i Gauplus.[/bold cyan]")
        )
        choice = utils.get_single_char_input_with_prompt(
            Text.from_markup("[bold cyan]Wybierz opcję i naciśnij Enter[/bold cyan]", justify="center")
        )

        if choice.isdigit() and 1 <= int(choice) <= 5:
            config.selected_phase4_tools[int(choice) - 1] ^= 1
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
                utils.console.print(Align.center("[bold yellow]Wybierz co najmniej jedno narzędzie.[/bold yellow]"))
        else:
            utils.console.print(Align.center("[bold yellow]Nieprawidłowa opcja.[/bold yellow]"))
        time.sleep(0.1)


def display_phase4_settings_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 4[/bold cyan]")))
        table = Table(show_header=False, show_edge=False, padding=(0, 2))

        proxy_display = f"[bold green]{config.PROXY}[/bold green]" if config.PROXY else "[dim]Brak[/dim]"
        safe_status = ("[bold green]✓[/bold green]" if config.SAFE_MODE else "[bold red]✗[/bold red]")
        aff_status = ("[bold green]✓[/bold green]" if config.AUTO_FORM_FILL else "[bold red]✗[/bold red]")
        headless_status = ("[bold green]✓[/bold green]" if config.USE_HEADLESS_BROWSER else "[bold red]✗[/bold red]")

        table.add_row("[1]", f"[{safe_status}] Tryb bezpieczny")
        table.add_row("[2]", f"Głębokość crawlera (Katana, Hakrawler): {config.CRAWL_DEPTH_P4}")
        table.add_row("[3]", f"[{aff_status}] Automatyczne wypełnianie formularzy (Katana)")
        table.add_row("[4]", f"[{headless_status}] Użyj przeglądarki Headless (Katana, Safe Mode)")
        table.add_row("[5]", f"Proxy: {proxy_display}")
        table.add_row("[6]", f"Liczba wątków: {config.THREADS}")
        table.add_row("[7]", f"Limit czasu narzędzia: {config.TOOL_TIMEOUT_SECONDS}s")
        table.add_section()
        table.add_row("[\fb]", "Powrót do menu Fazy 4")
        table.add_row("[\fq]", "Wyjdź")
        utils.console.print(Align.center(table))

        choice = utils.get_single_char_input_with_prompt(
            Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center")
        )

        if choice == "1":
            config.SAFE_MODE = not config.SAFE_MODE
            utils.handle_safe_mode_tor_check()
        elif choice == "2":
            new_depth = Prompt.ask("[bold cyan]Podaj głębokość crawlera[/bold cyan]", default=str(config.CRAWL_DEPTH_P4))
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
            new_proxy = Prompt.ask("[bold cyan]Podaj adres proxy[/bold cyan]", default=config.PROXY or "")
            config.PROXY = new_proxy
            config.USER_CUSTOMIZED_PROXY = bool(new_proxy)
        elif choice == "6":
            new_threads = Prompt.ask("[bold cyan]Podaj liczbę wątków[/bold cyan]", default=str(config.THREADS))
            if new_threads.isdigit():
                config.THREADS = int(new_threads)
                config.USER_CUSTOMIZED_THREADS = True
        elif choice == "7":
            new_timeout = Prompt.ask("[bold cyan]Podaj limit czasu (s)[/bold cyan]", default=str(config.TOOL_TIMEOUT_SECONDS))
            if new_timeout.isdigit():
                config.TOOL_TIMEOUT_SECONDS = int(new_timeout)
                config.USER_CUSTOMIZED_TIMEOUT = True
        elif choice.lower() == "b": break
        elif choice.lower() == "q": sys.exit(0)
