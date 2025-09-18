#!/usr/bin/env python3

import sys
import os
import subprocess
import re
import time
from typing import List, Dict, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress, TaskID

# Importy z naszego projektu
import config
import utils

def _run_and_parse_crawl_tool(tool_name: str, command: List[str], target_url: str, timeout: int) -> List[str]:
    """
    Uruchamia narzędzie do web crawlingu, parsuje jego output w poszukiwaniu URL-i i zwraca listę.
    """
    results: Set[str] = set()
    cmd_str = ' '.join(f'"{p}"' if ' ' in p else p for p in command)
    utils.console.print(f"[bold cyan]Uruchamiam {tool_name} dla {target_url}:[/bold cyan] [dim white]{cmd_str}[/dim white]")
    
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=timeout, encoding='utf-8', errors='ignore')
        
        # Ogólne parsowanie URL-i z stdout
        url_pattern = re.compile(r'https?://[^\s"\'<>]+')
        found_urls = url_pattern.findall(process.stdout)
        
        # Specjalne parsowanie dla LinkFindera, który może zwracać ścieżki względne
        if tool_name == "LinkFinder":
            endpoint_pattern = re.compile(r"^(?!\[\+\]|\[i\]|\[!\])(?:'|\")?(/[a-zA-Z0-9_./-]+(?:\.js)?)")
            for line in process.stdout.splitlines():
                line = line.strip()
                if url_match := url_pattern.search(line):
                    found_urls.append(url_match.group(0))
                elif endpoint_match := endpoint_pattern.search(line):
                    path = endpoint_match.group(1)
                    base_url = '/'.join(target_url.split('/')[:3])
                    found_urls.append(f"{base_url}{path}")
        
        for url in found_urls:
            # Czyszczenie URL-i
            url = url.strip().strip("'\"").rstrip('/')
            if url:
                results.add(url)
        
        if process.returncode == 0:
            utils.console.print(f"[bold green]✅ {tool_name} zakończył dla {target_url}. Znaleziono {len(results)} unikalnych URLi.[/bold green]")
        else:
            utils.log_and_echo(f"Narzędzie {tool_name} dla {target_url} zakończyło z błędem (kod: {process.returncode}). STDERR: {process.stderr[:200]}", "WARN")

    except subprocess.TimeoutExpired:
        utils.log_and_echo(f"Komenda '{tool_name}' dla {target_url} przekroczyła limit czasu ({timeout}s).", "WARN")
    except Exception as e:
        utils.log_and_echo(f"Ogólny błąd wykonania '{tool_name}' dla {target_url}: {e}", "ERROR")
    
    return sorted(list(results))

def _categorize_urls(urls: List[str]) -> Dict[str, List[str]]:
    """
    Kategoryzuje listę URL-i na podstawie słów kluczowych i wzorców.
    """
    categorized = {
        "parameters": [], "js_files": [], "api_endpoints": [], "interesting_paths": [], "all_urls": sorted(list(set(urls)))
    }
    api_keywords = ['api', 'rest', 'graphql', 'rpc', 'json', 'xml']
    interesting_ext = ['.json', '.xml', '.yml', '.yaml', '.conf', '.config', '.bak', '.old', '.zip', '.tar.gz', '.sql']
    
    for url in categorized["all_urls"]:
        if '?' in url and '=' in url:
            categorized["parameters"].append(url)
        if url.endswith('.js'):
            categorized["js_files"].append(url)
        if any(keyword in url.lower() for keyword in api_keywords):
            categorized["api_endpoints"].append(url)
        if any(url.endswith(ext) for ext in interesting_ext) or any(kw in url.lower() for kw in ['swagger', 'openapi', 'debug', 'test', 'backup', 'dump', 'admin']):
            categorized["interesting_paths"].append(url)
            
    # Deduplikacja
    for key in categorized:
        if key != "all_urls":
            categorized[key] = sorted(list(set(categorized[key])))
            
    return categorized

def start_web_crawl(
    urls: List[str],
    progress_obj: Optional[Progress] = None,
    main_task_id: Optional[TaskID] = None
) -> Dict[str, List[str]]:
    """
    Uruchamia Fazę 4: Web Crawling, agreguje i kategoryzuje wyniki.
    """
    utils.log_and_echo(f"Rozpoczynam Fazę 4 - Web Crawling dla {len(urls)} celów.", "INFO")
    
    all_found_urls: Set[str] = set()
    
    tool_configs = [
        {"name": "Katana", "enabled": config.selected_phase4_tools[0], "cmd_template": ["katana", "-silent", "-d", str(config.CRAWL_DEPTH_P4), "-jc"]},
        {"name": "Hakrawler", "enabled": config.selected_phase4_tools[1], "cmd_template": ["hakrawler", "-d", str(config.CRAWL_DEPTH_P4), "-insecure"]},
        {"name": "ParamSpider", "enabled": config.selected_phase4_tools[2], "cmd_template": ["paramspider", "-s"]},
        {"name": "LinkFinder", "enabled": config.selected_phase4_tools[3], "cmd_template": ["linkfinder", "-d"]},
        {"name": "Gauplus", "enabled": config.selected_phase4_tools[4], "cmd_template": ["gauplus", "-t", "50", "-random-agent"]}
    ]

    if config.PROXY:
        for cfg in tool_configs:
            if cfg["name"] == "Katana": cfg["cmd_template"].extend(["-proxy", config.PROXY])
            if cfg["name"] == "Hakrawler": cfg["cmd_template"].extend(["-proxy", config.PROXY])
            if cfg["name"] == "ParamSpider": cfg["cmd_template"].extend(["--proxy", config.PROXY])
    
    final_user_agent = config.CUSTOM_HEADER or (utils.get_random_user_agent_header() if config.SAFE_MODE else "")
    if final_user_agent:
        for cfg in tool_configs:
            if cfg["name"] == "Katana": cfg["cmd_template"].extend(["-H", f"User-Agent: {final_user_agent}"])
            if cfg["name"] == "Hakrawler": cfg["cmd_template"].extend(["-header", f"User-Agent: {final_user_agent}"])
            
    if config.AUTO_FORM_FILL:
        for cfg in tool_configs:
            if cfg["name"] == "Katana": cfg["cmd_template"].append("-aff")

    with ThreadPoolExecutor(max_workers=config.THREADS) as executor:
        futures = []
        for url in urls:
            for cfg in tool_configs:
                if cfg["enabled"]:
                    cmd = list(cfg["cmd_template"])
                    if cfg["name"] in ["ParamSpider", "LinkFinder"]:
                        cmd.extend(["-i" if cfg["name"] == "LinkFinder" else "-d", url])
                    else: # Katana, Hakrawler, Gauplus
                        cmd.extend(["-u", url] if cfg["name"] == "Katana" else [url])

                    futures.append(executor.submit(_run_and_parse_crawl_tool, cfg["name"], cmd, url, config.TOOL_TIMEOUT_SECONDS))

        for future in as_completed(futures):
            try:
                results_from_tool = future.result()
                all_found_urls.update(results_from_tool)
            except Exception as e:
                utils.log_and_echo(f"Błąd w wątku crawlera: {e}", "ERROR")
            if progress_obj and main_task_id is not None:
                progress_obj.update(main_task_id, advance=1)

    final_results = _categorize_urls(list(all_found_urls))
    utils.log_and_echo(f"Ukończono fazę 4 - Web Crawling. Znaleziono {len(final_results['all_urls'])} unikalnych URLi.", "INFO")
    
    return final_results

def display_phase4_tool_selection_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(Align.center(Panel.fit("[bold magenta]Faza 4: Web Crawling[/bold magenta]")))
        utils.console.print(Align.center(f"Obecny cel: [bold green]{config.ORIGINAL_TARGET}[/bold green]"))
        utils.console.print(Align.center(f"Tryb bezpieczny: {'[bold green]WŁĄCZONY[/bold green]' if config.SAFE_MODE else '[bold red]WYŁĄCZONY'}"))
        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        table.add_column("Key", style="bold blue", justify="center", min_width=5)
        table.add_column("Description", style="white", justify="left")
        tool_names = ["Katana", "Hakrawler", "ParamSpider", "LinkFinder", "Gauplus"]
        for i, tool_name in enumerate(tool_names):
            status_char = "[bold green]✓[/bold green]" if config.selected_phase4_tools[i] == 1 else "[bold red]✗[/bold red]"
            table.add_row(f"[{i+1}]", f"{status_char} {tool_name}")
        table.add_section()
        table.add_row("[\fs]", "[bold magenta]Zmień ustawienia Fazy 4[/bold magenta]")
        table.add_row("[\fb]", "Powrót do menu głównego")
        table.add_row("[\fq]", "Wyjdź")
        utils.console.print(Align.center(table))
        choice = utils.get_single_char_input_with_prompt(Text.from_markup("[bold cyan]Wybierz opcję i naciśnij Enter, aby rozpocząć[/bold cyan]", justify="center"))
        
        if choice.isdigit() and 1 <= int(choice) <= 5:
            config.selected_phase4_tools[int(choice) - 1] = 1 - config.selected_phase4_tools[int(choice) - 1]
        elif choice.lower() == 's': display_phase4_settings_menu(display_banner_func)
        elif choice.lower() == 'q': sys.exit(0)
        elif choice.lower() == 'b': return False
        elif choice == '\r':
            if any(config.selected_phase4_tools): return True
            else: utils.console.print(Align.center("[bold yellow]Proszę wybrać co najmniej jedno narzędzie.[/bold yellow]"))
        else: utils.console.print(Align.center("[bold yellow]Nieprawidłowa opcja.[/bold yellow]"))
        time.sleep(0.1)

def display_phase4_settings_menu(display_banner_func):
    while True:
        utils.console.clear()
        display_banner_func()
        utils.console.print(Align.center(Panel.fit("[bold cyan]Ustawienia Fazy 4[/bold cyan]")))
        table = Table(show_header=False, show_edge=False, padding=(0, 2))
        table.add_column("Key", style="bold blue", justify="center", min_width=5)
        table.add_column("Description", style="white", justify="left")
        
        user_agent_display = f"[dim white]'{config.CUSTOM_HEADER}'[/dim white]"
        if config.USER_CUSTOMIZED_USER_AGENT and config.CUSTOM_HEADER: user_agent_display = f"[bold green]'{config.CUSTOM_HEADER}' (Użytkownika)[/bold green]"
        elif config.SAFE_MODE and not config.USER_CUSTOMIZED_USER_AGENT: user_agent_display = f"[bold yellow]Losowy (Safe Mode)[/bold yellow]"
        elif not config.CUSTOM_HEADER: user_agent_display = f"[dim white]Domyślny[/dim white]"
        
        proxy_display = "[dim]Brak[/dim]"
        if config.PROXY: proxy_display = f"[bold green]{config.PROXY}[/bold green]"

        table.add_row("[1]", f"Głębokość crawlera (Katana, Hakrawler): {config.CRAWL_DEPTH_P4}")
        table.add_row("[2]", f"[{'[bold green]✓[/bold green]' if config.AUTO_FORM_FILL else '[bold red]✗[/bold red]'}] Automatyczne wypełnianie formularzy (Katana)")
        table.add_row("[3]", f"User-Agent: {user_agent_display}")
        table.add_row("[4]", f"Proxy: {proxy_display}")
        table.add_row("[5]", f"Liczba wątków: {config.THREADS}")
        table.add_row("[6]", f"Limit czasu narzędzia: {config.TOOL_TIMEOUT_SECONDS}s")
        table.add_section()
        table.add_row("[\fb]", "Powrót do menu Fazy 4")
        table.add_row("[\fq]", "Wyjdź")
        utils.console.print(Align.center(table))
        
        choice = utils.get_single_char_input_with_prompt(Text.from_markup("[bold cyan]Wybierz opcję[/bold cyan]", justify="center"))

        if choice == '1':
            new_depth = Prompt.ask("[bold cyan]Podaj głębokość crawlera[/bold cyan]", default=str(config.CRAWL_DEPTH_P4))
            if new_depth.isdigit(): config.CRAWL_DEPTH_P4, config.USER_CUSTOMIZED_CRAWL_DEPTH_P4 = int(new_depth), True
        elif choice == '2':
            config.AUTO_FORM_FILL = not config.AUTO_FORM_FILL
            config.USER_CUSTOMIZED_AUTO_FORM_FILL = True
        elif choice == '3':
            new_ua = Prompt.ask("[bold cyan]Podaj User-Agent[/bold cyan]", default=config.CUSTOM_HEADER)
            config.CUSTOM_HEADER, config.USER_CUSTOMIZED_USER_AGENT = new_ua, bool(new_ua)
        elif choice == '4':
            new_proxy = Prompt.ask("[bold cyan]Podaj adres proxy[/bold cyan]", default=config.PROXY or "")
            config.PROXY, config.USER_CUSTOMIZED_PROXY = new_proxy, bool(new_proxy)
        elif choice == '5':
            new_threads = Prompt.ask("[bold cyan]Podaj liczbę wątków[/bold cyan]", default=str(config.THREADS))
            if new_threads.isdigit(): config.THREADS, config.USER_CUSTOMIZED_THREADS = int(new_threads), True
        elif choice == '6':
            new_timeout = Prompt.ask("[bold cyan]Podaj limit czasu (s)[/bold cyan]", default=str(config.TOOL_TIMEOUT_SECONDS))
            if new_timeout.isdigit(): config.TOOL_TIMEOUT_SECONDS, config.USER_CUSTOMIZED_TIMEOUT = int(new_timeout), True
        elif choice.lower() == 'b': break
        elif choice.lower() == 'q': sys.exit(0)

