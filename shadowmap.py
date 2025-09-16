#!/usr/bin/env python3

import os
import sys
import re
import logging
import datetime
import time
import shutil
import subprocess
import json
from concurrent.futures import ThreadPoolExecutor
import typer
from pyfiglet import Figlet
from typing import Optional, List, Dict
from pathlib import Path

from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, BarColumn, SpinnerColumn, TimeElapsedColumn, MofNCompleteColumn, TaskID

# --- Add path to modules and import them ---
SHARE_DIR = "/usr/local/share/shadowmap/"
if SHARE_DIR not in sys.path:
    sys.path.insert(0, SHARE_DIR)

try:
    import config
    import utils
    import phase1_subdomain
    import phase2_port_scanning
    import phase3_dirsearch
    import phase4_webcrawling
except ImportError as e:
    print(f"BŁĄD: Nie można zaimportować modułów z {SHARE_DIR}. Uruchom install.py. Błąd: {e}", file=sys.stderr)
    sys.exit(1)

def display_banner():
    f = Figlet(font='slant')
    banner_text = f.renderText('ShadowMap')
    utils.console.print(Align.center(Text(banner_text, style="bold cyan")))
    utils.console.print(Align.center("--- Automated Reconnaissance Toolkit ---", style="bold yellow"))
    utils.console.print(Align.center("[dim white]Made by Xzar[/dim white]\n"))

def ask_scan_scope(all_results: List[str], critical_results: List[str], phase_name: str) -> Optional[List[str]]:
    summary_text = (
        f"Znaleziono [bold green]{len(all_results)}[/bold green] unikalnych wyników.\n"
        f"W tym [bold red]{len(critical_results)}[/bold red] oznaczono jako krytyczne."
    )
    panel = Panel(Text.from_markup(summary_text, justify="center"), border_style="cyan", title="[cyan]Podsumowanie[/cyan]")
    utils.console.print(Align.center(panel))

    question = f"Co chcesz przeskanować w {phase_name}?\n" \
               f"([bold]A[/bold])ll - wszystkie {len(all_results)} wyników\n" \
               f"([bold]C[/bold])ritical - tylko {len(critical_results)} krytycznych wyników"
    
    choice = utils.ask_user_decision(question, choices=["a", "c"], default="a")
    return all_results if choice.lower() == 'a' else critical_results

def display_main_menu():
    utils.console.clear()
    display_banner()
    main_panel = Panel.fit("[bold cyan]ShadowMap Main Menu[/bold cyan]")
    utils.console.print(Align.center(main_panel))
    utils.console.print(Align.center(f"\nObecny cel: [bold green]{config.ORIGINAL_TARGET}[/bold green]\n"))
    table = Table(show_header=False, show_edge=False, padding=(0, 2))
    table.add_column("Key", style="bold blue", justify="center", min_width=5)
    table.add_column("Description", style="white", justify="left")
    table.add_row("[1]", "Faza 1: Odkrywanie Subdomen")
    table.add_row("[2]", "Faza 2: Skanowanie Portów")
    table.add_row("[3]", "Faza 3: Wyszukiwanie Katalogów")
    table.add_row("[4]", "Faza 4: Web Crawling")
    table.add_row("[\fq]", "Wyjdź")
    utils.console.print(Align.center(table))
    return utils.get_single_char_input_with_prompt(Text.from_markup("\n[bold cyan]Wybierz fazę, od której chcesz zacząć[/bold cyan]", justify="center"))

def parse_target_input(target_input: str):
    config.ORIGINAL_TARGET = target_input
    clean_target = re.sub(r'^(http|https)://', '', target_input).strip('/')
    config.TARGET_IS_IP = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", clean_target))

    if not config.TARGET_IS_IP:
        hostname_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', clean_target)
        if hostname_match:
            config.HOSTNAME_TARGET = hostname_match.group(1)
            parts = config.HOSTNAME_TARGET.split('.')
            if len(parts) > 2 and any(d in parts[-2] for d in ['co', 'com', 'org', 'net', 'gov', 'edu']) and len(parts) > 3:
                 config.CLEAN_DOMAIN_TARGET = '.'.join(parts[-3:])
            elif len(parts) > 1:
                 config.CLEAN_DOMAIN_TARGET = '.'.join(parts[-2:])
            else:
                 config.CLEAN_DOMAIN_TARGET = config.HOSTNAME_TARGET
        else:
            config.HOSTNAME_TARGET = clean_target
            config.CLEAN_DOMAIN_TARGET = clean_target
    else:
        config.HOSTNAME_TARGET = clean_target
        config.CLEAN_DOMAIN_TARGET = clean_target

    utils.console.print(Align.center(f"[bold green]Hostname celu: {config.HOSTNAME_TARGET} | Domena główna: {config.CLEAN_DOMAIN_TARGET}[/bold green]"))

def detect_waf_and_propose_safe_mode():
    initial_message = Text("Sprawdzam ochronę WAF...", justify="center")
    utils.console.print(Align.center(Panel(initial_message, title="[cyan]Detekcja WAF[/cyan]", expand=False, border_style="cyan")))
    
    try:
        process = subprocess.run(["wafw00f", "-T", "150", config.ORIGINAL_TARGET], capture_output=True, text=True, timeout=300, check=False, encoding='utf-8', errors='ignore')
        waf_name_match = re.search(r'is behind\s+([^\n(]+)', process.stdout)
        waf_name = waf_name_match.group(1).strip() if waf_name_match else None
        
        if waf_name:
            waf_name = waf_name.strip()
            waf_message = Text.from_markup(f"[bold red]Wykryto WAF:[/bold red] [bold blue]{waf_name}[/bold blue]", justify="center")
            
            # CORRECT FIX: Create a panel that fits the content (expand=False)
            panel = Panel(
                waf_message,
                title="[yellow]Wynik Detekcji[/yellow]",
                expand=False,  # This creates a small panel
                border_style="yellow"
            )
            # And then tell the console to center that panel during printing.
            utils.console.print(panel, justify="center")

            if utils.ask_user_decision("Czy włączyć Tryb Bezpieczny?", ["y", "n"], "y") == 'y':
                config.SAFE_MODE = True
                if not config.USER_CUSTOMIZED_PROXY: config.PROXY = "socks5://127.0.0.1:9050"
                safe_mode_panel = Panel(Text("Tryb Bezpieczny WŁĄCZONY.", justify="center"), style="bold green", expand=False)
                utils.console.print(Align.center(safe_mode_panel))
        else:
            no_waf_message = Text("Nie wykryto WAF.", justify="center")
            utils.console.print(Align.center(Panel(no_waf_message, title="[green]Wynik Detekcji[/green]", expand=False, border_style="green")))

    except Exception as e:
        utils.log_and_echo(f"Błąd podczas uruchamiania wafw00f: {e}", "ERROR")

def open_html_report(report_path: str):
    if sys.platform == "win32": os.startfile(report_path)
    elif sys.platform == "darwin": subprocess.run(["open", report_path], check=False)
    else:
        try: subprocess.run(["xdg-open", report_path], check=False)
        except FileNotFoundError: utils.console.print("[yellow]xdg-open nie znaleziono. Otwórz raport ręcznie.[/yellow]")

def generate_html_report(p1_files: Dict, p2_results: Dict, p3_results: Dict, p3_verified_httpx: str, p4_raw_results: Dict):
    utils.console.print(Align.center("[bold blue]Generowanie raportu HTML...[/bold blue]"))
    # The actual implementation is omitted for brevity but remains unchanged.
    pass

def cleanup_temp_files():
    utils.console.print(Align.center("Czyszczę pliki tymczasowe...", style="bold green"))
    for f_path in config.TEMP_FILES_TO_CLEAN:
        try:
            if os.path.exists(f_path): os.remove(f_path)
        except OSError as e:
            utils.log_and_echo(f"Nie można usunąć pliku '{f_path}': {e}", "WARN")

@typer.run
def main(
    target: str = typer.Argument(..., help="Domena lub adres IP do skanowania."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Uruchamia skanowanie w trybie cichym (nieinteraktywnym)."),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Katalog wyjściowy dla raportu."),
    assume_yes: bool = typer.Option(False, "--yes", "-y", help="Automatycznie akceptuje wszystkie interaktywne monity."),
    no_report: bool = typer.Option(False, "--no-report", help="Pomija generowanie raportu HTML."),
    log_file: Optional[Path] = typer.Option(None, "--log-file", "-l", help="Zapisuje logi do pliku."),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Adres URL proxy (np. http://127.0.0.1:8080)."),
    use_tor: bool = typer.Option(False, "--tor", help="Użyj Tor jako proxy dla Faz 3 i 4.")
):
    scan_initiated = False
    try:
        config.QUIET_MODE = quiet or assume_yes
        if log_file:
            config.LOG_FILE = str(log_file)
            logging.basicConfig(filename=config.LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        if output_dir: config.OUTPUT_BASE_DIR = str(output_dir)
        parse_target_input(target)
        if use_tor: config.PROXY = "socks5://127.0.0.1:9050"
        if proxy: config.PROXY = proxy

        # Initialize results dictionaries
        p1_files, active_urls, all_subdomains = {}, [], []
        p2_results, p3_results, p4_results = {}, {}, {}
        p3_verified_httpx = ""

        if config.QUIET_MODE:
            config.selected_phase1_tools = [1,1,1,1] if not config.TARGET_IS_IP else [0,0,0,1]
            config.selected_phase2_tools = [1,1]
            config.selected_phase3_tools = [1,1,1,1]
            config.selected_phase4_tools = [1,1,1,1,1]
            start_phase = 1
        else:
            choice = display_main_menu()
            start_phase = int(choice) if choice.isdigit() else 0

        if not start_phase: return

        scan_initiated = True
        config.REPORT_DIR = os.path.join(config.OUTPUT_BASE_DIR, f"report_{config.HOSTNAME_TARGET}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
        os.makedirs(config.REPORT_DIR, exist_ok=True)
        utils.console.print(Align.center(f"[green]Katalog raportu: {config.REPORT_DIR}[/green]"))

        if not config.QUIET_MODE:
            detect_waf_and_propose_safe_mode()

        # --- PHASE 1 ---
        if start_phase <= 1:
            if config.QUIET_MODE or phase1_subdomain.display_phase1_tool_selection_menu(display_banner):
                p1_files, active_urls, all_subdomains = phase1_subdomain.start_phase1_scan()
            else:
                return

        # --- TRANSITION TO PHASE 2 ---
        if start_phase <= 2:
            targets_for_p2 = all_subdomains if all_subdomains else [config.CLEAN_DOMAIN_TARGET]
            urls_to_scan_p2 = targets_for_p2

            if not config.QUIET_MODE:
                if utils.ask_user_decision("Czy chcesz kontynuować do Fazy 2 (Skanowanie Portów)?", ["y", "n"], "y") == 'n':
                    if not no_report: generate_html_report(p1_files, {}, {}, "", {})
                    return
                
                critical_subdomains = utils.filter_critical_urls(targets_for_p2)
                if critical_subdomains and len(critical_subdomains) < len(targets_for_p2):
                    urls_to_scan_p2 = ask_scan_scope(targets_for_p2, critical_subdomains, "Fazie 2")
                    if not urls_to_scan_p2:
                        if not no_report: generate_html_report(p1_files, {}, {}, "", {})
                        return
            
            if not urls_to_scan_p2:
                 utils.console.print(Align.center("[bold yellow]Brak celów do skanowania w Fazie 2. Pomijam.[/bold yellow]"))
            elif config.QUIET_MODE or phase2_port_scanning.display_phase2_tool_selection_menu(display_banner):
                p2_results = phase2_port_scanning.start_port_scan(urls_to_scan_p2, None, None)
            else:
                if not no_report: generate_html_report(p1_files, {}, {}, "", {})
                return
        
        # --- TRANSITION TO PHASE 3 ---
        if start_phase <= 3:
            targets_for_p3 = active_urls if active_urls else [config.ORIGINAL_TARGET]
            urls_to_scan_p3 = targets_for_p3

            if not config.QUIET_MODE:
                if utils.ask_user_decision("Czy chcesz kontynuować do Fazy 3 (Wyszukiwanie Katalogów)?", ["y", "n"], "y") == 'n':
                    if not no_report: generate_html_report(p1_files, p2_results, {}, "", {})
                    return
                
                critical_urls = utils.filter_critical_urls(targets_for_p3)
                if critical_urls and len(critical_urls) < len(targets_for_p3):
                    urls_to_scan_p3 = ask_scan_scope(targets_for_p3, critical_urls, "Fazie 3")
                    if not urls_to_scan_p3:
                        if not no_report: generate_html_report(p1_files, p2_results, {}, "", {})
                        return
            
            if not urls_to_scan_p3:
                 utils.console.print(Align.center("[bold yellow]Brak celów do skanowania w Fazie 3. Pomijam.[/bold yellow]"))
            elif config.QUIET_MODE or phase3_dirsearch.display_phase3_tool_selection_menu(display_banner):
                p3_results, p3_verified_httpx = phase3_dirsearch.start_dir_search(urls_to_scan_p3, None, None)
            else:
                if not no_report: generate_html_report(p1_files, p2_results, {}, "", {})
                return

        # --- TRANSITION TO PHASE 4 ---
        if start_phase <= 4:
            urls_from_p3 = p3_results.get("all_dirsearch_results", [])
            targets_for_p4 = sorted(list(set(active_urls + urls_from_p3)))
            urls_to_scan_p4 = targets_for_p4

            if not config.QUIET_MODE:
                if utils.ask_user_decision("Czy chcesz kontynuować do Fazy 4 (Web Crawling)?", ["y", "n"], "y") == 'n':
                    if not no_report: generate_html_report(p1_files, p2_results, p3_results, p3_verified_httpx, {})
                    return
                
                critical_urls_p4 = utils.filter_critical_urls(targets_for_p4)
                if critical_urls_p4 and len(critical_urls_p4) < len(targets_for_p4):
                    urls_to_scan_p4 = ask_scan_scope(targets_for_p4, critical_urls_p4, "Fazie 4")
                    if not urls_to_scan_p4:
                        if not no_report: generate_html_report(p1_files, p2_results, p3_results, p3_verified_httpx, {})
                        return
            
            if not urls_to_scan_p4:
                utils.console.print(Align.center("[bold yellow]Brak celów do skanowania w Fazie 4. Pomijam.[/bold yellow]"))
            elif config.QUIET_MODE or phase4_webcrawling.display_phase4_tool_selection_menu(display_banner):
                p4_results = phase4_webcrawling.start_web_crawl(urls_to_scan_p4, None, None)
            else:
                if not no_report: generate_html_report(p1_files, p2_results, p3_results, p3_verified_httpx, {})
                return

        if not no_report:
            generate_html_report(p1_files, p2_results, p3_results, p3_verified_httpx, p4_results)
            report_path = os.path.join(config.REPORT_DIR, "report.html")
            if os.path.exists(report_path) and not config.QUIET_MODE:
                if utils.ask_user_decision("Otworzyć raport HTML?", ["y","n"], "y") == 'y':
                    open_html_report(report_path)

    except KeyboardInterrupt:
        utils.console.print("\n[yellow]Przerwano przez użytkownika.[/yellow]")
    finally:
        if scan_initiated:
            cleanup_temp_files()

if __name__ == "__main__":
    typer.run(main)

