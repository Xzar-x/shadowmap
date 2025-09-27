#!/usr/bin/env python3

import datetime
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
from pyfiglet import Figlet
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
from rich.table import Table
from rich.text import Text

# --- Dodanie ścieżki i import modułów ---
SHARE_DIR = "/usr/local/share/shadowmap/"
if SHARE_DIR not in sys.path:
    sys.path.insert(0, SHARE_DIR)

try:
    import config
    import phase0_osint
    import phase1_subdomain
    import phase2_port_scanning
    import phase3_dirsearch
    import phase4_webcrawling
    import utils
except ImportError as e:
    print(f"BŁĄD: Nie można zaimportować modułów. Uruchom install.py. Błąd: {e}")
    sys.exit(1)

# --- Definicja aplikacji Typer ---
app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
    help="""
    ShadowMap: Zautomatyzowany zestaw narzędzi do rekonesansu.

    Narzędzie przeprowadza skanowanie w wielu fazach:
    - Faza 0: OSINT (WHOIS, technologie, IP, etc.)
    - Faza 1: Odkrywanie subdomen
    - Faza 2: Skanowanie portów
    - Faza 3: Wyszukiwanie katalogów i plików
    - Faza 4: Web crawling i odkrywanie linków

    Wyniki są agregowane i prezentowane w interaktywnym raporcie HTML.
    """,
)


def display_banner():
    f = Figlet(font="slant")
    banner_text = f.renderText("ShadowMap")
    utils.console.print(Align.center(Text(banner_text, style="bold cyan")))
    utils.console.print(
        Align.center("--- Automated Reconnaissance Toolkit ---", style="bold yellow")
    )
    utils.console.print(Align.center("[dim white]Made by Xzar[/dim white]\n"))


def ask_scan_scope(
    all_results: List[str], critical_results: List[str], phase_name: str
) -> List[str]:
    summary_text = (
        f"Znaleziono [bold green]{len(all_results)}[/bold green] wyników.\n"
        f"W tym [bold red]{len(critical_results)}[/bold red] potencjalnie krytycznych."
    )
    panel = Panel(
        Text.from_markup(summary_text, justify="center"),
        border_style="cyan", title="[cyan]Podsumowanie[/cyan]",
    )
    utils.console.print(Align.center(panel))

    question = (
        f"Jaki zakres celów skanować w {phase_name}?\n"
        f"([bold]A[/bold])ll - wszystkie [bold green]{len(all_results)}[/bold green]\n"
        f"([bold]C[/bold])ritical - tylko [bold red]{len(critical_results)}[/bold red]"
    )

    choice = utils.ask_user_decision(question, choices=["a", "c"], default="c")
    return critical_results if choice.lower() == "c" else all_results


def display_main_menu() -> str:
    utils.console.clear()
    display_banner()
    utils.console.print(Align.center(Panel.fit("[bold cyan]ShadowMap Main Menu[/bold cyan]")))
    utils.console.print(
        Align.center(f"\nObecny cel: [bold green]{config.ORIGINAL_TARGET}[/bold green]\n")
    )

    table = Table(show_header=False, show_edge=False, padding=(0, 2))
    table.add_row("[bold cyan][1][/bold cyan]", "Faza 1: Odkrywanie Subdomen")
    table.add_row("[bold cyan][2][/bold cyan]", "Faza 2: Skanowanie Portów")
    table.add_row("[bold cyan][3][/bold cyan]", "Faza 3: Wyszukiwanie Katalogów")
    table.add_row("[bold cyan][4][/bold cyan]", "Faza 4: Web Crawling")
    table.add_section()
    table.add_row("[bold cyan][q][/bold cyan]", "Zapisz raport i Wyjdź")
    utils.console.print(Align.center(table))

    return utils.get_single_char_input_with_prompt(
        Text.from_markup("\n[bold cyan]Wybierz fazę[/bold cyan]", justify="center")
    )


def parse_target_input(target_input: str):
    config.ORIGINAL_TARGET = target_input
    clean_target = re.sub(r"^(https|http)://", "", target_input).strip("/")
    config.TARGET_IS_IP = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", clean_target))

    if not config.TARGET_IS_IP:
        hostname_match = re.search(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", clean_target)
        if hostname_match:
            config.HOSTNAME_TARGET = hostname_match.group(1)
            parts = config.HOSTNAME_TARGET.split(".")
            config.CLEAN_DOMAIN_TARGET = (
                ".".join(parts[-2:]) if len(parts) > 1 else config.HOSTNAME_TARGET
            )
        else:
            config.HOSTNAME_TARGET = config.CLEAN_DOMAIN_TARGET = clean_target
    else:
        config.HOSTNAME_TARGET = config.CLEAN_DOMAIN_TARGET = clean_target

    utils.console.print(
        Align.center(f"[green]Hostname: {config.HOSTNAME_TARGET} | Domena: {config.CLEAN_DOMAIN_TARGET}[/green]")
    )


def detect_waf_and_propose_safe_mode():
    utils.console.print(
        Align.center(Panel(Text("Sprawdzam ochronę WAF...", justify="center"), title="[cyan]Detekcja WAF[/cyan]"))
    )
    try:
        command = ["wafw00f", "-T", "150", "--no-colors", config.ORIGINAL_TARGET]
        process = subprocess.run(command, capture_output=True, text=True, timeout=300)

        if waf_name_match := re.search(r"is behind\s+([^\n(]+)", process.stdout):
            waf_name = waf_name_match.group(1).strip()
            panel_text = f"[red]Wykryto WAF:[/red] [blue]{waf_name}[/blue]"
            utils.console.print(Align.center(Panel(
                Text.from_markup(panel_text, justify="center"), title="[yellow]Wynik[/yellow]"
            )))
            if utils.ask_user_decision("Włączyć Tryb Bezpieczny?", ["y", "n"], "y") == "y":
                config.SAFE_MODE = True
                utils.handle_safe_mode_tor_check()
        else:
            utils.console.print(Align.center(Panel(
                Text("Nie wykryto WAF.", justify="center"), title="[green]Wynik[/green]"
            )))

    except Exception as e:
        utils.log_and_echo(f"Błąd podczas uruchamiania wafw00f: {e}", "ERROR")


def open_html_report(report_path: str):
    if not os.path.exists(report_path):
        utils.console.print(f"[yellow]Ostrzeżenie: Plik '{report_path}' nie istnieje.[/yellow]")
        return
    utils.console.print(f"[cyan]Próba otwarcia raportu: {report_path}[/cyan]")
    try:
        if sys.platform == "darwin": subprocess.run(["open", report_path], check=True)
        elif sys.platform.startswith("linux"): subprocess.run(["xdg-open", report_path], check=True)
        elif sys.platform == "win32": os.startfile(report_path)
        else: utils.console.print("[yellow]Otwórz raport ręcznie.[/yellow]")
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        utils.console.print(f"[red]Błąd otwierania raportu. Szczegóły: {e}[/dim]")


def generate_html_report(
    p0_data: Dict[str, Any], p1_files: Dict[str, str],
    active_urls_data: List[Dict[str, Any]], p2_results: Dict[str, Any],
    p3_results: Dict[str, Any], p3_verified_data: List[Dict[str, Any]],
    p4_results: Dict[str, Any]
) -> Optional[str]:
    utils.console.print(Align.center("[blue]Generowanie raportu HTML...[/blue]"))

    def read_file(path: Optional[str]) -> str:
        return open(path, "r", errors="ignore").read() if path and os.path.exists(path) else ""

    try:
        with open(config.HTML_TEMPLATE_PATH, "r", encoding="utf-8") as f:
            template = f.read()
    except FileNotFoundError:
        utils.console.print(f"[red]BŁĄD: Nie znaleziono szablonu: {config.HTML_TEMPLATE_PATH}[/red]")
        return None

    all_subdomains_content = "".join(read_file(f) for f in p1_files.values())
    all_subdomains_list = sorted({line.strip() for line in all_subdomains_content.splitlines() if line.strip()})
    p3_by_tool = p3_results.get("results_by_tool", {})
    open_ports_count = sum(len(p) for p in p2_results.get("open_ports_by_host", {}).values())

    tech_list = p0_data.get("technologies", [])
    if tech_list:
        mid = (len(tech_list) + 1) // 2
        col1 = "".join(f"<li>{t}</li>" for t in tech_list[:mid])
        col2 = "".join(f"<li>{t}</li>" for t in tech_list[mid:])
        tech_html = f'<div class="tech-columns"><ul>{col1}</ul><ul>{col2}</ul></div>'
    else:
        tech_html = "<p>Brak danych</p>"
        
    searchsploit_html = "<p>Brak danych lub nie znaleziono exploitów.</p>"
    if sploit_data := p0_data.get("searchsploit_results"):
        if "Error" not in sploit_data and any(sploit_data.values()):
            html_parts = []
            for tech, exploits in sploit_data.items():
                if exploits:
                    exploit_items = "".join(
                        f'<li><a href="https://www.exploit-db.com/exploits/{e["id"]}" target="_blank"><span class="exploit-id">EDB-ID: {e["id"]}</span>{e["title"]}</a></li>'
                        for e in exploits
                    )
                    html_parts.append(
                        f'<details><summary>{tech} ({len(exploits)})</summary><ul class="exploit-list">{exploit_items}</ul></details>'
                    )
            if html_parts:
                searchsploit_html = "".join(html_parts)

    replacements = {
        "{{DOMAIN}}": config.HOSTNAME_TARGET,
        "{{OSINT_IP}}": p0_data.get("ip"), "{{OSINT_ASN_DETAILS}}": p0_data.get("asn_details"),
        "{{OSINT_CDN}}": p0_data.get("cdn_name"), "{{OSINT_REGISTRAR}}": p0_data.get("registrar"),
        "{{OSINT_CREATION_DATE}}": p0_data.get("creation_date"),
        "{{OSINT_EXPIRATION_DATE}}": p0_data.get("expiration_date"),
        "{{OSINT_NAME_SERVERS}}": "\n".join(p0_data.get("name_servers", [])),
        "{{OSINT_TECHNOLOGIES_HTML}}": tech_html,
        "{{SEARCHSPLOIT_RESULTS_HTML}}": searchsploit_html,
        "{{COUNT_ALL_SUBDOMAINS}}": len(all_subdomains_list),
        "{{COUNT_HTTPX}}": len(active_urls_data), "{{COUNT_OPEN_PORTS}}": open_ports_count,
        "{{COUNT_DIR_SEARCH}}": len(p3_results.get("all_dirsearch_results", [])),
        "{{COUNT_ALL_URLS_P4}}": len(p4_results.get("all_urls", [])),
        "{{HTTPX_OUTPUT_JSON_P1}}": json.dumps(active_urls_data, indent=4),
        "{{HTTPX_OUTPUT_JSON_P3}}": json.dumps(p3_verified_data, indent=4),
        "{{NMAP_RESULTS_RAW_JSON}}": json.dumps({t: read_file(f) for t, f in p2_results.get("nmap_files", {}).items()}),
        "{{NAABU_RAW_OUTPUT}}": read_file(p2_results.get("naabu_file")).replace("`", "\\`"),
        "{{MASSCAN_RAW_OUTPUT}}": read_file(p2_results.get("masscan_file")).replace("`", "\\`"),
        "{{SUBFINDER_OUTPUT}}": read_file(p1_files.get("Subfinder")),
        "{{ASSETFINDER_OUTPUT}}": read_file(p1_files.get("Assetfinder")),
        "{{FINDOMAIN_OUTPUT}}": read_file(p1_files.get("Findomain")),
        "{{PUREDNS_OUTPUT}}": read_file(p1_files.get("Puredns")),
        "{{ALL_SUBDOMAINS_OUTPUT}}": "\n".join(all_subdomains_list),
        "{{DIR_SEARCH_ALL_OUTPUT}}": "\n".join(p3_results.get("all_dirsearch_results", [])),
        "{{PHASE4_ALL_URLS_OUTPUT}}": "\n".join(p4_results.get("all_urls", [])),
        "{{PARAMETERS_OUTPUT}}": "\n".join(p4_results.get("parameters", [])),
    }
    for placeholder, value in replacements.items():
        template = template.replace(placeholder, str(value or "Brak danych"))

    report_path = os.path.join(config.REPORT_DIR, "report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(template)
    utils.console.print(f"[green]✓ Raport HTML wygenerowany: {report_path}[/green]")
    return report_path


def cleanup_temp_files():
    for f_path in config.TEMP_FILES_TO_CLEAN:
        try:
            if os.path.exists(f_path): os.remove(f_path)
        except OSError: pass


@app.command()
def main(
    target: Optional[str] = typer.Argument(
        None, help="Domena lub adres IP do skanowania."
    ),
    target_list: Optional[Path] = typer.Option(
        None,
        "-l",
        "--target-list",
        help="Plik zawierający listę celów do skanowania (jeden na linię).",
        rich_help_panel="Input",
    ),
    output_dir: Path = typer.Option(
        ".",
        "-o",
        "--output-dir",
        help="Katalog, w którym zostaną zapisane raporty.",
        rich_help_panel="Output",
    ),
    exclude: Optional[List[str]] = typer.Option(
        None,
        "-e",
        "--exclude",
        help="Wyklucz subdomeny ze skanowania (np. '-e test.example.com -e *.dev.example.com').",
        rich_help_panel="Tuning",
    ),
    safe_mode: bool = typer.Option(
        False,
        "--safe-mode",
        help="Włącz tryb bezpieczny (wolniejsze, mniej agresywne skanowanie, rotacja User-Agentów).",
        rich_help_panel="Tuning",
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        help="Użyj proxy dla wspieranych narzędzi (np. 'socks5://127.0.0.1:9050').",
        rich_help_panel="Tuning",
    ),
    quiet_mode: bool = typer.Option(
        False,
        "-q",
        "--quiet",
        help="Tryb cichy, minimalizuje output (przydatne przy wielu celach).",
        rich_help_panel="Output",
    ),
):
    targets_to_scan = []
    if target_list and target_list.is_file():
        with open(target_list) as f:
            targets_to_scan.extend(line.strip() for line in f if line.strip())
        config.QUIET_MODE = True
    elif target:
        targets_to_scan.append(target)

    if not targets_to_scan:
        utils.console.print("[red]Błąd: Podaj cel lub listę celów.[/red]")
        raise typer.Exit()

    config.QUIET_MODE = quiet_mode
    config.SAFE_MODE = safe_mode
    config.PROXY = proxy
    config.EXCLUSION_PATTERNS = exclude or []
    config.OUTPUT_BASE_DIR = str(output_dir)

    scan_initiated = False
    try:
        for current_target in targets_to_scan:
            p0_data, p1_files, active_urls_data, p2_results, p3_results, p3_verified_data, p4_results = {}, {}, [], {}, {}, [], {}
            targets_for_phase2_3, targets_for_phase4 = [], []

            parse_target_input(current_target)
            report_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            config.REPORT_DIR = os.path.join(
                config.OUTPUT_BASE_DIR, f"report_{config.HOSTNAME_TARGET}_{report_time}"
            )
            os.makedirs(config.REPORT_DIR, exist_ok=True)
            for phase_dir in ["faza0_osint", "faza1_subdomain_scanning", "faza2_port_scanning", "faza3_dirsearch", "faza4_webcrawling"]:
                os.makedirs(os.path.join(config.REPORT_DIR, phase_dir), exist_ok=True)
            
            scan_initiated = True

            if config.QUIET_MODE:
                continue

            p0_data, best_target_url = phase0_osint.start_phase0_osint()
            config.ORIGINAL_TARGET = best_target_url
            if not config.SAFE_MODE:
                detect_waf_and_propose_safe_mode()

            choice = ""
            while True:
                if not choice: choice = display_main_menu()
                
                if choice == "1":
                    if phase1_subdomain.display_phase1_tool_selection_menu(display_banner):
                        p1_files, active_urls_data, _ = phase1_subdomain.start_phase1_scan()
                        if active_urls_data:
                            all_p1_urls = [item["url"] for item in active_urls_data]
                            critical_p1_urls = utils.filter_critical_urls(all_p1_urls)
                            targets_for_phase2_3 = ask_scan_scope(all_p1_urls, critical_p1_urls, "Fazy 2 i 3")
                            if utils.ask_user_decision("Znaleziono aktywne subdomeny. Kontynuować do Fazy 2?", ["y", "n"], "y") == "y":
                                choice = "2"
                                continue
                        else:
                            utils.console.print(Align.center("[yellow]Brak aktywnych subdomen do dalszego skanowania.[/yellow]"))
                            time.sleep(2)
                    choice = ""

                elif choice == "2":
                    if not targets_for_phase2_3:
                        utils.console.print(Align.center("[yellow]Brak celów z Fazy 1. Używam głównego celu do skanowania portów.[/yellow]"))
                        targets_for_phase2_3 = [best_target_url]
                    
                    if phase2_port_scanning.display_phase2_tool_selection_menu(display_banner):
                        p2_results = phase2_port_scanning.start_port_scan(targets_for_phase2_3, None, None)
                        if p2_results.get("open_ports_by_host"):
                            if utils.ask_user_decision("Znaleziono otwarte porty. Kontynuować do Fazy 3?", ["y", "n"], "y") == "y":
                                choice = "3"
                                continue
                        else:
                            utils.console.print(Align.center("[yellow]Nie znaleziono otwartych portów.[/yellow]"))
                            time.sleep(2)
                    choice = ""

                elif choice == "3":
                    if not targets_for_phase2_3:
                        utils.console.print(Align.center("[yellow]Brak celów z Fazy 1. Używam głównego celu do wyszukiwania katalogów.[/yellow]"))
                        targets_for_phase2_3 = [best_target_url]

                    if phase3_dirsearch.display_phase3_tool_selection_menu(display_banner):
                        num_tools = sum(1 for x in config.selected_phase3_tools if x)
                        total_tasks = len(targets_for_phase2_3) * num_tools
                        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                                      BarColumn(), MofNCompleteColumn(), "•", TimeElapsedColumn(),
                                      console=utils.console, transient=True) as progress:
                            task = progress.add_task("[green]Faza 3[/green]", total=total_tasks or 1)
                            p3_results, p3_verified_data = phase3_dirsearch.start_dir_search(
                                targets_for_phase2_3, p0_data.get("technologies", []), progress, task
                            )

                        if p3_verified_data:
                            all_p3_urls = [item["url"] for item in p3_verified_data]
                            critical_p3_urls = utils.filter_critical_urls(all_p3_urls)
                            targets_for_phase4 = ask_scan_scope(all_p3_urls, critical_p3_urls, "Fazy 4")
                        else:
                            utils.console.print(Align.center("[yellow]Brak zweryfikowanych wyników z Fazy 3. Używam celów z Fazy 1/głównego celu.[/yellow]"))
                            targets_for_phase4 = targets_for_phase2_3

                        if utils.ask_user_decision("Zakończono Fazę 3. Kontynuować do Fazy 4?", ["y", "n"], "y") == "y":
                            choice = "4"
                            continue
                    choice = ""

                elif choice == "4":
                    if not targets_for_phase4:
                        base_targets = p3_verified_data or active_urls_data
                        if not base_targets:
                            utils.console.print(Align.center("[yellow]Brak celów z poprzednich faz. Używam głównego celu do web crawlingu.[/yellow]"))
                            targets_for_phase4 = [best_target_url]
                        else:
                            targets_for_phase4 = [item["url"] for item in base_targets] if isinstance(base_targets[0], dict) else base_targets

                    if phase4_webcrawling.display_phase4_tool_selection_menu(display_banner):
                        num_tools = sum(1 for x in config.selected_phase4_tools if x)
                        total_tasks = len(targets_for_phase4) * num_tools
                        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                                      BarColumn(), MofNCompleteColumn(), "•", TimeElapsedColumn(),
                                      console=utils.console, transient=True) as progress:
                            task = progress.add_task("[green]Faza 4[/green]", total=total_tasks or 1)
                            p4_results = phase4_webcrawling.start_web_crawl(targets_for_phase4, progress, task)
                        utils.console.print(Align.center("[bold green]Faza 4 zakończona.[/bold green]"))
                        time.sleep(2)
                    choice = ""
                
                elif choice.lower() == "q":
                    if report_path := generate_html_report(p0_data, p1_files, active_urls_data, p2_results, p3_results, p3_verified_data, p4_results):
                        open_html_report(report_path)
                    break

    except KeyboardInterrupt:
        utils.console.print("\n[yellow]Przerwano. Czyszczenie...[/yellow]")
    finally:
        if scan_initiated:
            cleanup_temp_files()


if __name__ == "__main__":
    app()
