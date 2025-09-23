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

app = typer.Typer(
    add_completion=False,
    help="ShadowMap: Zautomatyzowany zestaw narzędzi do rekonesansu.",
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
        f"W tym [bold red]{len(critical_results)}[/bold red] krytycznych."
    )
    panel = Panel(
        Text.from_markup(summary_text, justify="center"),
        border_style="cyan", title="[cyan]Podsumowanie[/cyan]",
    )
    utils.console.print(Align.center(panel))

    question = (
        f"Co skanować w {phase_name}?\n"
        f"([bold]A[/bold])ll - wszystkie {len(all_results)}\n"
        f"([bold]C[/bold])ritical - tylko {len(critical_results)}"
    )

    choice = utils.ask_user_decision(question, choices=["a", "c"], default="a")
    return all_results if choice.lower() == "a" else critical_results


def display_main_menu() -> str:
    utils.console.clear()
    display_banner()
    utils.console.print(Align.center(Panel.fit("[bold cyan]ShadowMap Main Menu[/bold cyan]")))
    utils.console.print(
        Align.center(f"\nObecny cel: [bold green]{config.ORIGINAL_TARGET}[/bold green]\n")
    )

    table = Table(show_header=False, show_edge=False, padding=(0, 2))
    table.add_row("[1]", "Faza 1: Odkrywanie Subdomen")
    table.add_row("[2]", "Faza 2: Skanowanie Portów")
    table.add_row("[3]", "Faza 3: Wyszukiwanie Katalogów")
    table.add_row("[4]", "Faza 4: Web Crawling")
    table.add_section()
    table.add_row("[\fq]", "Zapisz raport i Wyjdź")
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

    replacements = {
        "{{DOMAIN}}": config.HOSTNAME_TARGET,
        "{{OSINT_IP}}": p0_data.get("ip"), "{{OSINT_ASN_DETAILS}}": p0_data.get("asn_details"),
        "{{OSINT_CDN}}": p0_data.get("cdn_name"), "{{OSINT_REGISTRAR}}": p0_data.get("registrar"),
        "{{OSINT_CREATION_DATE}}": p0_data.get("creation_date"),
        "{{OSINT_EXPIRATION_DATE}}": p0_data.get("expiration_date"),
        "{{OSINT_NAME_SERVERS}}": "\n".join(p0_data.get("name_servers", [])),
        "{{OSINT_TECHNOLOGIES_HTML}}": tech_html,
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
    target: Optional[str] = typer.Argument(None, help="Domena lub IP."),
    target_list: Optional[Path] = typer.Option(None, "-l", help="Plik z listą celów."),
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

    scan_initiated = False
    try:
        for current_target in targets_to_scan:
            p0_data: Dict[str, Any] = {}
            p1_files: Dict[str, str] = {}
            active_urls_data: List[Dict[str, Any]] = []
            p2_results: Dict[str, Any] = {}
            p3_results: Dict[str, Any] = {}
            p3_verified_data: List[Dict[str, Any]] = []
            p4_results: Dict[str, Any] = {}

            parse_target_input(current_target)
            report_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            config.REPORT_DIR = os.path.join(
                config.OUTPUT_BASE_DIR, f"report_{config.HOSTNAME_TARGET}_{report_time}"
            )
            os.makedirs(config.REPORT_DIR, exist_ok=True)

            # Utwórz podkatalogi dla surowych wyników narzędzi
            phase_dirs = [
                "faza0_osint", "faza1_subdomain_scanning", "faza2_port_scanning",
                "faza3_dirsearch", "faza4_webcrawling"
            ]
            for phase_dir in phase_dirs:
                os.makedirs(os.path.join(config.REPORT_DIR, phase_dir), exist_ok=True)
            
            scan_initiated = True

            if config.QUIET_MODE:
                # TODO: Implement full non-interactive scan logic
                continue

            p0_data, best_target_url = phase0_osint.start_phase0_osint()
            config.ORIGINAL_TARGET = best_target_url  # Aktualizacja celu
            detect_waf_and_propose_safe_mode()

            choice = ""
            while True:
                if not choice: choice = display_main_menu()
                if choice == "1":
                    if phase1_subdomain.display_phase1_tool_selection_menu(display_banner):
                        p1_files, active_urls_data, _ = phase1_subdomain.start_phase1_scan()
                        if active_urls_data:
                            if utils.ask_user_decision("Kontynuować do Fazy 2?", ["y", "n"], "y") == "y":
                                choice = "2"
                                continue
                        else:
                            utils.console.print(Align.center("[yellow]Brak aktywnych subdomen.[/yellow]"))
                            time.sleep(2)
                    choice = ""
                elif choice == "2":
                    if not active_urls_data:
                        utils.console.print(Align.center("[bold yellow]Najpierw uruchom Fazę 1.[/bold yellow]"))
                        time.sleep(2)
                        choice = ""
                        continue
                    if phase2_port_scanning.display_phase2_tool_selection_menu(display_banner):
                        targets = [item["url"] for item in active_urls_data]
                        p2_results = phase2_port_scanning.start_port_scan(targets, None, None)
                        if p2_results.get("open_ports_by_host"):
                            if utils.ask_user_decision("Kontynuować do Fazy 3?", ["y", "n"], "y") == "y":
                                choice = "3"
                                continue
                        else:
                            utils.console.print(Align.center("[yellow]Brak otwartych portów.[/yellow]"))
                            time.sleep(2)
                    choice = ""
                elif choice == "3":
                    if phase3_dirsearch.display_phase3_tool_selection_menu(display_banner):
                        targets = [item["url"] for item in active_urls_data] or [config.ORIGINAL_TARGET]
                        num_tools = sum(config.selected_phase3_tools)
                        total_tasks = len(targets) * num_tools
                        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                                      BarColumn(), MofNCompleteColumn(), "•", TimeElapsedColumn(),
                                      console=utils.console, transient=True) as progress:
                            task = progress.add_task("[green]Faza 3[/green]", total=total_tasks or 1)
                            # ZMIANA: Przekazanie wykrytych technologii do Fazy 3
                            p3_results, p3_verified_data = phase3_dirsearch.start_dir_search(
                                targets,
                                p0_data.get("technologies", []),
                                progress,
                                task
                            )
                        if utils.ask_user_decision("Kontynuować do Fazy 4?", ["y", "n"], "y") == "y":
                            choice = "4"
                            continue
                    choice = ""
                elif choice == "4":
                    if phase4_webcrawling.display_phase4_tool_selection_menu(display_banner):
                        targets = ([item["url"] for item in p3_verified_data] or
                                   [item["url"] for item in active_urls_data] or
                                   [config.ORIGINAL_TARGET])
                        num_tools = sum(config.selected_phase4_tools)
                        total_tasks = len(targets) * num_tools
                        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                                      BarColumn(), MofNCompleteColumn(), "•", TimeElapsedColumn(),
                                      console=utils.console, transient=True) as progress:
                            task = progress.add_task("[green]Faza 4[/green]", total=total_tasks or 1)
                            p4_results = phase4_webcrawling.start_web_crawl(targets, progress, task)
                        utils.console.print(Align.center("[bold green]Faza 4 zakończona.[/bold green]"))
                        time.sleep(2)
                    choice = ""
                elif choice.lower() == "q":
                    if report_path := generate_html_report(
                        p0_data, p1_files, active_urls_data, p2_results,
                        p3_results, p3_verified_data, p4_results
                    ):
                        open_html_report(report_path)
                    break

    except KeyboardInterrupt:
        utils.console.print("\n[yellow]Przerwano. Czyszczenie...[/yellow]")
    finally:
        if scan_initiated:
            cleanup_temp_files()


if __name__ == "__main__":
    app()
