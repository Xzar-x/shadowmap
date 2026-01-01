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
    - Faza 0: OSINT (pasywny)
    - Faza 1: Subdomeny (aktywny/pasywny)
    - Faza 2: Skanowanie portów
    - Faza 3: Fuzzing katalogów (Dirsearch)
    - Faza 4: Web Crawling
    """
)


def display_banner():
    """Wyświetla banner startowy."""
    f = Figlet(font="slant")
    banner_text = f.renderText("ShadowMap")
    utils.console.print(Align.center(Text(banner_text, style="bold cyan")))
    utils.console.print(
        Align.center("[bold white]Advanced Reconnaissance Tool[/bold white]")
    )
    utils.console.print(Align.center("[dim]v1.0.2[/dim]\n"))


def cleanup_temp_files():
    """Usuwa pliki tymczasowe zdefiniowane w config."""
    if config.TEMP_FILES_TO_CLEAN:
        utils.console.print("[dim]Czyszczenie plików tymczasowych...[/dim]")
        for fpath in config.TEMP_FILES_TO_CLEAN:
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except OSError:
                    pass
        config.TEMP_FILES_TO_CLEAN = []


def load_previous_session(report_dir: str) -> Dict[str, Any]:
    """Wczytuje stan sesji z pliku report.json w podanym katalogu."""
    json_path = os.path.join(report_dir, "report.json")
    if not os.path.exists(json_path):
        utils.console.print(f"[bold red]Błąd: Nie znaleziono pliku report.json w {report_dir}[/bold red]")
        return {}
    
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        utils.console.print(f"[bold green]✓ Pomyślnie wczytano poprzednią sesję z {report_dir}[/bold green]")
        
        # Logika odtwarzania specyficznych typów danych, jeśli to konieczne
        # JSON nie przechowuje setów, więc jeśli gdzieś używamy setów, trzeba pamiętać, że tu wrócą jako listy.
        return data
    except Exception as e:
        utils.console.print(f"[bold red]Błąd podczas wczytywania sesji: {e}[/bold red]")
        return {}


def generate_json_report(scan_results: Dict[str, Any]):
    """Zapisuje surowe wyniki do pliku JSON."""
    json_path = os.path.join(config.REPORT_DIR, "report.json")
    try:
        # Konwersja setów na listy dla JSON
        def set_default(obj):
            if isinstance(obj, set):
                return list(obj)
            return str(obj)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(scan_results, f, indent=4, default=set_default)
        utils.log_and_echo(f"Raport JSON zaktualizowany: {json_path}", "INFO")
    except Exception as e:
        utils.log_and_echo(f"Błąd zapisu raportu JSON: {e}", "ERROR")


def generate_html_report(scan_results: Dict[str, Any]) -> str:
    """Generuje raport HTML na podstawie szablonu."""
    if not os.path.exists(config.HTML_TEMPLATE_PATH):
        utils.log_and_echo("Nie znaleziono szablonu HTML!", "ERROR")
        return ""

    try:
        with open(config.HTML_TEMPLATE_PATH, "r", encoding="utf-8") as f:
            template = f.read()

        # --- Przygotowanie danych do wstrzyknięcia ---
        # 1. OSINT
        p0 = scan_results.get("phase0_osint", {})
        osint_json = json.dumps(p0, default=str)

        # 2. Subdomeny (Faza 1)
        p1 = scan_results.get("phase1_subdomain", {})
        subdomains_list = sorted(list(p1.get("verified_subdomains", [])))
        
        # Przygotowanie danych HTTPX dla fazy 1
        httpx_p1_raw = []
        httpx_p1_file = os.path.join(config.REPORT_DIR, "httpx_results.json")
        if os.path.exists(httpx_p1_file):
            try:
                with open(httpx_p1_file, "r") as f:
                    for line in f:
                        httpx_p1_raw.append(json.loads(line))
            except Exception:
                pass
        
        httpx_p1_json = json.dumps(httpx_p1_raw, default=str)

        # 3. Porty (Faza 2)
        p2 = scan_results.get("phase2_port_scanning", {})
        naabu_raw = json.dumps(p2.get("naabu_raw", ""))
        masscan_raw = json.dumps(p2.get("masscan_raw", ""))
        nmap_raw = json.dumps(p2.get("nmap_raw", ""))

        # 4. Dirsearch (Faza 3)
        p3_tuple = scan_results.get("phase3_dirsearch", ({}, []))
        # Obsługa przypadku, gdy wczytujemy z JSON (wtedy to lista, nie krotka)
        if isinstance(p3_tuple, list):
            p3_verified = p3_tuple[1] if len(p3_tuple) > 1 else []
        elif isinstance(p3_tuple, tuple):
            p3_verified = p3_tuple[1] if len(p3_tuple) > 1 else []
        else:
            p3_verified = []
            
        httpx_p3_json = json.dumps(p3_verified, default=str)

        # 5. Web Crawling (Faza 4)
        p4 = scan_results.get("phase4_results", {})
        p4_all = json.dumps(p4.get("all_urls", []), default=str)
        p4_params = json.dumps(p4.get("parameters", []), default=str)
        p4_js = json.dumps(p4.get("js_files", []), default=str)
        p4_api = json.dumps(p4.get("api_endpoints", []), default=str)
        p4_interesting = json.dumps(p4.get("interesting_paths", []), default=str)

        gen_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # --- Podmiana w szablonie ---
        html_content = template.replace("{{DOMAIN}}", config.ORIGINAL_TARGET)
        html_content = html_content.replace("{{GENERATION_DATE}}", gen_date)
        html_content = html_content.replace("{{OSINT_DATA}}", osint_json)
        html_content = html_content.replace("{{HTTPX_DATA_P1}}", httpx_p1_json)
        html_content = html_content.replace("{{NAABU_RAW}}", naabu_raw)
        html_content = html_content.replace("{{MASSCAN_RAW}}", masscan_raw)
        html_content = html_content.replace("{{NMAP_RAW}}", nmap_raw)
        html_content = html_content.replace("{{HTTPX_DATA_P3}}", httpx_p3_json)
        html_content = html_content.replace("{{P4_ALL_URLS}}", p4_all)
        html_content = html_content.replace("{{P4_PARAMS}}", p4_params)
        html_content = html_content.replace("{{P4_JS}}", p4_js)
        html_content = html_content.replace("{{P4_API}}", p4_api)
        html_content = html_content.replace("{{P4_INTERESTING}}", p4_interesting)

        report_file = os.path.join(config.REPORT_DIR, "report.html")
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        utils.console.print(
            Align.center(
                f"\n[bold green]Raport HTML wygenerowany:[/bold green] {report_file}"
            )
        )
        return report_file

    except Exception as e:
        utils.log_and_echo(f"Błąd generowania raportu HTML: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        return ""


def open_html_report(report_path: str):
    """Otwiera raport w domyślnej przeglądarce (jeśli nie root/headless)."""
    if config.USE_HEADLESS_BROWSER or os.geteuid() == 0:
        return

    try:
        if sys.platform == 'darwin':
            subprocess.Popen(['open', report_path])
        elif sys.platform == 'linux':
            subprocess.Popen(['xdg-open', report_path], stderr=subprocess.DEVNULL)
        elif sys.platform == 'win32':
            os.startfile(report_path)
    except Exception:
        pass


@app.command()
def main(
    target: str = typer.Argument(..., help="Cel ataku (domena lub IP)"),
    quiet: bool = typer.Option(
        False, "-y", "--yes", "--quiet", help="Tryb cichy (automatyczna akceptacja)"
    ),
    safe: bool = typer.Option(
        False, "-s", "--safe", help="Tryb bezpieczny (wolniejszy, mniej wykrywalny)"
    ),
    threads: Optional[int] = typer.Option(
        None, "-t", "--threads", help="Globalna liczba wątków dla wszystkich narzędzi"
    ),
    rate_limit: Optional[int] = typer.Option(
        None, "-rl", "--rate-limit", help="Globalny limit zapytań/s"
    ),
    user_agent: Optional[str] = typer.Option(
        None, "-ua", "--user-agent", help="Niestandardowy User-Agent"
    ),
    scope_list: Optional[str] = typer.Option(
        None, "-l", "--list", help="Plik z listą celów [Funkcja eksperymentalna]"
    ),
    resume: Optional[str] = typer.Option(
        None, "-r", "--resume", help="Ścieżka do katalogu raportu, aby wznowić sesję"
    )
):
    """
    Główna funkcja orkiestrująca działanie ShadowMap.
    """
    display_banner()

    # --- Weryfikacja narzędzi ---
    missing = utils.check_required_tools()
    if missing:
        utils.console.print(
            Align.center(
                Panel(
                    f"[bold red]Brakujące narzędzia:[/bold red] {', '.join(missing)}\n"
                    "Niektóre funkcje mogą nie działać poprawnie.\n"
                    "Uruchom [bold]install.py[/bold] aby naprawić.",
                    title="Ostrzeżenie",
                    border_style="red",
                )
            )
        )
        config.MISSING_TOOLS = missing
        time.sleep(2)
    else:
        utils.console.print(
            Align.center("[bold green]Wszystkie narzędzia dostępne.[/bold green]\n")
        )

    # --- Konfiguracja na podstawie flag ---
    config.QUIET_MODE = quiet
    config.AUTO_MODE = quiet  # W trybie cichym zakładamy auto
    config.SAFE_MODE = safe

    # Obsługa flag globalnych
    if threads is not None:
        config.THREADS = threads
        config.USER_CUSTOMIZED_THREADS = True
        utils.console.print(f"[bold blue]ℹ Ustawiono globalną liczbę wątków na: {threads}[/bold blue]")

    if rate_limit is not None:
        config.NAABU_RATE = rate_limit
        config.MASSCAN_RATE = rate_limit
        config.PUREDNS_RATE_LIMIT = rate_limit
        config.HTTPX_P1_RATE_LIMIT = rate_limit
        
        config.USER_CUSTOMIZED_NAABU_RATE = True
        config.USER_CUSTOMIZED_MASSCAN_RATE = True
        config.USER_CUSTOMIZED_PUREDNS_RATE_LIMIT = True
        config.USER_CUSTOMIZED_HTTPX_P1_RATE_LIMIT = True
        
        utils.console.print(f"[bold blue]ℹ Ustawiono globalny limit zapytań (rate-limit) na: {rate_limit}[/bold blue]")

    if user_agent is not None:
        config.CUSTOM_HEADER = user_agent
        config.USER_CUSTOMIZED_USER_AGENT = True
        utils.console.print(f"[bold blue]ℹ Ustawiono niestandardowy User-Agent: {user_agent}[/bold blue]")

    if scope_list is not None:
        utils.console.print(f"[bold yellow]⚠ Opcja -l (Scope List) jest załadowana, ale pełna obsługa wielu celów jest w budowie.[/bold yellow]")

    # --- Inicjalizacja Celu ---
    config.ORIGINAL_TARGET = target
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
    config.CLEAN_DOMAIN_TARGET = clean_target
    config.HOSTNAME_TARGET = clean_target

    # Sprawdź czy cel to IP
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", clean_target):
        config.TARGET_IS_IP = True
        utils.console.print(f"[yellow]Cel zidentyfikowany jako adres IP: {clean_target}[/yellow]")
    
    # --- Katalog Raportu i Wznawianie Sesji ---
    scan_results = {}
    
    if resume:
        # Tryb wznawiania
        if os.path.exists(resume) and os.path.isdir(resume):
            config.REPORT_DIR = resume
            utils.console.print(f"[bold blue]ℹ Wznawiam sesję w katalogu: {resume}[/bold blue]")
            scan_results = load_previous_session(resume)
            # Ustawienie logowania do istniejącego pliku
            config.LOG_FILE = os.path.join(config.REPORT_DIR, "shadowmap.log")
            # Spróbujmy wczytać OSINT jeśli jest, żeby nie robić od nowa
            if "phase0_osint" not in scan_results:
                 pass # nic nie robimy, user może uruchomić ponownie
        else:
            utils.console.print(f"[bold red]Katalog do wznowienia nie istnieje: {resume}. Tworzę nowy.[/bold red]")
            resume = None # fallback to new creation

    if not resume:
        # Tworzenie nowego katalogu
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir_name = f"report_{clean_target}_{timestamp}"
        config.REPORT_DIR = os.path.join(config.OUTPUT_BASE_DIR, report_dir_name)
        os.makedirs(config.REPORT_DIR, exist_ok=True)
        config.LOG_FILE = os.path.join(config.REPORT_DIR, "shadowmap.log")
        utils.log_and_echo(f"Rozpoczęto skanowanie dla: {target}", "INFO")

    scan_initiated = False

    try:
        # --- Tryb Automatyczny (Quiet/Yes) ---
        if config.QUIET_MODE:
            # Faza 0
            if "phase0_osint" not in scan_results:
                osint_data, best_url = phase0_osint.start_phase0_osint()
                scan_results["phase0_osint"] = osint_data
            else:
                osint_data = scan_results["phase0_osint"]
                best_url = phase0_osint.get_best_target_url(config.HOSTNAME_TARGET)
            
            # Faza 1
            if "phase1_subdomain" not in scan_results:
                if not config.TARGET_IS_IP:
                    p1_subs, p1_verified, p1_ips = phase1_subdomain.start_phase1_scan()
                    scan_results["phase1_subdomain"] = {
                        "subdomains": p1_subs,
                        "verified_subdomains": p1_verified,
                        "ips": p1_ips
                    }
                    current_targets = p1_verified 
                else:
                    current_targets = [clean_target]
            else:
                if not config.TARGET_IS_IP:
                    current_targets = scan_results["phase1_subdomain"].get("verified_subdomains", [])
                else:
                    current_targets = [clean_target]

            # Faza 2
            if "phase2_port_scanning" not in scan_results:
                p2_res = phase2_port_scanning.start_port_scan(current_targets)
                scan_results["phase2_port_scanning"] = p2_res
            else:
                p2_res = scan_results["phase2_port_scanning"]
            
            # Faza 3
            if "phase3_dirsearch" not in scan_results:
                urls_for_phase3 = []
                if not config.TARGET_IS_IP:
                    # Jeśli wznawiamy, upewnijmy się że mamy listę
                    p1_res = scan_results.get("phase1_subdomain", {})
                    urls_for_phase3.extend(p1_res.get("verified_subdomains", []))
                
                if p2_res and "open_ports_summary" in p2_res:
                    for host, ports in p2_res["open_ports_summary"].items():
                        for port in ports:
                            if port in [80, 443, 8080, 8443, 8000, 8888]:
                                 proto = "https" if port in [443, 8443] else "http"
                                 urls_for_phase3.append(f"{proto}://{host}:{port}")
                
                urls_for_phase3 = sorted(list(set(urls_for_phase3)))
                if not urls_for_phase3:
                    urls_for_phase3 = [best_url]

                p3_res, p3_verified = phase3_dirsearch.start_dir_search(
                    urls_for_phase3, osint_data.get("technologies", [])
                )
                scan_results["phase3_dirsearch"] = (p3_res, p3_verified)
            else:
                p3_tuple = scan_results["phase3_dirsearch"]
                if isinstance(p3_tuple, list):
                    p3_verified = p3_tuple[1] if len(p3_tuple) > 1 else []
                elif isinstance(p3_tuple, tuple):
                    p3_verified = p3_tuple[1] if len(p3_tuple) > 1 else []
                else:
                    p3_verified = []

            # Faza 4
            if "phase4_results" not in scan_results:
                targets_for_phase4 = [item['url'] for item in p3_verified]
                if not targets_for_phase4:
                    # Fallback URLS
                    targets_for_phase4 = [best_url]

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    MofNCompleteColumn(),
                    "•",
                    TimeElapsedColumn(),
                    console=utils.console,
                    transient=True,
                ) as progress:
                    task = progress.add_task("[green]Faza 4[/green]", total=1)
                    p4_res = phase4_webcrawling.start_web_crawl(targets_for_phase4, progress, task)
                    scan_results["phase4_results"] = p4_res
            
            generate_json_report(scan_results)
            report_path = generate_html_report(scan_results)
            if report_path:
                open_html_report(report_path)

        # --- Tryb Interaktywny ---
        else:
            while True:
                utils.console.print(
                    Align.center(Panel.fit("[bold magenta]Menu Główne[/bold magenta]"))
                )
                utils.console.print(Align.center(f"Cel: [bold green]{config.ORIGINAL_TARGET}[/bold green]"))
                utils.console.print(Align.center(f"Raport: [dim]{config.REPORT_DIR}[/dim]"))
                
                # Wyświetlanie statusu faz
                p0_stat = "[green]✓[/green]" if "phase0_osint" in scan_results else "[dim]-[/dim]"
                p1_stat = "[green]✓[/green]" if "phase1_subdomain" in scan_results else "[dim]-[/dim]"
                p2_stat = "[green]✓[/green]" if "phase2_port_scanning" in scan_results else "[dim]-[/dim]"
                p3_stat = "[green]✓[/green]" if "phase3_dirsearch" in scan_results else "[dim]-[/dim]"
                p4_stat = "[green]✓[/green]" if "phase4_results" in scan_results else "[dim]-[/dim]"

                table = Table(show_header=False, show_edge=False, padding=(0, 2))
                table.add_row("[bold cyan][1][/bold cyan]", f"{p0_stat} Faza 0: OSINT (Pasywny)")
                table.add_row("[bold cyan][2][/bold cyan]", f"{p1_stat} Faza 1: Subdomeny (Aktywny/Pasywny)")
                table.add_row("[bold cyan][3][/bold cyan]", f"{p2_stat} Faza 2: Skanowanie Portów")
                table.add_row("[bold cyan][4][/bold cyan]", f"{p3_stat} Faza 3: Fuzzing Katalogów")
                table.add_row("[bold cyan][5][/bold cyan]", f"{p4_stat} Faza 4: Web Crawling")
                table.add_row("[bold cyan][A][/bold cyan]", "Uruchom WSZYSTKO (Auto)")
                table.add_section()
                table.add_row("[bold cyan][q][/bold cyan]", "Wyjdź i Generuj Raport")

                utils.console.print(Align.center(table))
                choice = utils.get_single_char_input_with_prompt(
                    Text("Wybierz opcję", justify="center")
                )

                scan_initiated = True

                if choice == "1":
                    osint_data, best_url = phase0_osint.start_phase0_osint()
                    scan_results["phase0_osint"] = osint_data
                    generate_json_report(scan_results) # Zapisujemy postęp od razu
                    utils.console.print("\n[dim]Naciśnij dowolny klawisz...[/dim]")
                    utils.get_single_char_input()

                elif choice == "2":
                    if config.TARGET_IS_IP:
                        utils.console.print("[red]Faza 1 (Subdomeny) jest niedostępna dla adresu IP.[/red]")
                        time.sleep(2)
                    else:
                        if phase1_subdomain.display_phase1_tool_selection_menu(display_banner):
                             p1_subs, p1_verified, p1_ips = phase1_subdomain.start_phase1_scan()
                             scan_results["phase1_subdomain"] = {
                                "subdomains": p1_subs,
                                "verified_subdomains": p1_verified,
                                "ips": p1_ips
                             }
                             generate_json_report(scan_results)

                elif choice == "3":
                    targets_p2 = [config.CLEAN_DOMAIN_TARGET]
                    # Logika wznawiania: sprawdzamy czy mamy wyniki Fazy 1 w pamięci
                    if "phase1_subdomain" in scan_results and scan_results["phase1_subdomain"].get("verified_subdomains"):
                        count = len(scan_results['phase1_subdomain']['verified_subdomains'])
                        q = f"Znaleziono {count} subdomen w Fazie 1. Czy skanować je wszystkie?"
                        if utils.ask_user_decision(q, ["y", "n"], "y") == "y":
                             targets_p2 = scan_results["phase1_subdomain"]["verified_subdomains"]

                    if phase2_port_scanning.display_phase2_tool_selection_menu(display_banner):
                         p2_res = phase2_port_scanning.start_port_scan(targets_p2)
                         scan_results["phase2_port_scanning"] = p2_res
                         generate_json_report(scan_results)

                elif choice == "4":
                    urls_p3 = []
                    # 1. Subdomeny z pamięci
                    if "phase1_subdomain" in scan_results:
                        urls_p3.extend(scan_results["phase1_subdomain"].get("verified_subdomains", []))
                    
                    # 2. Porty z pamięci
                    if "phase2_port_scanning" in scan_results:
                         summ = scan_results["phase2_port_scanning"].get("open_ports_summary", {})
                         for h, ports in summ.items():
                             for p in ports:
                                 if p in [80, 443, 8080, 8443]:
                                     proto = "https" if p in [443, 8443] else "http"
                                     urls_p3.append(f"{proto}://{h}:{p}")
                    
                    if not urls_p3:
                        best_u = phase0_osint.get_best_target_url(config.HOSTNAME_TARGET)
                        urls_p3 = [best_u]
                    
                    urls_p3 = sorted(list(set(urls_p3)))
                    
                    # Technologie z pamięci
                    techs = scan_results.get("phase0_osint", {}).get("technologies", [])
                    
                    if phase3_dirsearch.display_phase3_tool_selection_menu(display_banner):
                        p3_res, p3_verified = phase3_dirsearch.start_dir_search(urls_p3, techs)
                        scan_results["phase3_dirsearch"] = (p3_res, p3_verified)
                        generate_json_report(scan_results)

                elif choice == "5":
                    targets_p4 = []
                    # 1. Wyniki Fazy 3
                    if "phase3_dirsearch" in scan_results:
                         p3_data = scan_results["phase3_dirsearch"]
                         # Obsługa ładowania z JSON (lista) vs tuple w locie
                         if isinstance(p3_data, list) and len(p3_data) > 1:
                             p3_v = p3_data[1]
                         elif isinstance(p3_data, tuple) and len(p3_data) > 1:
                             p3_v = p3_data[1]
                         else:
                             p3_v = []
                         
                         if p3_v:
                             targets_p4 = [x['url'] for x in p3_v]
                    
                    # Fallback
                    if not targets_p4:
                         if "phase1_subdomain" in scan_results:
                             targets_p4 = scan_results["phase1_subdomain"].get("verified_subdomains", [])
                         else:
                             targets_p4 = [f"https://{config.CLEAN_DOMAIN_TARGET}"]

                    if phase4_webcrawling.display_phase4_tool_selection_menu(display_banner):
                        with Progress(
                            SpinnerColumn(),
                            TextColumn("[progress.description]{task.description}"),
                            BarColumn(),
                            MofNCompleteColumn(),
                            "•",
                            TimeElapsedColumn(),
                            console=utils.console,
                            transient=True,
                        ) as progress:
                            task = progress.add_task(
                                "[green]Faza 4[/green]", total=1
                            )
                            p4_res = phase4_webcrawling.start_web_crawl(
                                targets_p4, progress, task
                            )
                            scan_results["phase4_results"] = p4_res
                        utils.console.print(
                            Align.center("[bold green]Faza 4 zakończona.[/bold green]")
                        )
                        generate_json_report(scan_results)
                        time.sleep(2)

                elif choice.lower() == "a":
                    # AUTO MODE (sekwencyjnie uruchamiamy brakujące fazy)
                    # Uproszczona logika: leci wszystko jak w quiet mode, ale sprawdza czy dane już są
                    config.AUTO_MODE = True
                    utils.console.print("[bold yellow]Uruchamiam kontynuację skanowania (Auto)...[/bold yellow]")
                    
                    # Tu można by wstawić logikę "jeśli nie ma w scan_results to uruchom",
                    # ale dla uproszczenia w trybie "A" z menu po prostu puszczamy pętlę
                    # (użytkownik widzi co się dzieje).
                    # W przyszłości można to zoptymalizować.
                    pass 

                elif choice.lower() == "q":
                    generate_json_report(scan_results)
                    report_path = generate_html_report(scan_results)
                    if report_path:
                        open_html_report(report_path)
                    break

    except KeyboardInterrupt:
        utils.console.print("\n[yellow]Przerwano. Czyszczenie...[/yellow]")
    finally:
        if scan_initiated:
            cleanup_temp_files()


if __name__ == "__main__":
    app()
