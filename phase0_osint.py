#!/usr/bin/env python3

import json
import os
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Tuple, Union

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.panel import Panel
from rich.table import Table

try:
    from webtech import WebTech
except ImportError:
    WebTech = None

import config
import utils


def get_best_target_url(target: str) -> str:
    """
    Sprawdza dostępność celu na porcie 443 (HTTPS) i 80 (HTTP)
    i zwraca najlepszy URL (preferując HTTPS).
    """
    utils.console.print(
        Align.center("[bold cyan]Sprawdzam protokół (HTTP/HTTPS)...[/bold cyan]")
    )

    try:
        sock_https = socket.create_connection((target, 443), timeout=5)
        sock_https.close()
        https_url = f"https://{target}"
        utils.console.print(
            Align.center(
                f"[bold green]✓ Port 443 (HTTPS) jest otwarty. "
                f"Używam: {https_url}[/bold green]"
            )
        )
        return https_url
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    try:
        sock_http = socket.create_connection((target, 80), timeout=5)
        sock_http.close()
        http_url = f"http://{target}"
        utils.console.print(
            Align.center(
                f"[bold yellow]! Port 443 zamknięty. Port 80 (HTTP) jest "
                f"otwarty. Używam: {http_url}[/bold yellow]"
            )
        )
        return http_url
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    default_url = f"http://{config.HOSTNAME_TARGET}"
    utils.console.print(
        Align.center(
            f"[bold red]! Nie udało się połączyć z portami 80 i 443. "
            f"Używam fallback: {default_url}[/bold red]"
        )
    )
    return default_url


def get_whois_info(domain: str) -> Dict[str, Any]:
    """Pobiera informacje WHOIS dla podanej domeny."""
    results: Dict[str, Any] = {}
    if config.TARGET_IS_IP:
        return {"Error": "WHOIS nie dotyczy adresów IP."}
    try:
        command = ["whois", domain]
        process = subprocess.run(command, capture_output=True, text=True, timeout=60)
        output = process.stdout

        phase0_dir = os.path.join(config.REPORT_DIR, "faza0_osint")
        with open(
            os.path.join(phase0_dir, "whois_raw.txt"), "w", encoding="utf-8"
        ) as f:
            f.write(f"--- WHOIS for {domain} ---\n")
            f.write(output)
            if process.stderr:
                f.write("\n--- STDERR ---\n")
                f.write(process.stderr)

        if process.returncode != 0 and "No whois server" not in process.stderr:
            utils.log_and_echo(f"Błąd 'whois': {process.stderr}", "WARN")
            return {"Error": "Nie można pobrać danych WHOIS."}

        patterns = {
            "registrar": r"Registrar:\s*(.*)",
            "creation_date": r"Creation Date:\s*(.*)",
            "expiration_date": r"Registry Expiry Date:\s*(.*)",
            "name_servers": r"Name Server:\s*(.*)",
        }

        for key, pattern in patterns.items():
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                if key == "name_servers":
                    results[key] = sorted(list(set(m.lower().strip() for m in matches)))
                else:
                    results[key] = matches[0].strip()

    except FileNotFoundError:
        return {"Error": "Polecenie 'whois' nie jest zainstalowane."}
    except subprocess.TimeoutExpired:
        return {"Error": "Polecenie WHOIS przekroczyło limit czasu."}
    except Exception as e:
        return {"Error": f"Niespodziewany błąd: {e}"}

    return results


def get_http_info(target: str) -> Dict[str, Any]:
    """Używa httpx do zebrania informacji o IP, ASN, CDN i technologiach."""
    results: Dict[str, Any] = {}

    try:
        command = [
            "httpx",
            "-u",
            target,
            "-silent",
            "-json",
            "-ip",
            "-asn",
            "-cdn",
            "-tech-detect",
        ]
        process = subprocess.run(command, capture_output=True, text=True, timeout=60)

        phase0_dir = os.path.join(config.REPORT_DIR, "faza0_osint")
        raw_path = os.path.join(phase0_dir, "httpx_osint_raw.txt")
        with open(raw_path, "w", encoding="utf-8") as f:
            f.write(f"--- httpx OSINT for {target} ---\n")
            f.write(process.stdout)
            if process.stderr:
                f.write("\n--- STDERR ---\n")
                f.write(process.stderr)

        if process.stdout:
            for line in process.stdout.strip().split("\n"):
                try:
                    data = json.loads(line)
                    asn_data = data.get("asn", {})
                    as_num = asn_data.get("as_number")
                    as_name = asn_data.get("as_name")
                    results["asn_details"] = f"AS{as_num} ({as_name})"
                    results["cdn_name"] = data.get("cdn_name")
                    results["technologies"] = data.get("tech", [])

                    ip = data.get("ip")
                    if not ip:
                        try:
                            hostname = data.get("host", config.CLEAN_DOMAIN_TARGET)
                            ip = socket.gethostbyname(hostname)
                        except socket.gaierror:
                            ip = "Nie udało się rozwiązać"
                    results["ip"] = ip
                    break
                except json.JSONDecodeError:
                    continue

    except FileNotFoundError:
        return {"Error": "Polecenie 'httpx' nie jest zainstalowane."}
    except (json.JSONDecodeError, IndexError):
        try:
            results["ip"] = socket.gethostbyname(config.CLEAN_DOMAIN_TARGET)
        except socket.gaierror:
            results["ip"] = "Nie udało się rozwiązać"
        return {"Error": "Błąd parsowania JSON z httpx.", **results}
    except subprocess.TimeoutExpired:
        return {"Error": "Polecenie httpx przekroczyło limit czasu."}
    except Exception as e:
        return {"Error": f"Niespodziewany błąd httpx: {e}"}

    return results


def get_whatweb_info(target_url: str) -> List[str]:
    """Używa whatweb do zebrania informacji o technologiach."""
    techs = []
    try:
        command = ["whatweb", "--no-error", "--log-json=-", target_url]
        process = subprocess.run(command, capture_output=True, text=True, timeout=120)

        phase0_dir = os.path.join(config.REPORT_DIR, "faza0_osint")
        raw_path = os.path.join(phase0_dir, "whatweb_raw.txt")
        with open(raw_path, "w", encoding="utf-8") as f:
            f.write(f"--- whatweb for {target_url} ---\n")
            f.write(process.stdout)
            if process.stderr:
                f.write("\n--- STDERR ---\n")
                f.write(process.stderr)

        for line in process.stdout.strip().split("\n"):
            try:
                data = json.loads(line)
                if "plugins" in data:
                    for plugin, details in data["plugins"].items():
                        tech_name = plugin.replace("-", " ").title()
                        if "version" in details and details["version"]:
                            versions = ", ".join(map(str, details["version"]))
                            techs.append(f"{tech_name} ({versions})")
                        else:
                            techs.append(tech_name)
            except json.JSONDecodeError:
                continue
    except FileNotFoundError:
        utils.log_and_echo(
            "Polecenie 'whatweb' nie jest zainstalowane. Pomijam.", "WARN"
        )
    except subprocess.TimeoutExpired:
        utils.log_and_echo("Polecenie whatweb przekroczyło limit czasu.", "WARN")
    except Exception as e:
        utils.log_and_echo(f"Niespodziewany błąd whatweb: {e}", "ERROR")

    return sorted(list(set(techs)))


def get_webtech_info(target_url: str) -> List[str]:
    """Używa biblioteki webtech do zebrania informacji o technologiach."""
    if WebTech is None:
        utils.log_and_echo(
            "Biblioteka 'webtech' nie jest zainstalowana. Pomijam.", "WARN"
        )
        return []

    techs = []
    try:
        wt = WebTech()
        results_obj = wt.start_from_url(target_url, timeout=30)

        results = {}
        if isinstance(results_obj, str):
            try:
                results = json.loads(results_obj)
            except json.JSONDecodeError:
                utils.log_and_echo("Błąd parsowania JSON z webtech.", "WARN")
                return []
        elif isinstance(results_obj, dict):
            results = results_obj

        for tech_info in results.get("tech", []):
            if isinstance(tech_info, dict):
                name = tech_info.get("name")
                version = tech_info.get("version")
                if name:
                    tech_entry = name
                    if version:
                        tech_entry += f" ({version})"
                    techs.append(tech_entry)
            elif isinstance(tech_info, str):
                techs.append(tech_info)

    except Exception as e:
        utils.log_and_echo(f"Niespodziewany błąd webtech: {e}", "ERROR")

    return sorted(list(set(techs)))


def get_searchsploit_info(
    technologies: List[str],
) -> Union[Dict[str, List[Dict[str, str]]], Dict[str, str]]:
    """Używa searchsploit do znalezienia exploitów."""
    results: Dict[str, List[Dict[str, str]]] = {}
    phase0_dir = os.path.join(config.REPORT_DIR, "faza0_osint")
    raw_output_path = os.path.join(phase0_dir, "searchsploit_raw.txt")

    with open(raw_output_path, "w", encoding="utf-8") as raw_f:
        for tech in technologies:
            try:
                search_terms = re.findall(r"[\w.-]+", tech.split("(")[0].strip())
                if not search_terms:
                    continue

                command = ["searchsploit", "--json"] + search_terms
                process = subprocess.run(
                    command, capture_output=True, text=True, timeout=60
                )

                raw_f.write(f"--- searchsploit for: {' '.join(search_terms)} ---\n")
                raw_f.write(process.stdout)
                if process.stderr:
                    raw_f.write(f"\n--- STDERR ---\n{process.stderr}\n")

                if process.stdout:
                    data = json.loads(process.stdout)
                    exploits = data.get("RESULTS_EXPLOIT")
                    if exploits:
                        if tech not in results:
                            results[tech] = []

                        existing_ids = {e["id"] for e in results[tech]}
                        for exploit in exploits:
                            if exploit.get("EDB-ID") not in existing_ids:
                                results[tech].append(
                                    {
                                        "title": exploit.get("Title", "N/A"),
                                        "path": exploit.get("Path", "N/A"),
                                        "id": exploit.get("EDB-ID", "N/A"),
                                    }
                                )
                                existing_ids.add(exploit["EDB-ID"])

            except FileNotFoundError:
                msg = "Polecenie 'searchsploit' nie jest zainstalowane."
                return {"Error": msg}
            except subprocess.TimeoutExpired:
                msg = f"Searchsploit dla '{tech}' przekroczył limit czasu."
                utils.log_and_echo(msg, "WARN")
            except json.JSONDecodeError:
                msg = f"Błąd parsowania JSON z searchsploit dla '{tech}'."
                utils.log_and_echo(msg, "WARN")
            except Exception as e:
                utils.log_and_echo(f"Niespodziewany błąd searchsploit: {e}", "ERROR")
    return results


def start_phase0_osint() -> Tuple[Dict[str, Any], str]:
    """Orkiestruje zbieranie informacji w Fazie 0."""
    panel_title = f"[bold cyan]Faza 0: OSINT dla {config.ORIGINAL_TARGET}[/bold cyan]"
    utils.console.print(Align.center(Panel.fit(panel_title)))

    osint_data: Dict[str, Any] = {}
    status_text = "[green]Przeprowadzam zwiad pasywny (OSINT)...[/green]"
    with utils.console.status(status_text, spinner="dots") as status:
        best_target_url = get_best_target_url(config.HOSTNAME_TARGET)

        status.update(
            "[green]Zbieram informacje WHOIS, HTTP i o technologiach...[/green]"
        )
        with ThreadPoolExecutor() as executor:
            f_http = executor.submit(get_http_info, best_target_url)
            f_whois = executor.submit(get_whois_info, config.CLEAN_DOMAIN_TARGET)
            f_whatweb = executor.submit(get_whatweb_info, best_target_url)
            f_webtech = executor.submit(get_webtech_info, best_target_url)

            osint_data.update(f_http.result())
            osint_data.update(f_whois.result())
            all_techs = set(osint_data.get("technologies", []))
            all_techs.update(f_whatweb.result())
            all_techs.update(f_webtech.result())

            filtered_techs = {
                tech
                for tech in all_techs
                if tech.split("(")[0].strip().lower() not in config.OSINT_TECH_BLOCKLIST
            }
            osint_data["technologies"] = sorted(list(filtered_techs))

        if osint_data.get("technologies"):
            status.update(
                "[green]Szukam publicznych exploitów (Searchsploit)...[/green]"
            )
            searchsploit_results = get_searchsploit_info(osint_data["technologies"])
            osint_data["searchsploit_results"] = searchsploit_results

    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.ROUNDED,
        expand=True,
    )
    table.add_column("Pole", style="cyan", min_width=20)
    table.add_column("Wartość", style="white")

    table.add_row("Adres IP", osint_data.get("ip", "Brak danych"))
    table.add_row("ASN / Dostawca", osint_data.get("asn_details", "Brak danych"))
    table.add_row("CDN", osint_data.get("cdn_name", "Brak") or "Brak")

    if not config.TARGET_IS_IP:
        table.add_section()
        table.add_row("Rejestrator", osint_data.get("registrar", "Brak danych"))
        table.add_row("Data Utworzenia", osint_data.get("creation_date", "Brak danych"))
        table.add_row(
            "Data Wygaśnięcia",
            osint_data.get("expiration_date", "Brak danych"),
        )
        ns = osint_data.get("name_servers")
        table.add_row("Serwery Nazw (NS)", "\n".join(ns) if ns else "Brak danych")

    if technologies := osint_data.get("technologies"):
        table.add_section()
        midpoint = (len(technologies) + 1) // 2
        col1 = "\n".join(technologies[:midpoint])
        col2 = "\n".join(technologies[midpoint:])
        tech_display = Columns([col1, col2], equal=True, expand=True)
        table.add_row(f"Technologie ({len(technologies)})", tech_display)

    exploits = osint_data.get("searchsploit_results")
    if exploits and "Error" not in exploits:
        table.add_section()
        exploits_summary = []
        total_exploits = 0
        for tech, exploit_list in exploits.items():
            count = len(exploit_list)
            if count:
                total_exploits += count
                summary = f"[yellow]{tech}[/yellow]: [bold red]{count}[/bold red]"
                exploits_summary.append(summary)
        if total_exploits > 0:
            table.add_row(
                f"Znalezione Exploity ({total_exploits})",
                "\n".join(exploits_summary),
            )
        else:
            table.add_row(
                "Znalezione Exploity",
                "[green]Brak znanych exploitów[/green]",
            )

    utils.console.print(table)
    return osint_data, best_target_url
