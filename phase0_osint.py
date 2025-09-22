#!/usr/bin/env python3

import json
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# NOWOŚĆ: Import biblioteki webtech
try:
    from webtech import WebTech
except ImportError:
    WebTech = None  # Zapewnij działanie, nawet jeśli import zawiedzie

import config
import utils


def get_best_target_url(target: str) -> str:
    """
    Sprawdza dostępność celu na porcie 443 (HTTPS) i 80 (HTTP) za pomocą gniazd (sockets)
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
                f"[bold green]✓ Port 443 (HTTPS) jest otwarty. Używam: {https_url}[/bold green]"
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
                f"[bold yellow]! Port 443 zamknięty. Port 80 (HTTP) jest otwarty. Używam: {http_url}[/bold yellow]"
            )
        )
        return http_url
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    default_url = f"http://{config.HOSTNAME_TARGET}"
    utils.console.print(
        Align.center(
            f"[bold red]! Nie udało się połączyć ani z portem 80, ani 443. Używam fallback: {default_url}[/bold red]"
        )
    )
    return default_url


def get_whois_info(domain: str) -> Dict[str, Any]:
    """
    Pobiera informacje WHOIS dla podanej domeny.
    """
    results = {}
    if config.TARGET_IS_IP:
        return {"Error": "WHOIS lookup not applicable for IP addresses."}
    try:
        command = ["whois", domain]
        process = subprocess.run(command, capture_output=True, text=True, timeout=60)

        if (
            process.returncode != 0
            and "No whois server is known for this kind of object" not in process.stderr
        ):
            utils.log_and_echo(
                f"Błąd podczas wykonywania komendy whois: {process.stderr}", "WARN"
            )
            return {"Error": "Could not retrieve WHOIS data."}

        output = process.stdout

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
        return {"Error": "The 'whois' command is not installed."}
    except subprocess.TimeoutExpired:
        return {"Error": "WHOIS command timed out."}
    except Exception as e:
        return {"Error": f"An unexpected error occurred: {e}"}

    return results


def get_http_info(target: str) -> Dict[str, Any]:
    """
    Używa httpx do zebrania informacji o IP, ASN, CDN i technologiach.
    """
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

        if process.stdout:
            for line in process.stdout.strip().split("\n"):
                try:
                    httpx_data = json.loads(line)
                    results["asn_details"] = (
                        f"AS{httpx_data.get('asn', {}).get('as_number')} ({httpx_data.get('asn', {}).get('as_name')})"
                    )
                    results["cdn_name"] = httpx_data.get("cdn_name")
                    results["technologies"] = httpx_data.get(
                        "tech", []
                    )  # Zawsze zwracaj listę

                    ip_address = httpx_data.get("ip")
                    if not ip_address:
                        try:
                            hostname_to_resolve = httpx_data.get(
                                "host", config.CLEAN_DOMAIN_TARGET
                            )
                            ip_address = socket.gethostbyname(hostname_to_resolve)
                        except socket.gaierror:
                            ip_address = "Nie udało się rozwiązać"
                    results["ip"] = ip_address
                    break
                except json.JSONDecodeError:
                    continue

    except FileNotFoundError:
        return {"Error": "The 'httpx' command is not installed."}
    except (json.JSONDecodeError, IndexError):
        try:
            results["ip"] = socket.gethostbyname(config.CLEAN_DOMAIN_TARGET)
        except socket.gaierror:
            results["ip"] = "Nie udało się rozwiązać"
        return {"Error": "Failed to parse httpx JSON output.", **results}
    except subprocess.TimeoutExpired:
        return {"Error": "httpx command timed out."}
    except Exception as e:
        return {"Error": f"An unexpected httpx error occurred: {e}"}

    return results


def get_whatweb_info(target_url: str) -> List[str]:
    """
    Używa whatweb do zebrania informacji o technologiach.
    """
    techs = []
    try:
        command = ["whatweb", "--no-error", "--log-json=-", target_url]
        process = subprocess.run(command, capture_output=True, text=True, timeout=120)

        for line in process.stdout.strip().split("\n"):
            try:
                data = json.loads(line)
                if "plugins" in data:
                    for plugin, details in data["plugins"].items():
                        techs.append(plugin.replace("-", " ").title())
                        if "version" in details and details["version"]:
                            # Dodaj wersję do poprzedniego elementu
                            techs[-1] = (
                                f"{techs[-1]} ({', '.join(map(str, details['version']))})"
                            )
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
    """
    Używa biblioteki webtech do zebrania informacji o technologiach.
    """
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
                utils.log_and_echo(f"Błąd parsowania JSON z webtech.", "WARN")
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


def start_phase0_osint() -> Tuple[Dict[str, Any], str]:
    """
    Orkiestruje zbieranie informacji w Fazie 0 i zwraca wyniki oraz najlepszy URL.
    """
    utils.console.print(
        Align.center(
            Panel.fit(
                f"[bold cyan]Faza 0: Zwiad Pasywny (OSINT) dla {config.ORIGINAL_TARGET}[/bold cyan]"
            )
        )
    )

    best_target_url = get_best_target_url(config.HOSTNAME_TARGET)

    osint_data: Dict[str, Any] = {}
    with ThreadPoolExecutor() as executor:
        future_http = executor.submit(get_http_info, best_target_url)
        future_whois = executor.submit(get_whois_info, config.CLEAN_DOMAIN_TARGET)
        future_whatweb = executor.submit(get_whatweb_info, best_target_url)
        future_webtech = executor.submit(get_webtech_info, best_target_url)

        http_results = future_http.result()
        whois_results = future_whois.result()
        whatweb_results = future_whatweb.result()
        webtech_results = future_webtech.result()

        osint_data.update(http_results)
        osint_data.update(whois_results)

        # Scalanie technologii z 3 źródeł: httpx, whatweb, webtech
        all_techs = set(osint_data.get("technologies", []))
        all_techs.update(whatweb_results)
        all_techs.update(webtech_results)
        osint_data["technologies"] = sorted(list(all_techs))

    table = Table(
        show_header=True, header_style="bold magenta", box=box.ROUNDED, expand=True
    )
    table.add_column("Pole", style="cyan", min_width=20)
    table.add_column("Wartość", style="white")

    table.add_row("Adres IP", osint_data.get("ip", "Brak danych"))
    table.add_row("ASN / Dostawca", osint_data.get("asn_details", "Brak danych"))
    table.add_row("CDN", osint_data.get("cdn_name", "Brak") or "Brak")

    if not config.TARGET_IS_IP:
        table.add_section()
        table.add_row("Rejestrator Domeny", osint_data.get("registrar", "Brak danych"))
        table.add_row("Data Utworzenia", osint_data.get("creation_date", "Brak danych"))
        table.add_row(
            "Data Wygaśnięcia", osint_data.get("expiration_date", "Brak danych")
        )

        name_servers = osint_data.get("name_servers")
        if name_servers and isinstance(name_servers, list):
            table.add_row("Serwery Nazw (NS)", "\n".join(name_servers))
        else:
            table.add_row("Serwery Nazw (NS)", "Brak danych")

    technologies = osint_data.get("technologies")
    if technologies and isinstance(technologies, list):
        table.add_section()
        # ZMIANA: Wyświetlanie technologii w dwóch kolumnach
        midpoint = (len(technologies) + 1) // 2
        col1 = "\n".join(technologies[:midpoint])
        col2 = "\n".join(technologies[midpoint:])
        tech_display = Columns([col1, col2], equal=True, expand=True)
        table.add_row(f"Technologie ({len(technologies)} wykrytych)", tech_display)

    utils.console.print(table)
    return osint_data, best_target_url
