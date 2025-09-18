#!/usr/bin/env python3

import subprocess
import socket
import json
import re
from typing import Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor

from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.table import Table
from rich import box

import config
import utils

def get_whois_info(domain: str) -> Dict[str, Any]:
    """
    Pobiera informacje WHOIS dla podanej domeny.
    """
    results = {}
    if config.TARGET_IS_IP:
        return {"Error": "WHOIS lookup not applicable for IP addresses."}
    try:
        # Używamy flagi `-H`, aby ukryć informacje prawne, które zaśmiecają output
        command = ["whois", domain]
        process = subprocess.run(command, capture_output=True, text=True, timeout=60)
        
        if process.returncode != 0 and "No whois server is known for this kind of object" not in process.stderr:
             utils.log_and_echo(f"Błąd podczas wykonywania komendy whois: {process.stderr}", "WARN")
             return {"Error": "Could not retrieve WHOIS data."}

        output = process.stdout
        
        patterns = {
            "registrar": r"Registrar:\s*(.*)",
            "creation_date": r"Creation Date:\s*(.*)",
            "expiration_date": r"Registry Expiry Date:\s*(.*)",
            "name_servers": r"Name Server:\s*(.*)"
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
    Używa httpx do zebrania informacji o IP, ASN, CDN i technologiach,
    z fallbackiem do manualnego rozwiązywania DNS.
    """
    results: Dict[str, Any] = {}
    httpx_data: Optional[Dict[str, Any]] = None
    
    try:
        command = [
            "httpx", "-u", target, "-silent", "-json",
            "-ip", "-asn", "-cdn", "-tech-detect"
        ]
        process = subprocess.run(command, capture_output=True, text=True, timeout=60)
        
        if process.stdout:
            first_line = process.stdout.strip().split('\n')[0]
            httpx_data = json.loads(first_line)
            
            results["asn_details"] = f"AS{httpx_data.get('asn', {}).get('as_number')} ({httpx_data.get('asn', {}).get('as_name')})"
            results["cdn_name"] = httpx_data.get("cdn_name")
            results["technologies"] = httpx_data.get("tech")
            
            # --- ZMIANA: Logika pobierania IP z fallbackiem ---
            ip_address = httpx_data.get("ip")
            if not ip_address:
                try:
                    # Używamy `hostname` z wyników httpx lub oryginalnego celu
                    hostname_to_resolve = httpx_data.get('host', config.CLEAN_DOMAIN_TARGET)
                    ip_address = socket.gethostbyname(hostname_to_resolve)
                    utils.log_and_echo(f"Httpx nie zwrócił IP. Użyto socket.gethostbyname dla '{hostname_to_resolve}', znaleziono: {ip_address}", "DEBUG")
                except socket.gaierror:
                    utils.log_and_echo(f"Nie udało się rozwiązać adresu IP dla '{config.CLEAN_DOMAIN_TARGET}' przez socket.", "WARN")
                    ip_address = "Nie udało się rozwiązać"
            results["ip"] = ip_address
            # --- KONIEC ZMIANY ---

    except FileNotFoundError:
        return {"Error": "The 'httpx' command is not installed."}
    except (json.JSONDecodeError, IndexError):
        # Jeśli httpx zawiedzie, spróbuj chociaż rozwiązać IP
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

def start_phase0_osint() -> Dict[str, Any]:
    """
    Orkiestruje zbieranie informacji w Fazie 0 i wyświetla wyniki.
    """
    utils.console.print(Align.center(Panel.fit(f"[bold cyan]Faza 0: Zwiad Pasywny (OSINT) dla {config.ORIGINAL_TARGET}[/bold cyan]")))
    
    osint_data: Dict[str, Any] = {}

    with ThreadPoolExecutor() as executor:
        future_http = executor.submit(get_http_info, config.ORIGINAL_TARGET)
        future_whois = executor.submit(get_whois_info, config.CLEAN_DOMAIN_TARGET)

        http_results = future_http.result()
        whois_results = future_whois.result()
        
        osint_data.update(http_results)
        osint_data.update(whois_results)

    # Przygotowanie tabeli do wyświetlenia
    table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED, expand=True)
    table.add_column("Pole", style="cyan", min_width=20)
    table.add_column("Wartość", style="white")

    # Dodawanie wierszy do tabeli
    table.add_row("Adres IP", osint_data.get("ip", "Brak danych"))
    table.add_row("ASN / Dostawca", osint_data.get("asn_details", "Brak danych"))
    table.add_row("CDN", osint_data.get("cdn_name", "Brak") or "Brak")
    
    if not config.TARGET_IS_IP:
        table.add_section()
        table.add_row("Rejestrator Domeny", osint_data.get("registrar", "Brak danych"))
        table.add_row("Data Utworzenia", osint_data.get("creation_date", "Brak danych"))
        table.add_row("Data Wygaśnięcia", osint_data.get("expiration_date", "Brak danych"))
        
        name_servers = osint_data.get("name_servers")
        if name_servers and isinstance(name_servers, list):
             table.add_row("Serwery Nazw (NS)", "\n".join(name_servers))
        else:
             table.add_row("Serwery Nazw (NS)", "Brak danych")

    technologies = osint_data.get("technologies")
    if technologies and isinstance(technologies, list):
        table.add_section()
        table.add_row("Technologie (strona główna)", "\n".join(sorted(technologies)))

    utils.console.print(table)
    return osint_data
