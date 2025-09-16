#!/usr/bin/env python3

import os
import sys
import subprocess
import shutil
import time

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    import questionary
    from pyfiglet import Figlet
    from rich.align import Align
    from rich.columns import Columns
    from rich import box
except ImportError:
    print("BŁĄD: Podstawowe pakiety Python (rich, questionary, pyfiglet) nie są zainstalowane.")
    print("Uruchom: pip3 install rich questionary pyfiglet typer")
    sys.exit(1)

console = Console(highlight=False)

BIN_DIR = "/usr/local/bin"
SHARE_DIR = "/usr/local/share/shadowmap"
ASSUME_YES = "-y" in sys.argv or "--yes" in sys.argv
DRY_RUN = "-d" in sys.argv or "--dry-run" in sys.argv
NONINTERACTIVE = "-n" in sys.argv or "--non-interactive" in sys.argv

GO_TOOLS_TO_INSTALL = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "puredns": "github.com/d3mondev/puredns/v2/cmd/puredns@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "ffuf": "github.com/ffuf/ffuf@latest",
    "feroxbuster": "github.com/epi052/feroxbuster/cmd/feroxbuster@latest",
    "gobuster": "github.com/OJ/gobuster/v3@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "hakrawler": "github.com/hakluke/hakrawler@latest",
    "gauplus": "github.com/bp0lr/gauplus@latest"
}
PYTHON_PKGS = ["rich", "questionary", "pyfiglet", "typer"]

def run_command(command, description, sudo=False, live_output=False):
    sudo_prefix = ["sudo"] if sudo and os.geteuid() != 0 else []
    full_command = sudo_prefix + command

    if DRY_RUN:
        console.print(f"[blue]DRY RUN[/blue] Wykonuję: {' '.join(full_command)}")
        return True
    
    try:
        if live_output:
            process = subprocess.Popen(full_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
            for line in process.stdout:
                sys.stdout.write(line)
            process.wait()
            if process.returncode != 0:
                console.print(f"[red]Błąd[/red] podczas '{description}': Kod {process.returncode}")
                return False
        else:
            subprocess.run(full_command, check=True, capture_output=True, text=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        console.print(f"[red]Błąd[/red] podczas '{description}': {e}")
        return False

# ... (reszta funkcji pomocniczych bez zmian)

def main():
    # ... (logika sprawdzania zależności bez zmian)
    
    # Podmień sekcję kopiowania plików na poniższą
    console.print(f"\n[blue]Kopiowanie plików ShadowMap do {BIN_DIR} i {SHARE_DIR}...[/blue]")
    run_command(["mkdir", "-p", BIN_DIR], f"Tworzenie {BIN_DIR}", sudo=not os.geteuid() == 0)
    run_command(["mkdir", "-p", SHARE_DIR], f"Tworzenie {SHARE_DIR}", sudo=not os.geteuid() == 0)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Plik wykonywalny
    run_command(["cp", os.path.join(base_dir, "shadowmap"), BIN_DIR], "Kopiowanie shadowmap", sudo=not os.geteuid() == 0)
    run_command(["chmod", "+x", os.path.join(BIN_DIR, "shadowmap")], "Nadawanie uprawnień shadowmap", sudo=not os.geteuid() == 0)

    # Pliki modułów i zasobów
    files_to_copy_to_share = [
        "config.py",
        "utils.py",
        "phase1_subdomain.py",
        "phase2_port_scanning.py", 
        "phase3_dirsearch.py", 
        "phase4_webcrawling.py", 
        "report_template.html", 
        "resolvers.txt", 
        "user_agents.txt", 
        "subdomen_wordlist.txt", 
        "dir_wordlist.txt"
    ]
    for f in files_to_copy_to_share:
        src = os.path.join(base_dir, f)
        if os.path.exists(src):
            run_command(["cp", src, os.path.join(SHARE_DIR, f)], f"Kopiowanie {f}", sudo=not os.geteuid() == 0)

    console.print("[green]Instalacja ShadowMap zakończona pomyślnie![/green]")
    console.print("[yellow]Może być konieczne ponowne uruchomienie terminala, aby zmiany weszły w życie.[/yellow]")

if __name__ == "__main__":
    main()
