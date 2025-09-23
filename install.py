#!/usr/bin/env python3

import os
import shutil
import subprocess
import sys

try:
    import questionary
    from pyfiglet import Figlet
    from rich import box
    from rich.align import Align
    from rich.columns import Columns
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("BŁĄD: Podstawowe pakiety (rich, questionary, pyfiglet) nie są zainstalowane.")
    print("Uruchom: pip3 install rich questionary pyfiglet typer")
    sys.exit(1)

console = Console(highlight=False)

# --- Definicje ---
BIN_DIR = "/usr/local/bin"
SHARE_DIR = "/usr/local/share/shadowmap"
ASSUME_YES = "-y" in sys.argv or "--yes" in sys.argv
DRY_RUN = "-d" in sys.argv or "--dry-run" in sys.argv
NONINTERACTIVE = "-n" in sys.argv or "--non-interactive" in sys.argv
IS_ROOT = os.geteuid() == 0

# ZAKTUALIZOWANO: Dodano 'whatweb'
SYSTEM_DEPS = ["go", "python3", "pip3", "nmap", "masscan", "whois", "whatweb"]
GO_TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "puredns": "github.com/d3mondev/puredns/v2/cmd/puredns@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "ffuf": "github.com/ffuf/ffuf@latest",
    "feroxbuster": "github.com/epi052/feroxbuster@latest",
    "gobuster": "github.com/OJ/gobuster/v3@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "hakrawler": "github.com/hakluke/hakrawler@latest",
    "gauplus": "github.com/bp0lr/gauplus@latest",
}
# ZAKTUALIZOWANO: Dodano 'webtech' i 'requests'
PYTHON_PKGS = [
    "rich", "questionary", "pyfiglet", "typer",
    "psutil", "webtech", "requests",
]


def display_banner():
    f = Figlet(font="slant")
    banner_text = f.renderText("ShadowMap\nInstaller")
    console.print(Align.center(Text(banner_text, style="bold cyan")))


def run_command(command, description, sudo=False, live_output=False):
    sudo_prefix = ["sudo"] if sudo and not IS_ROOT else []
    full_command = sudo_prefix + command
    cmd_str = " ".join(full_command)

    if DRY_RUN:
        console.print(Align.center(f"[blue]DRY RUN[/blue] Wykonuję: {cmd_str}"))
        return True

    console.print(Align.center(
        f"-> [yellow]Uruchamiam:[/yellow] {description} ([dim]{cmd_str}[/dim])"
    ))
    try:
        if live_output:
            process = subprocess.Popen(
                full_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, universal_newlines=True
            )
            for line in process.stdout:
                console.print(Align.center(f"[dim]  {line.strip()}[/dim]"))
            process.wait()
            if process.returncode != 0:
                console.print(Align.center(
                    f"[red]Błąd[/red] podczas '{description}': Kod {process.returncode}"
                ))
                return False
        else:
            subprocess.run(
                full_command, check=True, capture_output=True, text=True
            )
        return True
    except FileNotFoundError:
        console.print(Align.center(
            f"[red]Błąd[/red]: Polecenie '{full_command[0]}' nie znalezione."
        ))
        return False
    except subprocess.CalledProcessError as e:
        console.print(Align.center(
            f"[red]Błąd[/red] podczas '{description}': Kod {e.returncode}."
        ))
        console.print(Align.center(
            Panel(e.stderr, title="[red]STDERR[/red]", border_style="red", expand=False)
        ))
        return False
    except Exception as e:
        console.print(Align.center(
            f"[red]Nieoczekiwany błąd[/red] podczas '{description}': {e}"
        ))
        return False


def check_dependencies():
    missing_system, missing_go = [], []

    system_table = Table(
        title="Zależności Systemowe i Python", box=box.ROUNDED,
        show_header=True, header_style="bold magenta"
    )
    system_table.add_column("Narzędzie", style="cyan")
    system_table.add_column("Status", justify="center")

    for dep in SYSTEM_DEPS:
        if shutil.which(dep):
            system_table.add_row(dep, "[bold green]✓ ZNALEZIONO[/bold green]")
        else:
            system_table.add_row(dep, "[bold red]✗ BRAK[/bold red]")
            missing_system.append(dep)

    go_table = Table(
        title="Narzędzia Rekonesansu (Go)", box=box.ROUNDED,
        show_header=True, header_style="bold magenta"
    )
    go_table.add_column("Narzędzie", style="cyan")
    go_table.add_column("Status", justify="center")

    for tool in GO_TOOLS:
        if shutil.which(tool):
            go_table.add_row(tool, "[bold green]✓ ZNALEZIONO[/bold green]")
        else:
            go_table.add_row(tool, "[bold red]✗ BRAK[/bold red]")
            missing_go.append(tool)

    console.print(Align.center(Columns([system_table, go_table], expand=True)))
    return missing_system, missing_go


def main():
    display_banner()
    console.print(Align.center(Panel.fit(
        "[bold]Instalator ShadowMap sprawdzi i zainstaluje zależności.[/bold]",
        border_style="green",
    )))

    missing_system_deps, missing_go_tools = check_dependencies()

    if not missing_system_deps and not missing_go_tools:
        console.print(Align.center(
            "\n[bold green]Wszystkie zależności są już zainstalowane![/bold green]"
        ))
    else:
        console.print(Align.center("\n[bold yellow]Wykryto brakujące zależności.[/bold yellow]"))
        install_confirmed = (ASSUME_YES or NONINTERACTIVE or
                             questionary.confirm("Zainstalować brakujące pakiety?").ask())

        if install_confirmed:
            if missing_system_deps:
                console.print(Align.center(
                    f"\n[blue]Instaluję zależności: {', '.join(missing_system_deps)}...[/blue]"
                ))
                run_command(["apt-get", "update"], "Aktualizacja listy pakietów", sudo=True)
                run_command(
                    ["apt-get", "install", "-y"] + missing_system_deps,
                    "Instalacja pakietów systemowych", sudo=True, live_output=True
                )

            if missing_go_tools:
                console.print(Align.center(
                    f"\n[blue]Instaluję narzędzia Go: {', '.join(missing_go_tools)}...[/blue]"
                ))
                for tool in missing_go_tools:
                    run_command(
                        ["go", "install", "-v", GO_TOOLS[tool]],
                        f"Instalacja {tool}", live_output=True
                    )

    console.print(Align.center(
        f"\n[blue]Instaluję/aktualizuję pakiety Python...[/blue]"
    ))
    run_command(
        ["pip3", "install", "--upgrade"] + PYTHON_PKGS,
        "Instalacja pakietów pip", live_output=True
    )

    console.print(Align.center(
        f"\n[blue]Kopiuję pliki ShadowMap do {BIN_DIR} i {SHARE_DIR}...[/blue]"
    ))
    run_command(["mkdir", "-p", SHARE_DIR], f"Tworzenie katalogu {SHARE_DIR}", sudo=True)

    base_dir = os.path.dirname(os.path.abspath(__file__))

    run_command(
    ["cp", os.path.join(base_dir, "shadowmap.py"), os.path.join(BIN_DIR, "shadowmap")],
    "Kopiowanie głównego skryptu",
    sudo=True
)
    run_command(
        ["chmod", "+x", os.path.join(BIN_DIR, "shadowmap")],
        "Nadawanie uprawnień wykonywalnych", sudo=True
    )

    files_to_copy = [
        "config.py", "utils.py", "phase0_osint.py", "phase1_subdomain.py",
        "phase2_port_scanning.py", "phase3_dirsearch.py", "phase4_webcrawling.py",
        "report_template.html", "resolvers.txt", "user_agents.txt",
        "subdomen_wordlist.txt", "dir_wordlist.txt",
    ]
    for f_name in files_to_copy:
        src = os.path.join(base_dir, f_name)
        if os.path.exists(src):
            run_command(["cp", src, SHARE_DIR], f"Kopiowanie zasobu: {f_name}", sudo=True)

    final_message_text = (
        "[bold green]Instalacja ShadowMap zakończona pomyślnie![/bold green]\n\n"
        "Uruchom narzędzie wpisując: [bold cyan]shadowmap <cel>[/bold cyan]\n\n"
        "[yellow]Uwaga:[/yellow] Może być konieczne ponowne uruchomienie terminala."
    )
    final_message = Panel(
        Text.from_markup(final_message_text, justify="center"),
        title="[bold]Gotowe![/bold]", border_style="green"
    )
    console.print(Align.center(final_message))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Instalacja przerwana przez użytkownika.[/bold red]")
        sys.exit(1)

