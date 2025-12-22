#!/usr/bin/env python3

import os
import shutil
import subprocess
import sys
from typing import List, Dict, Tuple

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
    print("BŁĄD: Podstawowe pakiety nie są zainstalowane.")
    print("Uruchom: pip3 install rich questionary pyfiglet typer")
    sys.exit(1)

os.system("sudo rm -rf $(which httpx)")

console = Console(highlight=False)

BIN_DIR = "/usr/local/bin"
SHARE_DIR = "/usr/local/share/shadowmap"
ASSUME_YES = "-y" in sys.argv or "--yes" in sys.argv
DRY_RUN = "-d" in sys.argv or "--dry-run" in sys.argv
NONINTERACTIVE = "-n" in sys.argv or "--non-interactive" in sys.argv
IS_ROOT = os.geteuid() == 0

# Zależności systemowe (bez Pythona/Go)
SYSTEM_DEPS: List[str] = ["go", "nmap", "masscan", "whois", "git"]

# Narzędzia Python - mapowanie polecenia na pakiet apt
PYTHON_APT_TOOLS: Dict[str, str] = {
    "python3": "python3",
    "pip3": "python3-pip",
    "whatweb": "whatweb",
    "wafw00f": "wafw00f",
    "pipx": "python3-pipx",
    "searchsploit": "exploitdb",
}

# Narzędzia Go
GO_TOOLS: Dict[str, str] = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "puredns": "github.com/d3mondev/puredns/v2@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "ffuf": "github.com/ffuf/ffuf@latest",
    "feroxbuster": "github.com/epi052/feroxbuster@latest",
    "gobuster": "github.com/OJ/gobuster/v3@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "hakrawler": "github.com/hakluke/hakrawler@latest",
    "gauplus": "github.com/bp0lr/gauplus@latest",
    "dirsearch": "github.com/maurosoria/dirsearch@latest",
}

# Narzędzia Python instalowane przez pipx
PIPX_TOOLS: Dict[str, str] = {"paramspider": "paramspider"}

# Narzędzia Python wymagające specjalnej instalacji (pip3)
MANUAL_PYTHON_TOOLS: Dict[str, str] = {
    "linkfinder": "git+https://github.com/GerbenJavado/LinkFinder.git"
}

# Pakiety Python (pip)
PYTHON_PKGS: List[str] = [
    "rich",
    "questionary",
    "pyfiglet",
    "typer",
    "requests",
    "webtech",
    "urllib3",
]


def display_banner():
    """Wyświetla banner powitalny."""
    f = Figlet(font="slant")
    banner_text = f.renderText("ShadowMap\nInstaller")
    console.print(Align.center(Text(banner_text, style="bold cyan")))


def _get_path_with_go_and_pipx(env: Dict[str, str]) -> str:
    """Konstruuje zmienną PATH z uwzględnieniem ścieżek dla Go i Pipx."""
    path_list = [env.get("PATH", "")]
    home = env.get("HOME", "")

    if home:
        path_list.insert(0, f"{home}/.local/bin")

    go_path = env.get("GOPATH", f"{home}/go")
    if go_path:
        path_list.insert(0, os.path.join(go_path, "bin"))

    return ":".join(filter(None, path_list))


def run_command(
    command: List[str], description: str, sudo: bool = False, live_output: bool = False
) -> bool:
    """Uruchamia podane polecenie i obsługuje błędy."""
    env = os.environ.copy()
    env["PATH"] = _get_path_with_go_and_pipx(env)

    sudo_prefix = ["sudo"] if sudo and not IS_ROOT else []
    full_command = sudo_prefix + command
    cmd_str = " ".join(
        f'"{p}"' if " " in p and "'" not in p else p for p in full_command
    )

    if DRY_RUN:
        console.print(f"[blue]DRY RUN[/blue] Wykonuję: {cmd_str}")
        return True

    console.print(
        Align.center(
            f"-> [yellow]Uruchamiam:[/yellow] {description} " f"([dim]{cmd_str}[/dim])"
        )
    )
    try:
        process = subprocess.Popen(
            full_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            env=env,
        )
        for line in process.stdout:
            stripped_line = line.strip()
            if stripped_line and live_output:
                console.print(Align.center(f"[dim]  {stripped_line}[/dim]"))
        process.wait()

        if process.returncode != 0:
            msg = f"Błąd podczas '{description}': Kod {process.returncode}"
            console.print(Align.center(f"[bold red]{msg}[/bold red]"))
            return False
        return True

    except FileNotFoundError:
        tool_name = full_command[0]
        msg = f"BŁĄD: Polecenie '{tool_name}' nie znalezione. Upewnij się, że jest w PATH."
        console.print(Align.center(f"[bold red]{msg}[/bold red]"))
        return False
    except Exception as e:
        msg = f"Nieoczekiwany błąd podczas '{description}': {type(e).__name__}: {e}"
        console.print(Align.center(f"[bold red]{msg}[/bold red]"))
        return False


def check_dependencies() -> Tuple[List[str], List[str], List[str], List[str]]:
    """Sprawdza obecność narzędzi i zwraca listę brakujących w każdej kategorii."""
    missing_system, missing_go, missing_python_apt, missing_pipx_manual = [], [], [], []
    env = os.environ.copy()
    env["PATH"] = _get_path_with_go_and_pipx(env)

    system_table = Table(
        title="System & APT",
        box=box.ROUNDED,
        show_header=False,
        title_style="bold magenta",
    )
    all_system_tools = SYSTEM_DEPS + list(PYTHON_APT_TOOLS.keys())
    for dep in sorted(all_system_tools):
        if shutil.which(dep, path=env["PATH"]):
            system_table.add_row(f"[bold green]✓[/bold green] {dep}")
        else:
            if dep in SYSTEM_DEPS:
                missing_system.append(dep)
            elif dep in PYTHON_APT_TOOLS:
                missing_python_apt.append(dep)
            system_table.add_row(f"[bold red]✗[/bold red] {dep}")

    go_table = Table(
        title="Narzędzia Go",
        box=box.ROUNDED,
        show_header=False,
        title_style="bold magenta",
    )
    for tool in sorted(GO_TOOLS.keys()):
        if shutil.which(tool, path=env["PATH"]):
            go_table.add_row(f"[bold green]✓[/bold green] {tool}")
        else:
            missing_go.append(tool)
            go_table.add_row(f"[bold red]✗[/bold red] {tool}")

    pipx_table = Table(
        title="Narzędzia Python",
        box=box.ROUNDED,
        show_header=False,
        title_style="bold magenta",
    )
    all_python_cli_tools = {**PIPX_TOOLS, **MANUAL_PYTHON_TOOLS}
    for tool in sorted(all_python_cli_tools.keys()):
        if shutil.which(tool, path=env["PATH"]):
            pipx_table.add_row(f"[bold green]✓[/bold green] {tool}")
        else:
            missing_pipx_manual.append(tool)
            pipx_table.add_row(f"[bold red]✗[/bold red] {tool}")

    console.print(
        Panel(
            Columns([system_table, go_table, pipx_table], align="center", expand=True),
            title="[bold]Status Zależności[/bold]",
            border_style="blue",
        )
    )

    return missing_system, missing_go, missing_python_apt, missing_pipx_manual


def main():
    """Główna funkcja instalacyjna."""
    display_banner()
    panel_text = "[bold]Instalator ShadowMap sprawdzi i zainstaluje zależności.[/bold]"
    console.print(Align.center(Panel.fit(panel_text, border_style="green")))

    if not IS_ROOT and not DRY_RUN:
        console.print(
            Align.center(
                Panel(
                    "[bold yellow]UWAGA:[/bold yellow] Uruchomienie z `sudo` jest "
                    "zalecane do instalacji w /usr/local/.",
                    border_style="yellow",
                )
            )
        )

    missing_system, missing_go, missing_python_apt, missing_pipx_manual = (
        check_dependencies()
    )

    all_missing = missing_system + missing_go + missing_python_apt + missing_pipx_manual
    if not any(all_missing):
        console.print(
            Align.center(
                "\n[bold green]Wszystkie narzędzia CLI są zainstalowane![/bold green]"
            )
        )
    else:
        console.print(
            Align.center(
                "\n[bold yellow]Wykryto brakujące narzędzia CLI.[/bold yellow]"
            )
        )
        install_confirmed = (
            ASSUME_YES
            or NONINTERACTIVE
            or questionary.confirm("Zainstalować brakujące pakiety?").ask()
        )
        if install_confirmed:
            apt_packages_to_install = [
                p for p in missing_system if p in SYSTEM_DEPS
            ] + [
                PYTHON_APT_TOOLS[t] for t in missing_python_apt if t in PYTHON_APT_TOOLS
            ]

            if apt_packages_to_install:
                deps = ", ".join(apt_packages_to_install)
                console.print(
                    f"\n[blue]Instaluję zależności systemowe (apt): {deps}...[/blue]"
                )
                if not IS_ROOT:
                    console.print(
                        Align.center(
                            "[bold yellow]Wprowadź hasło do sudo...[/bold yellow]"
                        )
                    )
                run_command(
                    ["apt-get", "update"], "Aktualizacja listy pakietów", sudo=True
                )
                run_command(
                    ["apt-get", "install", "-y"] + apt_packages_to_install,
                    "Instalacja pakietów",
                    sudo=True,
                    live_output=True,
                )

            if missing_go:
                console.print(
                    f"\n[blue]Instaluję narzędzia Go: {', '.join(missing_go)}...[/blue]"
                )
                for tool in missing_go:
                    run_command(
                        ["go", "install", "-v", GO_TOOLS[tool]],
                        f"Instalacja {tool}",
                        live_output=True,
                    )

            if missing_pipx_manual:
                console.print(
                    f"\n[blue]Instaluję narzędzia Python CLI: {', '.join(missing_pipx_manual)}...[/blue]"
                )
                for tool in missing_pipx_manual:
                    if tool in PIPX_TOOLS:
                        run_command(
                            ["pipx", "install", "--force", PIPX_TOOLS[tool]],
                            f"Instalacja {tool}",
                            live_output=True,
                        )
                    elif tool in MANUAL_PYTHON_TOOLS:
                        console.print(
                            Align.center(
                                f"[cyan]Instalacja specjalna dla {tool} za pomocą pip3...[/cyan]"
                            )
                        )
                        if run_command(
                            ["pip3", "install", "--user", MANUAL_PYTHON_TOOLS[tool]],
                            f"Instalacja {tool}",
                            live_output=True,
                        ):
                            # KROK NAPRAWCZY: Utwórz symlink
                            console.print(
                                Align.center(
                                    "[cyan]Konfiguruję dowiązanie symboliczne dla LinkFinder...[/cyan]"
                                )
                            )
                            home = os.path.expanduser("~")
                            source_path = os.path.join(
                                home, ".local", "bin", "linkfinder.py"
                            )
                            target_path = os.path.join(
                                home, ".local", "bin", "linkfinder"
                            )

                            if os.path.exists(source_path):
                                if os.path.lexists(target_path):
                                    os.remove(target_path)
                                run_command(
                                    ["ln", "-s", source_path, target_path],
                                    "Tworzenie symlinka dla linkfinder",
                                )
                            else:
                                console.print(
                                    f"[bold red]BŁĄD: Nie znaleziono {source_path} po instalacji.[/bold red]"
                                )

    console.print(
        "\n[blue]Instaluję/aktualizuję podstawowe pakiety Python (pip)...[/blue]"
    )
    run_command(
        ["pip3", "install", "--upgrade"] + PYTHON_PKGS,
        "Instalacja pakietów pip",
        live_output=True,
    )

    console.print(f"\n[blue]Kopiuję pliki do {BIN_DIR} i {SHARE_DIR}...[/blue]")
    base_dir = os.path.dirname(os.path.abspath(__file__))

    run_command(["mkdir", "-p", SHARE_DIR], f"Tworzenie {SHARE_DIR}", sudo=True)

    script_path = os.path.join(base_dir, "shadowmap.py")
    bin_path = os.path.join(BIN_DIR, "shadowmap")
    run_command(["cp", script_path, bin_path], "Kopiowanie głównego skryptu", sudo=True)
    run_command(
        ["chmod", "+x", bin_path], "Nadawanie uprawnień wykonywalnych", sudo=True
    )

    files_to_copy = [
        "config.py",
        "utils.py",
        "phase0_osint.py",
        "phase1_subdomain.py",
        "phase2_port_scanning.py",
        "phase3_dirsearch.py",
        "phase4_webcrawling.py",
        "report_template.html",
        "resolvers.txt",
        "user_agents.txt",
    ]
    for f_name in files_to_copy:
        src = os.path.join(base_dir, f_name)
        if os.path.exists(src):
            run_command(["cp", src, SHARE_DIR], f"Kopiowanie {f_name}", sudo=True)

    final_text = (
        "[bold green]Instalacja ShadowMap zakończona pomyślnie![/bold green]\n\n"
        "Uruchom narzędzie wpisując: [bold cyan]shadowmap <cel>[/bold cyan]\n\n"
        "[yellow]Uwaga:[/yellow] Może być konieczne ponowne uruchomienie terminala, aby zmiany w PATH były widoczne."
    )
    console.print(
        Align.center(
            Panel(final_text, title="[bold]Gotowe![/bold]", border_style="green")
        )
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Instalacja przerwana przez użytkownika.[/bold red]")
        sys.exit(1)
