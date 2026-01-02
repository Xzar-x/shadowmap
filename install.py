#!/usr/bin/env python3

import os
import shutil
import subprocess
import sys
import re
from typing import List, Dict, Tuple, Any

try:
    import questionary
    import requests
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
    print("Uruchom: pip3 install rich questionary pyfiglet typer requests")
    sys.exit(1)

# Próba importu config.py z bieżącego katalogu
config: Any = None
try:
    import config
except ImportError:
    pass

console = Console(highlight=False)

BIN_DIR = "/usr/local/bin"
SHARE_DIR = "/usr/local/share/shadowmap"
WORDLISTS_DIR = os.path.join(SHARE_DIR, "wordlists")

ASSUME_YES = "-y" in sys.argv or "--yes" in sys.argv
DRY_RUN = "-d" in sys.argv or "--dry-run" in sys.argv
NONINTERACTIVE = "-n" in sys.argv or "--non-interactive" in sys.argv
IS_ROOT = os.geteuid() == 0

# --- Definicje Wordlist ---
WORDLIST_MAPPING = {
    "DEFAULT_WORDLIST_PHASE1": (
        "subdomains-top1million-20000.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
    ),
    "SMALL_WORDLIST_PHASE1": (
        "subdomains-top1million-5000.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
    ),
    "DEFAULT_WORDLIST_PHASE3": (
        "DirBuster-2007_directory-list-2.3-medium.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
    ),
    "SMALL_WORDLIST_PHASE3": (
        "DirBuster-2007_directory-list-2.3-small.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
    ),
    "WORDPRESS_WORDLIST": (
        "wordpress.fuzz.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
    ),
    "JOOMLA_WORDLIST": (
        "Joomla.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/Joomla.txt",
    ),
    "DRUPAL_WORDLIST": (
        "Drupal.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/Drupal.txt",
    ),
    "TOMCAT_WORDLIST": (
        "common.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
    ),
}

# Miejsca gdzie szukamy list
SEARCH_PATHS = [
    "/usr/share/seclists",
    "/usr/share/wordlists",
    "/opt/seclists",
    "/usr/local/share/wordlists",
    os.path.expanduser("~/SecLists"),
    os.path.expanduser("~/wordlists"),
    os.getcwd(),
]

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

PIPX_TOOLS: Dict[str, str] = {"paramspider": "paramspider"}

MANUAL_PYTHON_TOOLS: Dict[str, str] = {
    "linkfinder": "git+https://github.com/GerbenJavado/LinkFinder.git"
}

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
        if process.stdout:
            for line in process.stdout:
                stripped_line = line.strip()
                if stripped_line and live_output:
                    console.print(Align.center(f"[dim]  {stripped_line}[/dim]"))
        process.wait()

        if process.returncode != 0:
            console.print(
                Align.center(f"[bold red]Błąd podczas '{description}'[/bold red]")
            )
            return False
        return True

    except Exception as e:
        console.print(Align.center(f"[bold red]Błąd: {e}[/bold red]"))
        return False


def check_dependencies() -> Tuple[List[str], List[str], List[str], List[str]]:
    missing_system, missing_go, missing_python_apt, missing_pipx_manual = [], [], [], []
    env = os.environ.copy()
    env["PATH"] = _get_path_with_go_and_pipx(env)

    system_table = Table(title="System & APT", box=box.ROUNDED, show_header=False)
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

    go_table = Table(title="Narzędzia Go", box=box.ROUNDED, show_header=False)
    for tool in sorted(GO_TOOLS.keys()):
        if shutil.which(tool, path=env["PATH"]):
            go_table.add_row(f"[bold green]✓[/bold green] {tool}")
        else:
            missing_go.append(tool)
            go_table.add_row(f"[bold red]✗[/bold red] {tool}")

    pipx_table = Table(title="Narzędzia Python", box=box.ROUNDED, show_header=False)
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


def download_file(url: str, dest_path: str):
    """Pobiera plik z URL i zapisuje go w dest_path."""
    try:
        console.print(f"[dim]Pobieranie: {os.path.basename(dest_path)}...[/dim]")
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        with open(dest_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except Exception as e:
        console.print(f"[red]Błąd pobierania {url}: {e}[/red]")
        return False


def patch_config_file(config_path: str, variable_updates: Dict[str, str]):
    """Aktualizuje wartości zmiennych w pliku config.py."""
    if not os.path.exists(config_path):
        console.print(
            f"[red]Nie znaleziono pliku konfiguracyjnego: {config_path}[/red]"
        )
        return

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()

        for var_name, new_value in variable_updates.items():
            pattern = rf"^{var_name}\s*=\s*[\'\"].*?[\'\"]"
            replacement = f'{var_name} = "{new_value}"'

            if re.search(pattern, content, re.MULTILINE):
                content = re.sub(pattern, replacement, content, flags=re.MULTILINE)

        with open(config_path, "w", encoding="utf-8") as f:
            f.write(content)

        console.print("[green]Zaktualizowano ścieżki w pliku config.py[/green]")
    except Exception as e:
        console.print(f"[red]Błąd aktualizacji config.py: {e}[/red]")


def find_file_in_search_paths(filename: str) -> str | None:
    """Przeszukuje typowe lokalizacje w poszukiwaniu pliku."""
    for path in SEARCH_PATHS:
        if not os.path.exists(path):
            continue

        # Szybkie sprawdzenie czy plik jest bezpośrednio w ścieżce
        direct_path = os.path.join(path, filename)
        if os.path.isfile(direct_path):
            return direct_path

        # Przeszukiwanie rekurencyjne (walk)
        for root, _, files in os.walk(path):
            if filename in files:
                return os.path.join(root, filename)

    return None


def check_and_fix_wordlists():
    """Sprawdza listy słów, szuka ich w systemie lub oferuje pobranie."""
    if not config:
        return

    console.print("\n[blue]Weryfikacja dostępności list słów (wordlists)...[/blue]")

    missing_vars = []
    updates = {}

    table = Table(
        title="Status Wordlist",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Zmienna Config", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Ścieżka", style="dim")

    for var_name, (filename, url) in WORDLIST_MAPPING.items():
        current_path = getattr(config, var_name, "")
        if isinstance(current_path, tuple):
            current_path = current_path[0]

        if os.path.exists(current_path) and os.path.isfile(current_path):
            table.add_row(var_name, "[bold green]✓[/bold green]", current_path)
        else:
            # Próba znalezienia w systemie po samej nazwie pliku
            console.print(f"[dim]Szukam {filename} w systemie...[/dim]", end="\r")
            found_path = find_file_in_search_paths(filename)

            if found_path:
                table.add_row(
                    var_name, "[bold yellow]Znaleziono[/bold yellow]", found_path
                )
                updates[var_name] = found_path
            else:
                table.add_row(var_name, "[bold red]✗[/bold red]", "Nie znaleziono")
                missing_vars.append(var_name)

    console.print(Align.center(table))

    # Aktualizacja config.py jeśli znaleziono nowe ścieżki
    if updates:
        installed_config = os.path.join(SHARE_DIR, "config.py")
        console.print(
            f"\n[green]Znaleziono {len(updates)} list w systemie. Aktualizuję config.py...[/green]"
        )
        patch_config_file(installed_config, updates)

        if os.path.exists("config.py"):
            patch_config_file("config.py", updates)

    # Obsługa brakujących plików (pobieranie)
    if missing_vars:
        console.print(
            Align.center(
                Panel(
                    "[yellow]Nadal brakuje niektórych list słów.[/yellow]\n"
                    "Mogę pobrać brakujące pliki automatycznie.",
                    title="Naprawa Braków",
                    border_style="yellow",
                )
            )
        )

        should_download = (
            ASSUME_YES
            or NONINTERACTIVE
            or questionary.confirm("Czy chcesz pobrać BRAKUJĄCE listy teraz?").ask()
        )

        if should_download:
            if IS_ROOT:
                if not os.path.exists(WORDLISTS_DIR):
                    run_command(
                        ["mkdir", "-p", WORDLISTS_DIR],
                        "Tworzenie katalogu wordlists",
                        sudo=False,
                    )
                    run_command(
                        ["chmod", "755", WORDLISTS_DIR],
                        "Uprawnienia katalogu",
                        sudo=False,
                    )
            else:
                run_command(
                    ["mkdir", "-p", WORDLISTS_DIR],
                    "Tworzenie katalogu wordlists",
                    sudo=True,
                )
                run_command(
                    ["chmod", "777", WORDLISTS_DIR],
                    "Uprawnienia katalogu (tymczasowe)",
                    sudo=True,
                )

            download_updates = {}
            for var_name in missing_vars:
                filename, url = WORDLIST_MAPPING[var_name]
                dest_path = os.path.join(WORDLISTS_DIR, filename)

                if download_file(url, dest_path):
                    download_updates[var_name] = dest_path

            installed_config = os.path.join(SHARE_DIR, "config.py")
            if download_updates:
                console.print("[blue]Podpinam pobrane pliki do konfiguracji...[/blue]")
                patch_config_file(installed_config, download_updates)
                if os.path.exists("config.py"):
                    patch_config_file("config.py", download_updates)
    else:
        console.print(
            Align.center(
                "[bold green]Wszystkie wordlisty są skonfigurowane.[/bold green]"
            )
        )


def main():
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

    if any(all_missing):
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
            apt_packages = [p for p in missing_system if p in SYSTEM_DEPS] + [
                PYTHON_APT_TOOLS[t] for t in missing_python_apt if t in PYTHON_APT_TOOLS
            ]

            if apt_packages:
                console.print("\n[blue]Instaluję pakiety systemowe...[/blue]")
                run_command(["apt-get", "update"], "Update APT", sudo=True)
                run_command(
                    ["apt-get", "install", "-y"] + apt_packages,
                    "Instalacja APT",
                    sudo=True,
                    live_output=True,
                )

            if missing_go:
                console.print("\n[blue]Instaluję narzędzia Go...[/blue]")
                for tool in missing_go:
                    run_command(
                        ["go", "install", "-v", GO_TOOLS[tool]],
                        f"Go install {tool}",
                        live_output=True,
                    )

            if missing_pipx_manual:
                console.print("\n[blue]Instaluję narzędzia Python...[/blue]")
                for tool in missing_pipx_manual:
                    if tool in PIPX_TOOLS:
                        run_command(
                            ["pipx", "install", "--force", PIPX_TOOLS[tool]],
                            f"Pipx install {tool}",
                            live_output=True,
                        )
                    elif tool in MANUAL_PYTHON_TOOLS:
                        run_command(
                            ["pip3", "install", "--user", MANUAL_PYTHON_TOOLS[tool]],
                            f"Pip install {tool}",
                            live_output=True,
                        )
                        if tool == "linkfinder":
                            home = os.path.expanduser("~")
                            src = os.path.join(home, ".local", "bin", "linkfinder.py")
                            dst = os.path.join(home, ".local", "bin", "linkfinder")
                            if os.path.exists(src):
                                if os.path.lexists(dst):
                                    os.remove(dst)
                                run_command(
                                    ["ln", "-s", src, dst], "Symlink LinkFinder"
                                )

    console.print(f"\n[blue]Instaluję pliki aplikacji do {SHARE_DIR}...[/blue]")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    run_command(["mkdir", "-p", SHARE_DIR], f"Tworzenie {SHARE_DIR}", sudo=True)

    script_path = os.path.join(base_dir, "shadowmap.py")
    bin_path = os.path.join(BIN_DIR, "shadowmap")
    run_command(["cp", script_path, bin_path], "Instalacja shadowmap bin", sudo=True)
    run_command(["chmod", "+x", bin_path], "Uprawnienia wykonywalne", sudo=True)

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

    check_and_fix_wordlists()

    final_text = (
        "[bold green]Instalacja ShadowMap zakończona![/bold green]\n\n"
        "Uruchom: [bold cyan]shadowmap <cel>[/bold cyan]"
    )
    console.print(Align.center(Panel(final_text, title="Sukces", border_style="green")))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Przerwano.[/bold red]")
        sys.exit(1)
