#!/usr/bin/env python3

import os
import subprocess
import sys

# ---------------------------------------------------------------------------
# BOOTSTRAP: jeśli nie działamy jeszcze w dedykowanym venv shadowmap,
# tworzymy go, instalujemy zależności i re-execujemy się jego Pythonem.
# Dzięki temu install.py jest samowystarczalny bez --break-system-packages.
# ---------------------------------------------------------------------------
_VENV_DIR = "/usr/local/share/shadowmap/.venv"
_VENV_PYTHON = os.path.join(_VENV_DIR, "bin", "python3")
_PYTHON_PKGS = [
    "rich",
    "questionary",
    "pyfiglet",
    "typer",
    "requests",
    "webtech",
    "urllib3",
]


def _bootstrap():
    """Zapewnia działający venv z zależnościami i re-execuje się w nim."""
    running_in_venv = os.environ.get("_SHADOWMAP_INSTALLER_VENV") == "1"
    if running_in_venv:
        return  # jesteśmy już w venv, kontynuuj normalnie

    # W trybie dry-run pomijamy tworzenie venv — sprawdzamy tylko czy istnieje
    is_dry_run = "--dry-run" in sys.argv or "-d" in sys.argv
    if is_dry_run and os.path.exists(_VENV_PYTHON):
        os.environ["_SHADOWMAP_INSTALLER_VENV"] = "1"
        os.execv(_VENV_PYTHON, [_VENV_PYTHON] + sys.argv)

    is_root = os.geteuid() == 0
    share_dir = os.path.dirname(_VENV_DIR)

    # Sprawdź czy możemy pisać do katalogu share bez sudo
    can_write_share = os.access(share_dir, os.W_OK) if os.path.exists(share_dir) else False
    need_sudo_for_venv = not is_root and not can_write_share

    # Stwórz katalog nadrzędny jeśli nie istnieje
    if not os.path.exists(share_dir):
        sudo_prefix = [] if is_root else ["sudo"]
        subprocess.check_call(sudo_prefix + ["mkdir", "-p", share_dir])
        subprocess.check_call(sudo_prefix + ["chmod", "755", share_dir])

    # Stwórz venv jeśli nie istnieje
    if not os.path.exists(_VENV_PYTHON):
        print(f"[bootstrap] Tworzę środowisko wirtualne: {_VENV_DIR}")
        try:
            if need_sudo_for_venv:
                subprocess.check_call(["sudo", sys.executable, "-m", "venv", _VENV_DIR])
                # Nadaj uprawnienia aktualnemu użytkownikowi
                user = os.environ.get("SUDO_USER") or os.environ.get("USER", "")
                if user:
                    subprocess.check_call(["sudo", "chown", "-R", f"{user}:{user}", _VENV_DIR])
            else:
                subprocess.check_call([sys.executable, "-m", "venv", _VENV_DIR])
        except subprocess.CalledProcessError:
            print(f"BŁĄD: Nie udało się stworzyć venv w {_VENV_DIR}.")
            print("Spróbuj uruchomić: sudo python3 install.py")
            sys.exit(1)

    # Zainstaluj/zaktualizuj zależności Python w venv
    print("[bootstrap] Instaluję zależności Python w venv...")
    pip_cmd = [_VENV_PYTHON, "-m", "pip", "install", "--quiet", "--upgrade"] + _PYTHON_PKGS
    try:
        subprocess.check_call(pip_cmd)
    except subprocess.CalledProcessError:
        print("BŁĄD: Nie udało się zainstalować zależności Python.")
        sys.exit(1)

    # Re-exec z Pythonem z venv
    print("[bootstrap] Uruchamiam instalator w środowisku venv...\n")
    os.environ["_SHADOWMAP_INSTALLER_VENV"] = "1"
    os.execv(_VENV_PYTHON, [_VENV_PYTHON] + sys.argv)



_bootstrap()  # Wywołaj przed jakimikolwiek innymi importami

# ---------------------------------------------------------------------------
# Normalne importy — działamy już w venv, wszystko jest dostępne
# ---------------------------------------------------------------------------
import re
import shutil
from typing import List, Dict, Tuple, Any, Optional

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

# Próba importu config.py z bieżącego katalogu
config: Any = None
try:
    import config
except ImportError:
    pass

console = Console(highlight=False)

BIN_DIR = "/usr/local/bin"
SHARE_DIR = "/usr/local/share/shadowmap"
VENV_DIR = _VENV_DIR  # Ten sam venv co bootstrap
VENV_PYTHON = _VENV_PYTHON
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

# Mapowanie: polecenie CLI → pakiet APT
# Narzędzia z tej listy są sprawdzane i instalowane przez apt-get
SYSTEM_APT_TOOLS: Dict[str, str] = {
    "go": "golang-go",
    "nmap": "nmap",
    "masscan": "masscan",
    "whois": "whois",
    "git": "git",
    "python3": "python3",
    "pip3": "python3-pip",
    "whatweb": "whatweb",
    "wafw00f": "wafw00f",
    "pipx": "pipx",           # Parrot/Kali: pakiet to 'pipx', nie 'python3-pipx'
    "dirsearch": "dirsearch", # Python tool - dostępny w APT na Parrot/Kali
    "paramspider": "paramspider",  # Dostępny w APT na Parrot/Kali
    "massdns": "massdns",     # Wymagane przez puredns
    "searchsploit": "exploitdb",
}

# Backward compat — używane w kilku miejscach
SYSTEM_DEPS: List[str] = ["go", "nmap", "masscan", "whois", "git"]
PYTHON_APT_TOOLS: Dict[str, str] = {k: v for k, v in SYSTEM_APT_TOOLS.items() if k not in SYSTEM_DEPS}

# Narzędzia Go (tylko narzędzia napisane w Go - nie Python!)
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
    # dirsearch usunięty - to Python tool, instalowany przez APT
}

# Narzędzia binarne instalowane bezpośrednio z oficjalnych wydań GitHub (precompiled binaries)
BINARY_TOOLS: Dict[str, Dict[str, str]] = {
    "findomain": {
        "url": "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip",
        "binary_name": "findomain",
    },
}

# Narzędzia instalowane przez pipx (fallback gdy nie ma w APT)
# Na Parrot/Kali paramspider jest w APT - pipx tylko jako fallback
PIPX_TOOLS: Dict[str, str] = {}

# Narzędzia Python instalowane do shadowmap venv (pip install do venv)
# linkfinder nie ma pakietu APT - instalujemy do venv i tworzymy wrapper
VENV_PIP_TOOLS: Dict[str, str] = {
    "linkfinder": "git+https://github.com/GerbenJavado/LinkFinder.git",
}

# Stara nazwa - zachowana dla kompatybilności wstecznej
MANUAL_PYTHON_TOOLS: Dict[str, str] = VENV_PIP_TOOLS

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


def _get_real_user_home() -> str:
    """Zwraca katalog domowy rzeczywistego użytkownika.

    Gdy skrypt uruchamiany jest przez sudo, HOME jest ustawione na /root,
    ale SUDO_USER wskazuje na prawdziwego użytkownika. Ta funkcja zawsze
    zwraca katalog domowy rzeczywistego użytkownika (nie roota).
    """
    sudo_user = os.environ.get("SUDO_USER", "")
    if sudo_user:
        import pwd
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            pass
    return os.path.expanduser("~")


def _is_projectdiscovery_httpx(path: Optional[str]) -> bool:
    """Sprawdza, czy binarka podaną ścieżką to faktycznie httpx od ProjectDiscovery,
    a nie klient HTTP Pythona (pakiet Debian python3-httpx)."""
    if not path or not os.path.exists(path):
        return False
    try:
        res = subprocess.run(
            [path, "-version"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        out = (res.stdout + res.stderr).lower()
        return "projectdiscovery" in out or (
            "httpx" in out and "version" in out and "butterfly" not in out and "next generation" not in out
        )
    except Exception:
        return False


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
    missing_system, missing_go, missing_binary, missing_pipx_manual = [], [], [], []
    env = os.environ.copy()
    env["PATH"] = _get_path_with_go_and_pipx(env)

    # Gdy uruchomiony jako root (sudo), dodać też ścieżki rzeczywistego użytkownika
    real_home = _get_real_user_home()
    if real_home != env.get("HOME", ""):
        real_go_bin = os.path.join(real_home, "go", "bin")
        real_local_bin = os.path.join(real_home, ".local", "bin")
        for extra in [real_go_bin, real_local_bin]:
            if extra not in env["PATH"]:
                env["PATH"] = extra + ":" + env["PATH"]

    system_table = Table(title="System & APT", box=box.ROUNDED, show_header=False)
    for dep in sorted(SYSTEM_APT_TOOLS.keys()):
        if shutil.which(dep, path=env["PATH"]):
            system_table.add_row(f"[bold green]✓[/bold green] {dep}")
        else:
            missing_system.append(dep)
            system_table.add_row(f"[bold red]✗[/bold red] {dep}")

    go_table = Table(title="Narzędzia Go", box=box.ROUNDED, show_header=False)
    for tool in sorted(GO_TOOLS.keys()):
        p = shutil.which(tool, path=env["PATH"])
        if p and (tool != "httpx" or _is_projectdiscovery_httpx(p)):
            go_table.add_row(f"[bold green]✓[/bold green] {tool}")
        else:
            missing_go.append(tool)
            reason = " (kolizja z python3-httpx)" if (tool == "httpx" and p) else ""
            go_table.add_row(f"[bold red]✗[/bold red] {tool}{reason}")

    binary_table = Table(title="Narzędzia Binarne", box=box.ROUNDED, show_header=False)
    missing_binary: List[str] = []
    for tool in sorted(BINARY_TOOLS.keys()):
        if shutil.which(tool, path=env["PATH"]):
            binary_table.add_row(f"[bold green]✓[/bold green] {tool}")
        else:
            missing_binary.append(tool)
            binary_table.add_row(f"[bold red]✗[/bold red] {tool}")

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
            Columns([system_table, go_table, binary_table, pipx_table], align="center", expand=True),
            title="[bold]Status Zależności[/bold]",
            border_style="blue",
        )
    )
    return missing_system, missing_go, missing_binary, missing_pipx_manual


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


def create_shadowmap_wrapper(bin_path: str):
    """Tworzy shell wrapper skrypt dla shadowmap używający dedykowanego venv.

    Wrapper zapewnia że `shadowmap` działa globalnie z terminala bez
    konieczności aktywowania środowiska wirtualnego przez użytkownika.
    """
    wrapper_content = f"""#!/bin/bash
# ShadowMap - wrapper uruchamiający w dedykowanym środowisku Python
# Wygenerowany automatycznie przez install.py

SHADOWMAP_VENV="{VENV_DIR}"
SHADOWMAP_SCRIPT="{SHARE_DIR}/shadowmap.py"
VENV_PYTHON="$SHADOWMAP_VENV/bin/python3"

# Dodaj ~/go/bin i ~/.local/bin do PATH (narzędzia Go i pipx)
export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"

if [ ! -x "$VENV_PYTHON" ]; then
    echo "BŁĄD: Środowisko Python shadowmap nie jest skonfigurowane." >&2
    echo "Uruchom: sudo python3 {os.path.abspath(__file__)}" >&2
    exit 1
fi

if [ ! -f "$SHADOWMAP_SCRIPT" ]; then
    echo "BŁĄD: Nie znaleziono $SHADOWMAP_SCRIPT" >&2
    exit 1
fi

exec "$VENV_PYTHON" "$SHADOWMAP_SCRIPT" "$@"
"""
    if DRY_RUN:
        console.print(f"[blue]DRY RUN[/blue] Tworzę wrapper: {bin_path}")
        console.print(f"[dim]{wrapper_content}[/dim]")
        return

    tmp_wrapper = f"/tmp/shadowmap_wrapper_{os.getpid()}"
    try:
        with open(tmp_wrapper, "w") as f:
            f.write(wrapper_content)
        run_command(["cp", tmp_wrapper, bin_path], "Instalacja shadowmap wrapper", sudo=True)
        run_command(["chmod", "+x", bin_path], "Uprawnienia wykonywalne", sudo=True)
    finally:
        if os.path.exists(tmp_wrapper):
            os.remove(tmp_wrapper)

    console.print(f"[green]✓ Wrapper shadowmap zainstalowany: {bin_path}[/green]")


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

    missing_system, missing_go, missing_binary, missing_pipx_manual = (
        check_dependencies()
    )

    all_missing = missing_system + missing_go + missing_binary + missing_pipx_manual

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
            # Mapuj brakujące polecenia na nazwy pakietów apt
            apt_packages = [
                SYSTEM_APT_TOOLS[cmd]
                for cmd in missing_system
                if cmd in SYSTEM_APT_TOOLS
            ]
            # Usuń duplikaty zachowując kolejność
            seen: set = set()
            apt_packages = [p for p in apt_packages if not (p in seen or seen.add(p))]  # type: ignore

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
                # Narzędzia Go muszą być instalowane jako właściwy user (nie root)
                # bo GOPATH jest w katalogu domowym użytkownika
                real_home = _get_real_user_home()
                go_env = os.environ.copy()
                go_env["PATH"] = _get_path_with_go_and_pipx(go_env)
                if real_home:
                    go_env["HOME"] = real_home
                    go_env["GOPATH"] = os.path.join(real_home, "go")
                    go_env["PATH"] = os.path.join(real_home, "go", "bin") + ":" + go_env["PATH"]

                for tool in missing_go:
                    if IS_ROOT:
                        # Uruchom go install jako właściwy user przez sudo -u
                        real_user = os.environ.get("SUDO_USER", "")
                        if real_user:
                            run_command(
                                ["sudo", "-u", real_user, "-E",
                                 "env", f"HOME={real_home}", f"GOPATH={go_env['GOPATH']}" ,
                                 f"PATH={go_env['PATH']}",
                                 "go", "install", "-v", GO_TOOLS[tool]],
                                f"Go install {tool} (jako {real_user})",
                                live_output=True,
                            )
                        else:
                            run_command(
                                ["go", "install", "-v", GO_TOOLS[tool]],
                                f"Go install {tool}",
                                live_output=True,
                            )
                    else:
                        run_command(
                            ["go", "install", "-v", GO_TOOLS[tool]],
                            f"Go install {tool}",
                            live_output=True,
                        )

                # Utwórz symlinki w /usr/local/bin dla wszystkich narzędzi Go,
                # aby były dostępne globalnie w całym systemie (w tym dla sudo)
                real_go_bin = os.path.join(real_home, "go", "bin")
                if os.path.exists(real_go_bin):
                    for g_tool in os.listdir(real_go_bin):
                        src_g = os.path.join(real_go_bin, g_tool)
                        if os.path.isfile(src_g) and os.access(src_g, os.X_OK):
                            run_command(
                                ["ln", "-sf", src_g, os.path.join(BIN_DIR, g_tool)],
                                f"Symlink {BIN_DIR}/{g_tool} -> {src_g}",
                                sudo=True,
                            )

            if missing_binary:
                console.print("\n[blue]Pobieram i instaluję narzędzia binarne...[/blue]")
                import zipfile
                for b_name in missing_binary:
                    b_info = BINARY_TOOLS.get(b_name, {})
                    b_url = b_info.get("url")
                    if b_url:
                        tmp_zip = f"/tmp/{b_name}_{os.getpid()}.zip"
                        if download_file(b_url, tmp_zip):
                            try:
                                extract_dir = f"/tmp/{b_name}_extract_{os.getpid()}"
                                os.makedirs(extract_dir, exist_ok=True)
                                with zipfile.ZipFile(tmp_zip, "r") as z:
                                    z.extractall(extract_dir)
                                extracted_bin = os.path.join(extract_dir, b_info.get("binary_name", b_name))
                                if os.path.exists(extracted_bin):
                                    os.chmod(extracted_bin, 0o755)
                                    run_command(
                                        ["cp", extracted_bin, os.path.join(BIN_DIR, b_name)],
                                        f"Instalacja {b_name} do {BIN_DIR}",
                                        sudo=True,
                                    )
                                    console.print(f"[green]✓ Zainstalowano {b_name} do {BIN_DIR}/{b_name}[/green]")
                            except Exception as e:
                                console.print(f"[red]Błąd rozpakowywania {b_name}: {e}[/red]")
                            finally:
                                if os.path.exists(tmp_zip):
                                    os.remove(tmp_zip)

            if missing_pipx_manual:
                console.print("\n[blue]Instaluję narzędzia Python (do venv)...[/blue]")
                real_user = os.environ.get("SUDO_USER", "") if IS_ROOT else ""
                real_home = _get_real_user_home()

                for tool in missing_pipx_manual:
                    if tool in VENV_PIP_TOOLS:
                        # Instaluj do shadowmap venv — omija "externally-managed-environment"
                        # Venv jest owned przez real_user — musimy uruchomić pip jako ten user
                        pkg = VENV_PIP_TOOLS[tool]
                        if IS_ROOT and real_user:
                            run_command(
                                ["sudo", "-u", real_user, VENV_PYTHON, "-m", "pip",
                                 "install", "--quiet", pkg],
                                f"Pip install {tool} do venv (jako {real_user})",
                                live_output=True,
                            )
                        else:
                            run_command(
                                [VENV_PYTHON, "-m", "pip", "install", "--quiet", pkg],
                                f"Pip install {tool} do venv",
                                live_output=True,
                            )
                        # Utwórz wrapper script w ~/.local/bin żeby tool był dostępny globalnie
                        if tool == "linkfinder":
                            local_bin = os.path.join(real_home, ".local", "bin")
                            os.makedirs(local_bin, exist_ok=True)
                            wrapper_path = os.path.join(local_bin, "linkfinder")
                            # Znajdź skrypt linkfinder.py w venv
                            venv_linkfinder = os.path.join(
                                os.path.dirname(VENV_PYTHON), "linkfinder.py"
                            )
                            wrapper_content = f"""#!/bin/bash
exec "{VENV_PYTHON}" "{venv_linkfinder}" "$@"
"""
                            if not DRY_RUN:
                                with open(wrapper_path, "w") as wf:
                                    wf.write(wrapper_content)
                                os.chmod(wrapper_path, 0o755)
                                # Zmień właściciela jeśli jesteśmy rootem
                                if IS_ROOT and real_user:
                                    run_command(
                                        ["chown", f"{real_user}:{real_user}", wrapper_path],
                                        "Zmiana właściciela linkfinder wrapper",
                                    )
                                console.print(f"[green]✓ Wrapper linkfinder: {wrapper_path}[/green]")
                            else:
                                console.print(f"[blue]DRY RUN[/blue] Wrapper: {wrapper_path}")
                    elif tool in PIPX_TOOLS:
                        # Fallback: pipx (jeśli PIPX_TOOLS nie jest puste)
                        if IS_ROOT and real_user:
                            run_command(
                                ["sudo", "-u", real_user, "-E",
                                 "env", f"HOME={real_home}",
                                 "pipx", "install", "--force", PIPX_TOOLS[tool]],
                                f"Pipx install {tool} (jako {real_user})",
                                live_output=True,
                            )
                        else:
                            run_command(
                                ["pipx", "install", "--force", PIPX_TOOLS[tool]],
                                f"Pipx install {tool}",
                                live_output=True,
                            )



    console.print(f"\n[blue]Instaluję pliki aplikacji do {SHARE_DIR}...[/blue]")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    run_command(["mkdir", "-p", SHARE_DIR], f"Tworzenie {SHARE_DIR}", sudo=True)

    # Instaluj/zaktualizuj Python deps w venv shadowmap
    console.print("\n[blue]Aktualizuję zależności Python w venv...[/blue]")
    pip_install_cmd = [
        VENV_PYTHON, "-m", "pip", "install", "--quiet", "--upgrade"
    ] + PYTHON_PKGS
    run_command(pip_install_cmd, "Instalacja Python deps do venv")

    # Stwórz wrapper skrypt zamiast kopiować shadowmap.py bezpośrednio
    bin_path = os.path.join(BIN_DIR, "shadowmap")
    create_shadowmap_wrapper(bin_path)

    files_to_copy = [
        "shadowmap.py",
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
