#!/usr/bin/env python3

# install.py - checks and installs dependencies for the ShadowMap tool
# Author: Xzar - Improved version

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

# Initialize rich console
console = Console(highlight=False)

# --- Definitions ---
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

def run_command(command, description, sudo=False, capture_output=False, live_output=False, timeout=300, check_return_code=True):
    sudo_prefix = ["sudo"] if sudo and os.geteuid() != 0 else []
    full_command = sudo_prefix + command

    if DRY_RUN:
        console.print(f"[blue]DRY RUN[/blue] Wykonuję: {' '.join(full_command)}")
        return True, ""

    try:
        if live_output:
            process = subprocess.Popen(full_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
            output_buffer = []
            for line in process.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()
                output_buffer.append(line)
            process.wait()
            if check_return_code and process.returncode != 0:
                console.print(f"[red]Błąd[/red] podczas '{description}': Kod {process.returncode}")
                return False, "".join(output_buffer)
            return True, "".join(output_buffer)
        else:
            result = subprocess.run(full_command, capture_output=capture_output, text=True, check=check_return_code, timeout=timeout)
            return True, result.stdout.strip() if capture_output else ""
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        console.print(f"[red]Błąd[/red] podczas '{description}': {e}")
        return False, str(e)

def check_go_installation():
    """Checks if the 'go' command is available and returns the GOBIN path."""
    status, _ = run_command(["go", "version"], "Sprawdzanie Go", capture_output=True, check_return_code=False)
    if not status:
        return False, None
    _, gopath = run_command(["go", "env", "GOPATH"], "Pobieranie GOPATH", capture_output=True, check_return_code=False)
    gobin = os.path.join(gopath.strip(), 'bin') if gopath.strip() else None
    return True, gobin

def check_python_installation():
    """Checks if the 'python3' command is available."""
    status, _ = run_command(["python3", "--version"], "Sprawdzanie Python3", capture_output=True, check_return_code=False)
    return status

def install_with_pkg_manager(packages, manager_cmd, is_root, description):
    console.print(f"[blue]Instalacja: {description}...[/blue]")
    return run_command(manager_cmd + packages, f"Instalacja {description}", sudo=not is_root, live_output=True)[0]

def install_go_tools(missing_tools, gobin_path):
    for name in missing_tools:
        console.print(f"[blue]Instalacja {name}...[/blue]")
        run_command(["go", "install", GO_TOOLS_TO_INSTALL[name]], f"Instalacja {name}", live_output=True)
        # Ensure the tool is executable
        tool_path = os.path.join(gobin_path, name)
        if os.path.exists(tool_path):
            run_command(["chmod", "+x", tool_path], f"Nadawanie uprawnień {name}")

def install_python_deps(missing_pkgs):
    console.print(f"[blue]Instalacja pakietów Python: {', '.join(missing_pkgs)}...[/blue]")
    return run_command(["pip3", "install"] + missing_pkgs, "Instalacja pakietów Python", live_output=True)[0]

def install_from_git(repo_url, install_path, is_root, executable_name=None):
    console.print(f"[blue]Instalacja {os.path.basename(install_path)} z Git...[/blue]")
    if os.path.exists(install_path):
        run_command(["git", "-C", install_path, "pull"], f"Aktualizacja {os.path.basename(install_path)}", sudo=not is_root)
    else:
        run_command(["git", "clone", "--depth", "1", repo_url, install_path], f"Klonowanie {os.path.basename(install_path)}", sudo=not is_root, live_output=True)
    
    if executable_name:
        script_path = os.path.join(install_path, executable_name)
        if os.path.exists(script_path):
            run_command(["chmod", "+x", script_path], f"Nadawanie uprawnień {executable_name}", sudo=not is_root)

def main():
    f = Figlet(font='slant')
    console.print(Align.center(Text(f.renderText('ShadowMap'), style="blue")))
    console.print(Panel(Text("--- Narzędzie do instalacji i konfiguracji ---", justify="center"), style="bold blue"))

    is_root = os.geteuid() == 0
    pkg_manager = []
    if shutil.which("apt-get"): pkg_manager = ["apt-get", "install", "-y"]
    elif shutil.which("yum"): pkg_manager = ["yum", "install", "-y"]
    elif shutil.which("pacman"): pkg_manager = ["pacman", "-S", "--noconfirm"]

    system_and_python_deps_list = ["Go", "Python3", "git", "pip3", "pipx", "tor", "proxychains4", "SecLists", "nmap"] + [f"Python-pkg: {p}" for p in PYTHON_PKGS]
    recon_tools_list = list(GO_TOOLS_TO_INSTALL.keys()) + ["dirsearch", "ParamSpider", "wafw00f", "LinkFinder"]

    dependencies = {}

    go_ok, gobin_path = check_go_installation()
    python_ok = check_python_installation()
    dependencies["Go"], dependencies["Python3"] = go_ok, python_ok

    all_tools_to_check = recon_tools_list + ["git", "pip3", "pipx", "tor", "proxychains4", "SecLists", "nmap"] + [f"Python-pkg: {p}" for p in PYTHON_PKGS]

    for tool in all_tools_to_check:
        if tool.startswith("Python-pkg:"):
            pkg_name = tool.split(": ")[1]
            status, _ = run_command(["pip3", "show", pkg_name], f"Sprawdzanie {pkg_name}", capture_output=True, check_return_code=False)
            dependencies[tool] = status
        elif tool == "SecLists": dependencies[tool] = os.path.isdir("/usr/share/seclists")
        elif tool == "LinkFinder": dependencies[tool] = os.path.exists("/opt/LinkFinder/linkfinder.py")
        elif tool == "dirsearch": dependencies[tool] = shutil.which("dirsearch") is not None
        elif tool == "wafw00f":
            status, _ = run_command(["pip3", "show", "wafw00f"], "Sprawdzanie wafw00f", capture_output=True, check_return_code=False)
            dependencies[tool] = status
        elif tool == "ParamSpider":
            status, out = run_command(["pipx", "list"], "Sprawdzanie ParamSpider", capture_output=True, check_return_code=False)
            dependencies[tool] = status and "paramspider" in out
        elif tool not in ["Go", "Python3"]:
            dependencies[tool] = shutil.which(tool) is not None

    # --- Display tables ---
    table_system = Table(title="Zależności Systemowe i Pythonowe", title_style="bold blue", box=box.MINIMAL, show_header=True)
    table_system.add_column("Narzędzie", style="blue", no_wrap=True)
    table_system.add_column("Status", justify="center")

    for tool_name in system_and_python_deps_list:
        status_ok = dependencies.get(tool_name, False)
        table_system.add_row(tool_name, "[green]✓[/green]" if status_ok else "[red]✗[/red]")

    table_recon = Table(title="Narzędzia Rekonesansu", title_style="bold blue", box=box.MINIMAL, show_header=True)
    table_recon.add_column("Narzędzie", style="blue", no_wrap=True)
    table_recon.add_column("Status", justify="center")

    for tool_name in recon_tools_list:
        status_ok = dependencies.get(tool_name, False)
        table_recon.add_row(tool_name, "[green]✓[/green]" if status_ok else "[red]✗[/red]")

    console.print(Columns([table_system, table_recon], equal=True, expand=True))

    missing_deps = [dep for dep, installed in dependencies.items() if not installed]

    if not missing_deps:
        console.print("\n[green]Wszystkie zależności są spełnione.[/green]")
    else:
        console.print(f"\n[yellow]Brakujące zależności:[/yellow] {', '.join(missing_deps)}")
        if NONINTERACTIVE or ASSUME_YES or questionary.confirm("Zainstalować brakujące zależności?").ask():
            system_packages_to_install = []
            if "git" in missing_deps: system_packages_to_install.append("git")
            if "Go" in missing_deps: system_packages_to_install.append("golang-go" if "apt-get" in pkg_manager else "go")
            if "Python3" in missing_deps or "pip3" in missing_deps: system_packages_to_install.extend(["python3", "python3-pip"])
            if "tor" in missing_deps: system_packages_to_install.append("tor")
            if "proxychains4" in missing_deps: system_packages_to_install.append("proxychains-ng")
            if "SecLists" in missing_deps: system_packages_to_install.append("seclists")
            if "nmap" in missing_deps: system_packages_to_install.append("nmap")

            if system_packages_to_install and pkg_manager:
                install_with_pkg_manager(system_packages_to_install, pkg_manager, is_root, "pakiety systemowe")

            missing_python_pkgs = [p.split(": ")[1] for p in system_and_python_deps_list if p in missing_deps and p.startswith("Python-pkg:")]
            if missing_python_pkgs: install_python_deps(missing_python_pkgs)
            if "wafw00f" in missing_deps: run_command(["pip3", "install", "wafw00f"], "Instalacja wafw00f", live_output=True)

            if "pipx" in missing_deps:
                run_command(["pip3", "install", "pipx"], "Instalacja pipx", live_output=True)
                run_command([os.path.expanduser("~/.local/bin/pipx"), "ensurepath"], "Konfiguracja ścieżki pipx")

            if "ParamSpider" in missing_deps: run_command(["pipx", "install", "--force", "git+https://github.com/devanshbatham/ParamSpider.git"], "Instalacja ParamSpider", live_output=True)
            if "LinkFinder" in missing_deps: install_from_git("https://github.com/GerbenJavado/LinkFinder.git", "/opt/LinkFinder", is_root, "linkfinder.py")
            if "dirsearch" in missing_deps:
                install_from_git("https://github.com/maurosoria/dirsearch.git", "/opt/dirsearch", is_root)
                run_command(["ln", "-sf", "/opt/dirsearch/dirsearch.py", f"{BIN_DIR}/dirsearch"], "Tworzenie symlinka dla dirsearch", sudo=not is_root)

            missing_go_tools = [tool for tool in GO_TOOLS_TO_INSTALL if tool in missing_deps]
            if missing_go_tools and gobin_path:
                install_go_tools(missing_go_tools, gobin_path)

    console.print(f"\n[blue]Kopiowanie plików ShadowMap do {BIN_DIR} i {SHARE_DIR}...[/blue]")
    run_command(["mkdir", "-p", BIN_DIR], f"Tworzenie {BIN_DIR}", sudo=not is_root)
    run_command(["mkdir", "-p", SHARE_DIR], f"Tworzenie {SHARE_DIR}", sudo=not is_root)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    files_to_copy = [
        "shadowmap", 
        "phase2_port_scanning.py", 
        "phase3_dirsearch.py", 
        "phase4_webcrawling.py", 
        "report_template.html", 
        "resolvers.txt", 
        "user_agents.txt", 
        "subdomen_wordlist.txt", 
        "dir_wordlist.txt"
    ]
    for f in files_to_copy:
        src = os.path.join(base_dir, f)
        dest_dir = BIN_DIR if f == "shadowmap" else SHARE_DIR
        if os.path.exists(src):
            run_command(["cp", src, os.path.join(dest_dir, f)], f"Kopiowanie {f}", sudo=not is_root)
            if f.endswith(".py") or f == "shadowmap":
                run_command(["chmod", "+x", os.path.join(dest_dir, f)], f"Nadawanie uprawnień {f}", sudo=not is_root)

    console.print("[green]Instalacja ShadowMap zakończona pomyślnie![/green]")
    console.print("[yellow]Może być konieczne ponowne uruchomienie terminala, aby zmiany w PATH weszły w życie.[/yellow]")
    console.print("[yellow]Upewnij się, że ścieżka GOPATH/bin (zazwyczaj ~/go/bin) jest dodana do Twojej zmiennej środowiskowej PATH.[/yellow]")


if __name__ == "__main__":
    if "-h" in sys.argv or "--help" in sys.argv:
        console.print("Użycie: install.py [-y] [-d] [-n]")
        console.print("  -y, --yes: Automatycznie akceptuj instalację")
        console.print("  -d, --dry-run: Pokaż, co zostanie zrobione, bez wykonywania zmian")
        console.print("  -n, --non-interactive: Tryb nieinteraktywny")
        sys.exit(0)
    main()