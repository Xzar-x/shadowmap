<div align="center">
<img src="https://raw.githubusercontent.com/Xzar-x/images/refs/heads/main/shadowmap.png" alt="ShadowMap Banner" width="700"/>
</div>
<h1 align="center">ShadowMap</h1>
<p align="center">
<strong>An automated and interactive reconnaissance toolkit.</strong>
</p>
<p align="center">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Python-3.9%2B-blue.svg" alt="Python Version">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/License-MIT-green.svg" alt="License">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Status-Active-brightgreen.svg" alt="Status">
</p>
ShadowMap is an advanced reconnaissance tool that orchestrates and automates the workflow of numerous popular security tools. It was designed to simplify and accelerate the process of gathering information about a target, from initial OSINT and subdomain scanning to in-depth web application crawling. All findings are aggregated and presented in a clean, interactive HTML report.
🚀 Key Features
 * 🧩 Phased Scanning: The reconnaissance process is divided into logical phases, giving you full control over the scope and depth of the scan.
 * 🖥️ Interactive CLI Menu: Manage the entire scanning process through an intuitive terminal menu, built with the rich library.
 * 🛡️ WAF Detection & Safe Mode: The tool automatically detects Web Application Firewalls (WAFs) and suggests a "Safe Mode," which slows down the scan and applies evasion techniques.
 * 🔗 Tool Integration: ShadowMap integrates over a dozen popular tools, such as Nmap, Subfinder, Httpx, Ffuf, Katana, and many more.
 * 📊 Dynamic HTML Reports: Results from each phase are collected and presented in a single, well-designed, and interactive HTML report that simplifies data analysis.
 * ⚙️ High Configurability: Customize numerous scan parameters, including wordlists, recursion depth, timeouts, and proxy usage.
🗺️ Scan Structure
ShadowMap divides the reconnaissance process into five main phases, which can be run sequentially or individually.
| Phase | Description | Tools Used |
|---|---|---|
| Phase 0: OSINT | Gathers basic information about the target (WHOIS, IP, ASN, web technologies). | whois, httpx, whatweb, webtech |
| Phase 1: Subdomains | Discovers and verifies the target's active subdomains. | subfinder, assetfinder, findomain, puredns, httpx |
| Phase 2: Ports | Scans discovered hosts for open ports and services. | naabu, masscan, nmap |
| Phase 3: Directories | Fuzzes web servers to find hidden files and directories. | ffuf, feroxbuster, dirsearch, gobuster |
| Phase 4: Web Crawling | Performs deep crawling of web applications to find links, parameters, and API endpoints. | katana, hakrawler, paramspider, linkfinder, gauplus |
🛠️ Installation
The installation process is automated with the install.py script. The script will check for and install missing system dependencies and Go tools, then copy the ShadowMap files to the appropriate system directories.
 * Clone the repository:
   git clone [https://github.com/your-username/ShadowMap.git](https://github.com/your-username/ShadowMap.git)
cd ShadowMap

 * Run the installation script:
   > Note: The script requires sudo privileges to install packages and copy files.
   > 
   sudo python3 install.py

   The script will install all required apt and pip packages, as well as the Go-based tools.
 * Run ShadowMap:
   After a successful installation, the tool will be available globally.
   shadowmap <target>

⚙️ Usage
The tool can be run in interactive mode by providing a target as an argument, or in a fully automated mode for multiple targets.
Basic Interactive Scan
shadowmap example.com

This will launch the interactive menu, which will guide you through the scanning phases.
<div align="center">
<img src="https://www.google.com/search?q=https://raw.githubusercontent.com/Xzar-x/images/main/shadowmap_menu.gif" alt="ShadowMap Demo" width="800"/>
</div>
Command-Line Options
Usage: shadowmap [OPTIONS] [TARGET]

  ShadowMap: An automated reconnaissance toolkit.

Arguments:
  [TARGET]   The domain or IP address to scan.

Options:
  --target-list, -l FILE   File containing a list of targets.
  --output-dir, -o PATH    Directory to save reports in.
  --exclude, -e TEXT       Exclude subdomains (e.g., -e *.dev.example.com).
  --safe-mode              Enable Safe Mode (slower, less aggressive scanning).
  --proxy TEXT             Use a proxy (e.g., socks5://127.0.0.1:9050).
  --quiet, -q              Quiet mode, minimizes output.
  --help, -h               Show this message and exit.

Example: Scanning from a file and saving to a directory
shadowmap -l targets.txt -o /path/to/reports/

📊 HTML Report
After the scan is complete (or when you exit the menu), ShadowMap generates a detailed HTML report.
<div align="center">
<img src="https://www.google.com/search?q=https://raw.githubusercontent.com/Xzar-x/images/main/shadowmap_report.png" alt="HTML Report Example" width="800"/>
</div>
The report includes:
 * A summary with key statistics.
 * Detailed OSINT data, including WHOIS info and detected technologies.
 * Lists of active subdomains with their status codes.
 * Port scanning results from Nmap.
 * Raw output from every tool used, organized in separate tabs.
🤝 Contributing
Want to help improve ShadowMap? We are open to all suggestions, bug reports, and pull requests.
 * Fork the repository.
 * Create a new branch (git checkout -b feature/your-feature).
 * Make your changes.
 * Commit your changes (git commit -m 'Add a new feature').
 * Push to the branch (git push origin feature/your-feature).
 * Open a Pull Request.
📄 License
This project is licensed under the MIT License. See the LICENSE file for more details.
