<p align="center">
  <img src="https://raw.githubusercontent.com/Xzar-x/images/main/shadowmap.png" alt="ShadowMap Banner" width="700"/>
</p>

<h1 align="center">ShadowMap</h1>
<p align="center">
  <b>Automated Reconnaissance Toolkit</b><br>
  ShadowMap is an advanced automated reconnaissance framework that performs comprehensive target scanning through five integrated phases — from passive OSINT to deep web crawling.
</p>

---

## 📖 Table of Contents
- [🎯 About the Project](#-about-the-project)
- [✨ Key Features](#-key-features)
- [🛠️ Tools Used](#️-tools-used)
- [🚀 Getting Started](#-getting-started)
- [💻 Usage](#-usage)
- [📊 Scanning Phases](#-scanning-phases)
- [📄 Reports](#-reports)
- [📁 Project Structure](#-project-structure)
- [🤝 Contribution](#-contribution)
- [📄 License](#-license)
- [👤 Author](#-author)

---

## 🎯 About the Project
ShadowMap was built to automate and integrate time-consuming reconnaissance processes.  
It combines the power of dozens of leading open-source tools into one cohesive pipeline.  
Instead of manually running and aggregating results from multiple scripts, ShadowMap orchestrates the entire process, intelligently adjusts scanning, and generates a clear, interactive HTML report.

---

## ✨ Key Features
- 🔍 **Multi-Phase Reconnaissance:** 5 integrated phases (OSINT, Subdomains, Ports, Directories, Web Crawling)
- 🤖 **Full Automation:** `-y (--yes)` mode to run all phases without interaction
- 🛡️ **Detection & Adaptation:** Automatic WAF detection and Safe Mode scanning
- 📊 **Interactive Reports:** Modern HTML reports with dynamic filtering and visualization
- 💥 **Searchsploit Integration:** Automatically finds and evaluates public exploits for detected technologies
- 🧠 **Smart Scanning:** Dynamically selects wordlists based on detected technologies (e.g., WordPress, Joomla)
- ⚡ **Parallel Execution:** Multithreaded scanning for maximum performance
- 🎨 **Intuitive Interface:** Colorful and interactive terminal UI built with `rich`
- ⚙️ **Highly Configurable:** Advanced configuration options for each scanning phase
- 📤 **Dual Report Format:** Generates both human-readable HTML and machine-readable JSON outputs

---

## 🛠️ Tools Used

| Category | Tools |
|-----------|--------|
| **OSINT** | whois, httpx, whatweb, wafw00f, searchsploit |
| **Subdomains** | subfinder, assetfinder, findomain, puredns |
| **Port Scanning** | nmap, naabu, masscan |
| **Directories & Files** | ffuf, feroxbuster, dirsearch, gobuster |
| **Web Crawling** | katana, hakrawler, paramspider, linkfinder, gauplus |

---

## 🚀 Getting Started

### Requirements
- System: Linux (Debian/Ubuntu recommended) or macOS  
- Python 3.8+  
- Go 1.19+

### Installation
```bash
git clone https://github.com/Xzar-x/shadowmap.git
cd shadowmap
sudo ./install.py
```

The installation script will automatically:
- ✅ Check and install system dependencies
- 🐹 Install Go-based tools
- 🐍 Install Python tools and libraries
- 📁 Copy files to `/usr/local/share/shadowmap/`

Verify installation:
```bash
shadowmap --help
```

---

## 💻 Usage

### Basic Commands
```bash
# Interactive scan of a single target
shadowmap example.com

# Scan from a list of targets
shadowmap -l targets.txt

# Save report to a specific directory
shadowmap -o /scans/reports/ example.com

# Enable safe mode (slower but stealthier)
shadowmap --safe-mode example.com

# Use SOCKS5 proxy (e.g., Tor)
shadowmap --proxy socks5://127.0.0.1:9050 example.com
```

### Automated Mode
```bash
# Fully automated scanning
shadowmap -y example.com

# Scan multiple targets and save all reports
shadowmap -y -l targets.txt -o reports/
```

---

## 📊 Scanning Phases

| Phase | Description |
|-------|--------------|
| 🎯 **Phase 0: OSINT** | WHOIS data collection, IP/ASN/CDN analysis, technology detection, and public exploit search (searchsploit). |
| 🔍 **Phase 1: Subdomains** | Enumerates subdomains using subfinder, assetfinder, findomain, and puredns. |
| 🚪 **Phase 2: Port Scanning** | Fast port discovery via naabu and masscan, followed by detailed service and vulnerability scanning with nmap. |
| 📁 **Phase 3: Directory Discovery** | Bruteforces directories and files using ffuf, feroxbuster, dirsearch, and gobuster, with wildcard filtering and validation. |
| 🕸️ **Phase 4: Web Crawling** | Deep web crawling via katana, hakrawler, paramspider, linkfinder, and gauplus. |

---

## 📄 Reports

ShadowMap generates two types of reports:
- **HTML:** Interactive report with tabs, filtering, categories, and visual summaries.
- **JSON:** Structured output suitable for automation and data integration.

---

## 📁 Project Structure
```
/usr/local/share/shadowmap/
├── shadowmap.py
├── config.py
├── utils.py
├── phase0_osint.py
├── phase1_subdomain.py
├── phase2_port_scanning.py
├── phase3_dirsearch.py
├── phase4_webcrawling.py
├── report_template.html
├── resolvers.txt
├── user_agents.txt
└── install.py
```

---

## 🤝 Contribution
1. 🍴 Fork the repository  
2. 🌿 Create a new branch  
3. 💾 Commit your changes  
4. 📤 Push to your branch  
5. 🔄 Open a Pull Request  

Found a bug or have suggestions? Open an issue in the **Issues** section.

---

## 📄 License
This project is distributed under the **MIT License**.  
See the `LICENSE` file for details.

---

## 👤 Author
**Xzar**  
[GitHub](https://github.com/Xzar-x)

<p align="center">
  <b>ShadowMap - Your Automated Reconnaissance Companion 🗺️</b>
</p>
