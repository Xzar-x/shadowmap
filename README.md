# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

ShadowMap is a comprehensive automated reconnaissance toolkit written in Python, designed for security professionals and penetration testers. It orchestrates multiple phases of web application reconnaissance including subdomain discovery, directory searching, and web crawling.

## Development Commands

### Installation and Setup
```bash
# Install ShadowMap and all dependencies
sudo python3 install.py

# Install with automatic yes to all prompts
sudo python3 install.py -y

# Dry run to see what would be installed
python3 install.py -d

# Check dependencies without installing
python3 install.py -n
```

### Running ShadowMap
```bash
# Basic scan of a domain
shadowmap example.com

# Quiet mode (non-interactive)
shadowmap example.com -q

# Phase 2 only (directory searching)
shadowmap example.com --phase2-only

# Custom output directory
shadowmap example.com -o /path/to/output

# With logging
shadowmap example.com -l /path/to/logfile.log

# Auto-accept all prompts
shadowmap example.com -y
```

### Testing Individual Phases
```bash
# Test Phase 2 directory searching module directly
python3 phase2_dirsearch.py --urls http://example.com --report-dir ./test_output

# Test Phase 3 web crawling module directly  
python3 phase3_crawling.py --urls http://example.com --report-dir ./test_output
```

## Architecture Overview

### Core Components

**Main Entry Point (`shadowmap.py`)**
- Interactive menu system using Rich library for UI
- Orchestrates all phases of reconnaissance
- Manages global settings and configurations
- Handles target validation (IP vs domain detection)
- WAF detection and safe mode activation

**Phase 1 - Subdomain Discovery**
- Uses multiple tools: Subfinder, Assetfinder, Findomain, Puredns
- Results are validated with HTTPX to find active subdomains
- Implements threading for parallel execution
- Safe mode includes rate limiting and header rotation

**Phase 2 - Directory Searching (`phase2_dirsearch.py`)**
- Standalone module supporting Ffuf, Feroxbuster, Dirsearch, Gobuster
- Advanced result parsing with tool-specific regex patterns
- WAF evasion techniques in safe mode (header rotation, delays)
- Supports recursive scanning with configurable depth

**Phase 3 - Web Crawling (`phase3_crawling.py` / `Phase3_webcrawling.py`)**
- Utilizes Katana, Hakrawler, LinkFinder, ParamSpider
- Categorizes discovered URLs (APIs, JS files, parameters)
- Safe mode includes rate limiting and user agent rotation

### Key Design Patterns

**Modular Architecture**: Each phase is a separate module that can be run independently or integrated into the main workflow.

**Threading**: Uses ThreadPoolExecutor for parallel tool execution within each phase.

**Safe Mode**: Comprehensive WAF evasion including:
- Rate limiting and delays
- User agent rotation from file
- Additional browser-like headers
- Smaller wordlists
- Request method randomization

**Interactive UI**: Rich-based TUI with:
- Nested menu navigation
- Real-time progress bars
- Color-coded status indicators
- Single-key input handling

### Configuration System

**Global Settings**: Managed through interactive menus or command line arguments:
- Wordlist paths (separate for each phase)
- Thread counts and timeouts
- Safe mode toggles
- Custom headers and user agents
- Tool selection per phase

**File Locations**:
- Main executable: `/usr/local/bin/shadowmap`
- Shared resources: `/usr/local/share/shadowmap/`
- Wordlists: Uses SecLists by default with fallback to bundled lists
- Templates: HTML report generation from template file

## Development Guidelines

### Code Style
- Uses Rich library for all console output and UI
- Error handling with try/catch blocks and proper logging
- Type hints throughout the codebase
- Global variables for configuration state management

### Adding New Tools
1. Add tool configuration to appropriate phase module
2. Update tool detection in `check_dependencies()`
3. Add parsing logic for tool-specific output format
4. Update installation script if tool requires special installation

### Safe Mode Implementation
When adding new tools, ensure safe mode support includes:
- Rate limiting or delays
- Custom headers support
- Reduced thread counts
- Smaller wordlists where applicable

### Testing
- Test individual phases with sample targets
- Verify tool output parsing with edge cases
- Test safe mode functionality against WAF-protected targets
- Validate HTML report generation

### File Management
- Temporary files are tracked in `TEMP_FILES_TO_CLEAN`
- Results are organized in timestamped directories
- HTML reports use template-based generation
- Log files support multiple verbosity levels

## Dependencies

### System Requirements
- Go (for tool installation)
- Python 3.7+
- Git
- pip3/pipx

### Python Packages
- rich (UI framework)
- typer (CLI framework)
- questionary (interactive prompts)
- pyfiglet (ASCII banners)

### Security Tools
**Phase 1**: subfinder, assetfinder, findomain, puredns, httpx, wafw00f
**Phase 2**: ffuf, feroxbuster, dirsearch, gobuster  
**Phase 3**: katana, hakrawler, linkfinder, paramspider

### Wordlists
- SecLists (preferred, from package manager)
- Bundled fallback wordlists for subdomain and directory discovery

## Common Issues

- **Tool not found errors**: Ensure all tools are in PATH and properly installed
- **Permission errors**: Install script requires sudo for system-wide installation
- **Wordlist not found**: Verify SecLists installation or customize wordlist paths
- **Timeout issues**: Adjust tool timeout values in settings for slow targets
- **WAF blocking**: Enable safe mode for rate limiting and evasion techniques

## Safe Mode Recommendations

Safe mode should be used when:
- Target is protected by WAF/DDoS protection
- Performing authorized testing on production systems
- Rate limiting is required by engagement rules
- Stealth reconnaissance is needed

Safe mode automatically:
- Reduces thread counts and request rates
- Rotates user agents and headers
- Uses smaller wordlists to reduce noise
- Adds random delays between requests
