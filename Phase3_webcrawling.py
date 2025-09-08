#!/usr/bin/env python3

import sys
import os
import subprocess
import re
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
import json

# --- Importowanie współdzielonych funkcji ---
try:
    from rich.console import Console
    from rich.progress import Progress, TaskID
    from rich.align import Align
    
    # Importowanie z phase2_dirsearch, aby uniknąć duplikacji kodu
    from phase2_dirsearch import (
        log_and_echo as shared_log_and_echo,
        get_random_user_agent_header,
        safe_sort_unique,
        ansi_escape_pattern
    )
    RICH_AVAILABLE = True
except ImportError:
    # Fallback, jeśli uruchamiany samodzielnie bez rich
    RICH_AVAILABLE = False
    # ... (proste funkcje zastępcze) ...

# --- Globalne zmienne dla tego modułu ---
LOG_FILE: Optional[str] = None
USER_AGENTS_FILE: Optional[str] = None

# --- Główna funkcja wykonawcza dla pojedynczego narzędzia ---
def _execute_crawl_command(tool_name: str, command_parts: List[str], target_url: str, output_file: str, timeout: int, progress_obj: Progress):
    # ... (podobne do _execute_tool_command z fazy 2, ale dostosowane do Fazy 3) ...
    pass

# --- Główna funkcja orkiestrująca Fazę 3 ---
def start_web_crawl(
    urls: List[str],
    report_dir: str,
    safe_mode: bool,
    custom_header: str,
    threads: int,
    tool_timeout: int,
    log_file: Optional[str],
    user_agents_file: Optional[str],
    selected_tools_config: List[int],
    console_obj: Console,
    progress_obj: Optional[Progress],
    main_task_id: Optional[TaskID]
) -> Dict[str, List[str]]:
    
    global LOG_FILE, USER_AGENTS_FILE
    LOG_FILE, USER_AGENTS_FILE = log_file, user_agents_file

    all_tool_results: Dict[str, List[str]] = {
        "all_urls": [], "parameters": [], "js_files": [], "api_endpoints": [], "interesting_files": []
    }

    # Konfiguracja narzędzi Fazy 3
    tool_configs = [
        {"name": "Katana", "enabled": selected_tools_config[0], "base_cmd": ["katana", "-silent", "-jc", "-kf", "all"]},
        {"name": "Hakrawler", "enabled": selected_tools_config[1], "base_cmd": ["hakrawler"]},
        {"name": "LinkFinder", "enabled": selected_tools_config[2], "base_cmd": ["linkfinder", "-i"]}, # Użyjemy go na plikach JS
        {"name": "ParamSpider", "enabled": selected_tools_config[3], "base_cmd": ["paramspider", "-d"]}
    ]
    
    # Dostosowanie do Safe Mode
    if safe_mode:
        for config in tool_configs:
            if config["name"] == "Katana":
                config["base_cmd"].extend(["-rl", "5"]) # Rate limit
            # Hakrawler nie ma rate limit, ale można dodać opóźnienie w pętli
            # ParamSpider również nie ma, polega na archiwach

    # ... (Logika uruchamiania narzędzi w ThreadPoolExecutor, podobnie jak w Fazie 2) ...
    
    # ... (Logika parsowania wyników i kategoryzowania ich) ...
    
    return all_tool_results
