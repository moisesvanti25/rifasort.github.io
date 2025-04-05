#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import requests
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin
from colorama import init, Fore, Style, Back
import shutil
import re
import threading

# Configuração inicial
init(autoreset=True)
os.system("clear")

# Constantes
VERSION = "ULTRA-SCAN-2.0"
HOME = os.path.expanduser("~")
TOOLS_DIR = f"{HOME}/.termux_tools"
WORDLISTS_DIR = f"{HOME}/.termux_wordlists"
REPORT_DIR = f"{HOME}/termux_reports"
CACHE_DIR = f"{HOME}/.termux_cache"
THREADS = 3
TIMEOUT = 30
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Cores e estilos avançados
class TermuxColors:
    BANNER = Fore.LIGHTCYAN_EX + Style.BRIGHT
    CRITICAL = Back.RED + Fore.WHITE + Style.BRIGHT
    HIGH = Fore.RED + Style.BRIGHT
    MEDIUM = Fore.YELLOW + Style.BRIGHT
    LOW = Fore.LIGHTYELLOW_EX
    INFO = Fore.CYAN + Style.BRIGHT
    SUCCESS = Fore.GREEN + Style.BRIGHT
    DEBUG = Fore.LIGHTBLACK_EX
    PROGRESS = Fore.LIGHTMAGENTA_EX + Style.BRIGHT
    WARNING = Fore.LIGHTRED_EX + Style.BRIGHT
    XSS = Fore.LIGHTGREEN_EX + Style.BRIGHT
    SQL = Fore.LIGHTBLUE_EX + Style.BRIGHT
    NUCLEI = Fore.LIGHTYELLOW_EX + Style.BRIGHT

# Animação de spinner
def spinning_cursor():
    while True:
        for cursor in '⣾⣽⣻⢿⡿⣟⣯⣷':
            yield cursor

spinner = spinning_cursor()

# Banner estilizado
def print_banner():
    banner = f"""
{TermuxColors.BANNER}
▓█████ ▄▄▄       ███▄    █   ██████  ▄████▄   █    ██ 
▓█   ▀▒████▄     ██ ▀█   █ ▒██    ▒ ▒██▀ ▀█   ██  ▓██▒
▒███  ▒██  ▀█▄  ▓██  ▀█ ██▒░ ▓██▄   ▒▓█    ▄ ▓██  ▒██░
▒▓█  ▄░██▄▄▄▄██ ▓██▒  ▐▌██▒  ▒   ██▒▒▓▓▄ ▄██▒▓▓█  ░██░
░▒████▒▓█   ▓██▒▒██░   ▓██░▒██████▒▒▒ ▓███▀ ░▒▒█████▓ 
░░ ▒░ ░▒▒   ▓▒█░░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░░▒▓▒ ▒ ▒ 
 ░ ░  ░ ▒   ▒▒ ░░ ░░   ░ ▒░░ ░▒  ░ ░  ░  ▒   ░░▒░ ░ ░ 
   ░    ░   ▒      ░   ░ ░ ░  ░  ░  ░         ░░░ ░ ░ 
   ░  ░     ░  ░         ░       ░  ░ ░         ░     
                                  ░                   
{Style.RESET_ALL}
{TermuxColors.XSS}╔═╗╔═╗╔═╗   {TermuxColors.SQL}╔═╗ ╔═╗╦  ╔═╗╦═╗╦ ╦╔═╗   {TermuxColors.NUCLEI}╔╗ ╔╦╗╔═╗╦═╗╔═╗
{TermuxColors.XSS}╚═╗║╣ ╠═╝   {TermuxColors.SQL}╠═╝ ║ ║║  ║╣ ╠╦╝║ ║╚═╗   {TermuxColors.NUCLEI}╠╩╗ ║ ╠═╣╠╦╝║╣ 
{TermuxColors.XSS}╚═╝╚═╝╩     {TermuxColors.SQL}╩  ╚═╝╩═╝╚═╝╩╚═╚═╝╚═╝   {TermuxColors.NUCLEI}╚═╝ ╩ ╩ ╩╩╚═╚═╝
{Style.RESET_ALL}
{TermuxColors.INFO}{'═'*90}
   Termux Ultimate Security Scanner {VERSION} | Dalfox + SQLMap + Nuclei Integration
{'═'*90}{Style.RESET_ALL}
"""
    print(banner)

# Sistema de logs melhorado
class Logger:
    @staticmethod
    def status(msg, tool=None):
        prefix = f"{TermuxColors.PROGRESS}[{next(spinner)}]" 
        if tool:
            prefix += f" {tool}:"
        sys.stdout.write(f"\r{prefix} {msg.ljust(80)}")
        sys.stdout.flush()
    
    @staticmethod
    def critical(msg):
        print(f"\n{TermuxColors.CRITICAL}[!] {msg}{Style.RESET_ALL}")
    
    @staticmethod
    def high(msg):
        print(f"\n{TermuxColors.HIGH}[!] {msg}{Style.RESET_ALL}")
    
    @staticmethod
    def medium(msg):
        print(f"\n{TermuxColors.MEDIUM}[*] {msg}{Style.RESET_ALL}")
    
    @staticmethod
    def low(msg):
        print(f"\n{TermuxColors.LOW}[*] {msg}{Style.RESET_ALL}")
    
    @staticmethod
    def info(msg):
        print(f"\n{TermuxColors.INFO}[>] {msg}{Style.RESET_ALL}")
    
    @staticmethod
    def success(msg):
        print(f"\n{TermuxColors.SUCCESS}[✓] {msg}{Style.RESET_ALL}")
    
    @staticmethod
    def warning(msg):
        print(f"\n{TermuxColors.WARNING}[!] {msg}{Style.RESET_ALL}")
    
    @staticmethod
    def xss(msg):
        print(f"\n{TermuxColors.XSS}[XSS] {msg}{Style.RESET_ALL}")
    
    @staticmethod
    def sql(msg):
        print(f"\n{TermuxColors.SQL}[SQLi] {msg}{Style.RESET_ALL}")
    
    @staticmethod
    def nuclei(msg):
        print(f"\n{TermuxColors.NUCLEI}[NUCLEI] {msg}{Style.RESET_ALL}")

# Gerenciador de instalação
class TermuxManager:
    @staticmethod
    def check_installed(tool):
        locations = [
            f"{TOOLS_DIR}/{tool}",
            f"{HOME}/go/bin/{tool}",
            f"/data/data/com.termux/files/usr/bin/{tool}",
            f"{HOME}/.local/bin/{tool}"
        ]
        return any(os.path.exists(loc) for loc in locations)

    @staticmethod
    def setup_environment():
        Logger.info("Configuring advanced security environment...")
        
        try:
            # Criar diretórios
            os.makedirs(TOOLS_DIR, exist_ok=True)
            os.makedirs(WORDLISTS_DIR, exist_ok=True)
            os.makedirs(REPORT_DIR, exist_ok=True)
            os.makedirs(CACHE_DIR, exist_ok=True)

            # Atualizar pacotes
            Logger.status("Updating packages...")
            subprocess.run("pkg update -y && pkg upgrade -y", 
                         shell=True, 
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)

            # Instalar dependências
            Logger.status("Installing core dependencies...")
            deps = [
                "git", "python", "python-pip", "nmap", "curl", "wget", "ruby",
                "golang", "openssl", "dnsutils", "libxml2", "libxslt", "unzip",
                "make", "cmake", "clang", "binutils"
            ]
            subprocess.run(f"pkg install -y {' '.join(deps)}", 
                         shell=True,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)

            # Instalar pacotes Python
            Logger.status("Installing Python packages...")
            pip_deps = [
                "requests", "bs4", "lxml", "colorama", "urllib3",
                "cryptography", "pyOpenSSL", "dnspython"
            ]
            subprocess.run(f"pip install --upgrade {' '.join(pip_deps)}", 
                         shell=True,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)

            # Configurar PATH
            os.environ["PATH"] += f":{HOME}/go/bin:{TOOLS_DIR}:{HOME}/.local/bin"
            
            Logger.success("Environment configured successfully!")
            return True
        except Exception as e:
            Logger.critical(f"Environment setup failed: {str(e)}")
            return False

    @staticmethod
    def install_tools():
        # Ferramentas Go
        go_tools = [
            ("dalfox", "github.com/hahwul/dalfox/v2", "latest"),
            ("nuclei", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei", "latest")
        ]
        
        # Ferramentas Python
        py_tools = [
            ("sqlmap", "https://github.com/sqlmapproject/sqlmap.git")
        ]
        
        # Instalar ferramentas Go
        Logger.info("Installing Go tools...")
        for tool, pkg, version in go_tools:
            if not TermuxManager.install_go_tool(tool, pkg, version):
                Logger.critical(f"Failed to install {tool}!")
                return False
        
        # Instalar ferramentas Python
        Logger.info("Installing Python tools...")
        for tool, repo in py_tools:
            if not TermuxManager.install_python_tool(tool, repo):
                Logger.critical(f"Failed to install {tool}!")
                return False
        
        # Atualizar templates do Nuclei
        Logger.status("Updating Nuclei templates...", "Nuclei")
        subprocess.run("nuclei -update-templates", 
                     shell=True,
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.PIPE)
        
        Logger.success("All tools installed successfully!")
        return True

    @staticmethod
    def install_go_tool(tool, pkg, version=None):
        if TermuxManager.check_installed(tool):
            return True
            
        Logger.status(f"Installing {tool}...", "GO")
        try:
            install_cmd = f"go install {pkg}"
            if version:
                install_cmd += f"@{version}"
            
            result = subprocess.run(
                install_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                Logger.success(f"{tool} installed successfully!")
                return True
            
            # Fallback para compilação manual
            Logger.warning(f"Standard install failed, building from source...")
            os.chdir(TOOLS_DIR)
            subprocess.run(f"git clone https://github.com/{pkg.split('@')[0]}", 
                         shell=True,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE)
            
            tool_dir = pkg.split('/')[-1]
            os.chdir(f"{TOOLS_DIR}/{tool_dir}")
            
            if version:
                subprocess.run(f"git checkout tags/{version}", 
                             shell=True,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE)
            
            subprocess.run("go build", 
                         shell=True,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE)
            
            shutil.move(tool, f"{HOME}/go/bin")
            os.chdir(HOME)
            
            Logger.success(f"{tool} built successfully!")
            return True
            
        except Exception as e:
            Logger.debug(f"Go install error: {str(e)}")
            return False

    @staticmethod
    def install_python_tool(tool, repo):
        tool_path = f"{TOOLS_DIR}/{tool}"
        
        if os.path.exists(tool_path):
            shutil.rmtree(tool_path, ignore_errors=True)
                
        Logger.status(f"Installing {tool}...", "Python")
        try:
            subprocess.run(f"git clone --depth 1 {repo} {tool_path}", 
                         shell=True,
                         cwd=TOOLS_DIR,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         text=True)
            
            if tool == "sqlmap":
                os.symlink(f"{tool_path}/sqlmap.py", f"{TOOLS_DIR}/sqlmap")
            
            Logger.success(f"{tool} installed successfully!")
            return True
        except Exception as e:
            Logger.debug(f"Python tool install error: {str(e)}")
            return False

    @staticmethod
    def download_wordlists():
        wordlists = {
            "xss-payloads.txt": "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt",
            "sqli-payloads.txt": "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/sql-injection-payload-list.txt"
        }
        
        Logger.info("Downloading advanced payloads...")
        for name, url in wordlists.items():
            dest = f"{WORDLISTS_DIR}/{name}"
            if os.path.exists(dest):
                continue
                
            try:
                Logger.status(f"Downloading {name}...", "Payloads")
                response = requests.get(url, stream=True, timeout=60)
                with open(dest, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
            except Exception as e:
                Logger.debug(f"Failed to download {name}: {str(e)}")

# Scanner avançado
class AdvancedScanner:
    def __init__(self, target):
        self.target = self.normalize_target(target)
        self.domain = urlparse(self.target).netloc
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        })
        self.report_data = {
            "target": self.target,
            "metadata": {
                "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scanner_version": VERSION,
                "host_info": platform.uname()._asdict()
            },
            "results": {
                "xss_vulnerabilities": [],
                "sqli_vulnerabilities": [],
                "nuclei_findings": [],
                "information": []
            }
        }
        self.lock = threading.Lock()

    def normalize_target(self, target):
        if not target.startswith(("http://", "https://")):
            return f"http://{target}"
        return target

    def save_report(self):
        report_file = f"{REPORT_DIR}/full_scan_{self.domain}_{int(time.time())}.json"
        try:
            with self.lock:
                with open(report_file, "w") as f:
                    json.dump(self.report_data, f, indent=4, ensure_ascii=False)
                Logger.success(f"Report saved to: {report_file}")
                return report_file
        except Exception as e:
            Logger.critical(f"Failed to save report: {str(e)}")
            return None

    def run_dalfox_scan(self):
        """Executa varredura avançada de XSS com Dalfox"""
        Logger.status("Starting advanced XSS scan...", "Dalfox")
        
        report_file = f"{REPORT_DIR}/dalfox_{self.domain}.json"
        
        cmd = (
            f"dalfox url {self.target} "
            f"--custom-payload {WORDLISTS_DIR}/xss-payloads.txt "
            f"--user-agent '{USER_AGENT}' "
            f"--timeout {TIMEOUT} "
            f"--worker {THREADS} "
            f"--format json --output {report_file}"
        )
        
        result = self.run_tool(cmd, "Dalfox")
        
        if os.path.exists(report_file):
            with open(report_file) as f:
                try:
                    data = json.load(f)
                    for vuln in data.get("vulnerabilities", []):
                        self.add_xss_vulnerability(
                            vuln.get("type", "XSS"),
                            vuln.get("message", "XSS vulnerability found"),
                            vuln.get("severity", "medium"),
                            {
                                "parameter": vuln.get("param"),
                                "payload": vuln.get("payload"),
                                "evidence": vuln.get("evidence")
                            }
                        )
                except json.JSONDecodeError:
                    Logger.warning("Failed to parse Dalfox JSON output")
            
            os.remove(report_file)
        return result

    def run_sqlmap_scan(self):
        """Executa varredura avançada de SQLi com SQLMap"""
        Logger.status("Starting advanced SQLi scan...", "SQLMap")
        
        report_dir = f"{REPORT_DIR}/sqlmap_{self.domain}"
        os.makedirs(report_dir, exist_ok=True)
        
        cmd = (
            f"python {TOOLS_DIR}/sqlmap/sqlmap.py -u {self.target} "
            f"--level=5 --risk=3 "
            f"--batch "
            f"--output-dir={report_dir} "
            f"--threads={THREADS}"
        )
        
        result = self.run_tool(cmd, "SQLMap")
        
        # Processar resultados do SQLMap
        if os.path.exists(f"{report_dir}/log"):
            with open(f"{report_dir}/log") as f:
                log_content = f.read()
                if "sqlmap identified the following injection point" in log_content:
                    self.add_sqli_vulnerability(
                        "SQL Injection",
                        "SQL injection vulnerability found",
                        "high",
                        {
                            "technique": re.search(r"testing for (.+) on", log_content).group(1) if re.search(r"testing for (.+) on", log_content) else "unknown",
                            "database": re.search(r"back-end DBMS: (.+)", log_content).group(1) if re.search(r"back-end DBMS: (.+)", log_content) else "unknown"
                        }
                    )
        return result

    def run_nuclei_scan(self):
        """Executa varredura com Nuclei"""
        Logger.status("Starting Nuclei vulnerability scan...", "Nuclei")
        
        report_file = f"{REPORT_DIR}/nuclei_{self.domain}.json"
        
        cmd = (
            f"nuclei -u {self.target} "
            f"-severity critical,high,medium "
            f"-timeout {TIMEOUT} "
            f"-c {THREADS} "
            f"-json -o {report_file}"
        )
        
        result = self.run_tool(cmd, "Nuclei")
        
        if os.path.exists(report_file):
            with open(report_file) as f:
                for line in f:
                    try:
                        vuln = json.loads(line)
                        self.add_nuclei_finding(
                            vuln.get("templateID", "unknown"),
                            vuln.get("info", {}).get("name", "Unknown vulnerability"),
                            vuln.get("severity", "medium").lower(),
                            vuln
                        )
                    except json.JSONDecodeError:
                        continue
            
            os.remove(report_file)
        return result

    def add_xss_vulnerability(self, vuln_type, description, severity, details=None):
        entry = {
            "type": vuln_type,
            "description": description,
            "severity": severity,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "details": details if details else {}
        }
        
        with self.lock:
            self.report_data["results"]["xss_vulnerabilities"].append(entry)
        
        Logger.xss(f"{severity.upper()}: {description}")

    def add_sqli_vulnerability(self, vuln_type, description, severity, details=None):
        entry = {
            "type": vuln_type,
            "description": description,
            "severity": severity,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "details": details if details else {}
        }
        
        with self.lock:
            self.report_data["results"]["sqli_vulnerabilities"].append(entry)
        
        Logger.sql(f"{severity.upper()}: {description}")

    def add_nuclei_finding(self, template_id, description, severity, details=None):
        entry = {
            "template_id": template_id,
            "description": description,
            "severity": severity,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "details": details if details else {}
        }
        
        with self.lock:
            self.report_data["results"]["nuclei_findings"].append(entry)
        
        Logger.nuclei(f"{severity.upper()}: {description}")

    def run_tool(self, command, tool_name):
        try:
            Logger.status(f"Running {tool_name}...", tool_name)
            
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                output, error = process.communicate(timeout=TIMEOUT*3)
            except subprocess.TimeoutExpired:
                process.kill()
                Logger.warning(f"{tool_name} timed out")
                return None
            
            if process.returncode != 0:
                Logger.debug(f"{tool_name} error: {error.strip()}")
                return None
            
            return output.splitlines() if output else None
            
        except Exception as e:
            Logger.debug(f"{tool_name} exception: {str(e)}")
            return None
        finally:
            Logger.status(f"Finished {tool_name}...", tool_name)

    def run_full_scan(self):
        start_time = time.time()
        
        try:
            # Executar scanners em paralelo
            with ThreadPoolExecutor(max_workers=3) as executor:
                executor.submit(self.run_dalfox_scan)
                executor.submit(self.run_sqlmap_scan)
                executor.submit(self.run_nuclei_scan)
            
            # Finalizar relatório
            self.report_data["metadata"]["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
            self.report_data["metadata"]["duration"] = f"{round(time.time() - start_time, 2)} seconds"
            
            # Gerar resumo
            xss_count = len(self.report_data["results"]["xss_vulnerabilities"])
            sqli_count = len(self.report_data["results"]["sqli_vulnerabilities"])
            nuclei_count = len(self.report_data["results"]["nuclei_findings"])
            
            print("\n" + "═"*90)
            print(f"{TermuxColors.BANNER} SCAN SUMMARY {Style.RESET_ALL}")
            print("═"*90)
            print(f"Target: {self.target}")
            print(f"Scan duration: {self.report_data['metadata']['duration']}")
            print(f"\n{TermuxColors.XSS}XSS Vulnerabilities: {xss_count}")
            print(f"{TermuxColors.SQL}SQLi Vulnerabilities: {sqli_count}")
            print(f"{TermuxColors.NUCLEI}Nuclei Findings: {nuclei_count}{Style.RESET_ALL}")
            
            # Mostrar vulnerabilidades críticas
            critical_findings = [
                *[v for v in self.report_data["results"]["xss_vulnerabilities"] if v["severity"] in ["critical", "high"]],
                *[v for v in self.report_data["results"]["sqli_vulnerabilities"] if v["severity"] in ["critical", "high"]],
                *[v for v in self.report_data["results"]["nuclei_findings"] if v["severity"] in ["critical", "high"]]
            ][:5]  # Limitar a 5 resultados
            
            if critical_findings:
                print("\nCritical Findings:")
                for finding in critical_findings:
                    if "xss" in finding.get("type", "").lower():
                        color = TermuxColors.XSS
                    elif "sql" in finding.get("type", "").lower():
                        color = TermuxColors.SQL
                    else:
                        color = TermuxColors.NUCLEI
                    
                    print(f"{color}- {finding.get('type', finding.get('template_id', 'Finding'))}: {finding['description'][:100]}...{Style.RESET_ALL}")
            
            print("═"*90)
            
            # Salvar relatório
            report_path = self.save_report()
            return report_path
            
        except Exception as e:
            Logger.critical(f"Scan failed: {str(e)}")
            return None

def main_menu():
    print_banner()
    
    # Configurar ambiente
    if not TermuxManager.setup_environment():
        sys.exit(1)
    
    if not TermuxManager.install_tools():
        sys.exit(1)
    
    TermuxManager.download_wordlists()
    
    while True:
        print(f"\n{TermuxColors.INFO}Main Menu:{Style.RESET_ALL}")
        print(f"1. Scan Single Target")
        print(f"2. Scan Multiple Targets (file)")
        print(f"3. Update Tools")
        print(f"4. Exit")
        
        choice = input(f"\n{TermuxColors.INFO}[?] Select option: {Style.RESET_ALL}").strip()
        
        if choice == "1":
            target = input(f"{TermuxColors.INFO}[?] Enter target URL: {Style.RESET_ALL}").strip()
            if not target:
                continue
                
            scanner = AdvancedScanner(target)
            scanner.run_full_scan()
            
        elif choice == "2":
            file_path = input(f"{TermuxColors.INFO}[?] Enter file with targets: {Style.RESET_ALL}").strip()
            if not os.path.exists(file_path):
                Logger.critical("File not found!")
                continue
                
            with open(file_path) as f:
                targets = [line.strip() for line in f if line.strip()]
            
            for i, target in enumerate(targets, 1):
                Logger.info(f"\nScanning target {i}/{len(targets)}: {target}")
                scanner = AdvancedScanner(target)
                scanner.run_full_scan()
                time.sleep(2)  # Pausa entre scans
                
        elif choice == "3":
            Logger.info("Updating tools...")
            TermuxManager.install_tools()
            
        elif choice == "4":
            Logger.success("Exiting...")
            sys.exit(0)
            
        else:
            Logger.critical("Invalid option!")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        Logger.critical("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        Logger.critical(f"Fatal error: {str(e)}")
        sys.exit(1)