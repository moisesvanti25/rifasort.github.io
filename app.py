#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import requests
import subprocess
import platform
import shutil
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin
from colorama import init, Fore, Style, Back

# Initialize colorama
init(autoreset=True)
os.system("clear" if os.name != 'nt' else "cls")

# Constants
VERSION = "Termux-Pentest-Ultimate-5.0"
HOME = os.path.expanduser("~")
TOOLS_DIR = f"{HOME}/.termux_tools"
WORDLISTS_DIR = f"{HOME}/.termux_wordlists"
REPORT_DIR = f"{HOME}/termux_reports"
CACHE_DIR = f"{HOME}/.termux_cache"
THREADS = 3
TIMEOUT = 30
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Colors and styles
class TermuxColors:
    BANNER = Fore.LIGHTCYAN_EX
    CRITICAL = Back.RED + Fore.WHITE + Style.BRIGHT
    HIGH = Fore.RED + Style.BRIGHT
    MEDIUM = Fore.YELLOW + Style.BRIGHT
    LOW = Fore.LIGHTYELLOW_EX
    INFO = Fore.CYAN + Style.BRIGHT
    SUCCESS = Fore.GREEN + Style.BRIGHT
    DEBUG = Fore.LIGHTBLACK_EX
    PROGRESS = Fore.LIGHTMAGENTA_EX + Style.BRIGHT
    WARNING = Fore.LIGHTRED_EX + Style.BRIGHT

# Spinner animation
def spinning_cursor():
    while True:
        for cursor in '⣾⣽⣻⢿⡿⣟⣯⣷':
            yield cursor

spinner = spinning_cursor()

# Banner
def print_banner():
    banner = f"""
{TermuxColors.BANNER}
▓█████▄  ▒█████   ██▀███   ██▓ ███▄    █  ▄▄▄     ▄▄▄█████▓
▒██▀ ██▌▒██▒  ██▒▓██ ▒ ██▒▓██▒ ██ ▀█   █ ▒████▄   ▓  ██▒ ▓▒
░██   █▌▒██░  ██▒▓██ ░▄█ ▒▒██▒▓██  ▀█ ██▒▒██  ▀█▄ ▒ ▓██░ ▒░
░▓█▄   ▌▒██   ██░▒██▀▀█▄  ░██░▓██▒  ▐▌██▒░██▄▄▄▄██░ ▓██▓ ░ 
░▒████▓ ░ ████▓▒░░██▓ ▒██▒░██░▒██░   ▓██░ ▓█   ▓██▒ ▒██▒ ░ 
 ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░▓  ░ ▒░   ▒ ▒  ▒▒   ▓▒█░ ▒ ░░   
 ░ ▒  ▒   ░ ▒ ▒░   ░▒ ░ ▒░ ▒ ░░ ░░   ░ ▒░  ▒   ▒▒ ░   ░    
 ░ ░  ░ ░ ░ ░ ▒    ░░   ░  ▒ ░   ░   ░ ░   ░   ▒    ░      
   ░        ░ ░     ░      ░           ░       ░  ░        
 ░                                                          
{Style.RESET_ALL}
{TermuxColors.INFO}{'═'*60}
   Termux Pentest Ultimate {VERSION}
   Auto-Installer | Professional Security Scanner
{'═'*60}{Style.RESET_ALL}
"""
    print(banner)

# Logger system
class Logger:
    @staticmethod
    def status(msg, tool=None):
        prefix = f"{TermuxColors.PROGRESS}[{next(spinner)}]" 
        if tool:
            prefix += f" {tool}:"
        sys.stdout.write(f"\r{prefix} {msg.ljust(60)}")
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
    def debug(msg):
        print(f"\n{TermuxColors.DEBUG}[DEBUG] {msg}{Style.RESET_ALL}")
    
    @staticmethod
    def warning(msg):
        print(f"\n{TermuxColors.WARNING}[!] {msg}{Style.RESET_ALL}")

# Package Manager with Auto-Installation
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
        Logger.info("Configuring Termux environment...")
        
        try:
            # Create directories
            os.makedirs(TOOLS_DIR, exist_ok=True)
            os.makedirs(WORDLISTS_DIR, exist_ok=True)
            os.makedirs(REPORT_DIR, exist_ok=True)
            os.makedirs(CACHE_DIR, exist_ok=True)

            # Update packages
            Logger.status("Updating packages...")
            subprocess.run("pkg update -y && pkg upgrade -y", 
                         shell=True, 
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)

            # Install core dependencies
            Logger.status("Installing core dependencies...")
            core_deps = [
                "git", "python", "python-pip", "nmap", "curl", "wget", "ruby",
                "golang", "openssl", "dnsutils", "libxml2", "libxslt", "unzip",
                "make", "cmake", "clang", "binutils", "termux-exec"
            ]
            subprocess.run(f"pkg install -y {' '.join(core_deps)}", 
                         shell=True,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)

            # Install Python packages
            Logger.status("Installing Python packages...")
            python_deps = [
                "requests", "beautifulsoup4", "lxml", "colorama", "urllib3",
                "cryptography", "pyOpenSSL", "dnspython"
            ]
            subprocess.run(f"pip install --upgrade {' '.join(python_deps)}", 
                         shell=True,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)

            # Configure PATH
            os.environ["PATH"] += f":{HOME}/go/bin:{TOOLS_DIR}:{HOME}/.local/bin"
            
            Logger.success("Environment configured successfully!")
            return True
        except Exception as e:
            Logger.critical(f"Environment setup failed: {str(e)}")
            return False

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
            
            # Fallback to manual build
            Logger.warning(f"Standard installation failed, trying manual build...")
            os.chdir(TOOLS_DIR)
            
            repo_url = f"https://github.com/{pkg.split('@')[0].split('/')[-3]}/{pkg.split('@')[0].split('/')[-2]}"
            subprocess.run(f"git clone --depth 1 {repo_url}", 
                         shell=True,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE)
            
            tool_dir = pkg.split('@')[0].split('/')[-1]
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
            
            Logger.success(f"{tool} built and installed successfully!")
            return True
            
        except Exception as e:
            Logger.critical(f"Failed to install {tool}: {str(e)}")
            return False

    @staticmethod
    def install_python_tool(tool, repo):
        tool_path = f"{TOOLS_DIR}/{tool}"
        
        if os.path.exists(tool_path):
            shutil.rmtree(tool_path, ignore_errors=True)
                
        Logger.status(f"Installing {tool}...", "Python")
        try:
            # Clone with retry
            for attempt in range(3):
                result = subprocess.run(
                    f"git clone --depth 1 {repo} {tool_path}",
                    shell=True,
                    cwd=TOOLS_DIR,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if result.returncode == 0:
                    break
                time.sleep(2)
            else:
                raise Exception("Git clone failed after 3 attempts")
            
            # Install dependencies
            req_file = f"{tool_path}/requirements.txt"
            if os.path.exists(req_file):
                subprocess.run(
                    f"pip install -r {req_file}",
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE
                )
            
            # Create symlinks for common tools
            if tool == "sqlmap":
                os.symlink(f"{tool_path}/sqlmap.py", f"{TOOLS_DIR}/sqlmap")
            
            Logger.success(f"{tool} installed successfully!")
            return True
        except Exception as e:
            Logger.critical(f"Failed to install {tool}: {str(e)}")
            return False

    @staticmethod
    def setup_tools():
        # Go tools
        go_tools = [
            ("nuclei", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei", "v2.9.15"),
            ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder", "latest"),
            ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx", "latest"),
            ("ffuf", "github.com/ffuf/ffuf", "latest"),
            ("waybackurls", "github.com/tomnomnom/waybackurls", "latest")
        ]
        
        # Python tools
        py_tools = [
            ("sqlmap", "https://github.com/sqlmapproject/sqlmap.git"),
            ("nikto", "https://github.com/sullo/nikto.git")
        ]
        
        # Install Go tools
        Logger.info("Installing Go tools...")
        go_success = all(TermuxManager.install_go_tool(*tool) for tool in go_tools)
        
        # Install Python tools
        Logger.info("Installing Python tools...")
        py_success = all(TermuxManager.install_python_tool(*tool) for tool in py_tools)
        
        # Verify installation
        all_installed = all(TermuxManager.check_installed(tool[0]) for tool in go_tools + py_tools)
        
        if not all_installed:
            Logger.critical("Some tools failed to install!")
            return False
        
        # Set permissions
        subprocess.run(f"chmod +x {HOME}/go/bin/*", shell=True, stdout=subprocess.DEVNULL)
        subprocess.run(f"chmod +x {TOOLS_DIR}/sqlmap/sqlmap.py", shell=True, stdout=subprocess.DEVNULL)
        
        Logger.success("All tools installed successfully!")
        return True

    @staticmethod
    def download_wordlists():
        wordlists = {
            "web_content.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt",
            "subdomains.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
            "passwords.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
        }
        
        Logger.info("Downloading wordlists...")
        for name, url in wordlists.items():
            dest = f"{WORDLISTS_DIR}/{name}"
            if os.path.exists(dest):
                continue
                
            try:
                Logger.status(f"Downloading {name}...", "Wordlists")
                response = requests.get(url, stream=True, timeout=60)
                with open(dest, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
            except Exception as e:
                Logger.debug(f"Failed to download {name}: {str(e)}")

# Advanced Scanner
class AdvancedScanner:
    def __init__(self, target):
        self.target = target if target.startswith(("http://", "https://")) else f"http://{target}"
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
                "vulnerabilities": [],
                "information": [],
                "configuration_issues": []
            }
        }
        self.lock = threading.Lock()

    def save_report(self):
        report_file = f"{REPORT_DIR}/{self.domain}_{int(time.time())}.json"
        try:
            with self.lock:
                with open(report_file, "w") as f:
                    json.dump(self.report_data, f, indent=4, ensure_ascii=False)
                Logger.success(f"Report saved to: {report_file}")
                return report_file
        except Exception as e:
            Logger.critical(f"Failed to save report: {str(e)}")
            return None

    def add_vulnerability(self, vuln_type, description, severity, details=None):
        with self.lock:
            self.report_data["results"]["vulnerabilities"].append({
                "type": vuln_type,
                "description": description,
                "severity": severity,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "details": details if details else {}
            })
        
        if severity == "critical":
            Logger.critical(f"{vuln_type.upper()}: {description}")
        elif severity == "high":
            Logger.high(f"{vuln_type.upper()}: {description}")
        elif severity == "medium":
            Logger.medium(f"{vuln_type.upper()}: {description}")
        else:
            Logger.low(f"{vuln_type.upper()}: {description}")

    def add_information(self, info_type, data):
        with self.lock:
            self.report_data["results"]["information"].append({
                "type": info_type,
                "data": data,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            })
        Logger.info(f"{info_type.upper()}: {str(data)[:100]}...")

    def run_tool(self, command, tool_name, output_file=None, json_output=False):
        try:
            Logger.status(f"Starting {tool_name}...", tool_name)
            
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                output, error = process.communicate(timeout=TIMEOUT*2)
            except subprocess.TimeoutExpired:
                process.kill()
                Logger.warning(f"{tool_name} timed out")
                return None
            
            if output_file:
                with open(output_file, "w") as f:
                    f.write(output)
            
            if process.returncode != 0:
                Logger.debug(f"{tool_name} error: {error.strip()}")
                return None
            
            if json_output:
                try:
                    return json.loads(output)
                except json.JSONDecodeError:
                    return output.splitlines()
            
            return output.splitlines() if output else None
            
        except Exception as e:
            Logger.debug(f"{tool_name} exception: {str(e)}")
            return None
        finally:
            Logger.status(f"Finishing {tool_name}...", tool_name)

    def passive_reconnaissance(self):
        Logger.info("Starting passive reconnaissance...")
        
        # Subdomain Enumeration
        subdomains = self.run_tool(
            f"subfinder -d {self.domain} -silent -t {THREADS}",
            "SubFinder"
        )
        if subdomains:
            self.add_information("subdomains", list(set(subdomains)))
        
        # Historical Data
        wayback_data = self.run_tool(
            f"waybackurls {self.domain}",
            "WaybackURLs"
        )
        if wayback_data:
            self.add_information("historical_urls", wayback_data)
        
        # DNS Information
        dns_info = self.run_tool(
            f"host {self.domain}",
            "DNS Lookup"
        )
        if dns_info:
            self.add_information("dns_records", dns_info)

    def active_scanning(self):
        Logger.info("Starting active scanning...")
        
        # Nuclei Scan
        nuclei_report = f"{REPORT_DIR}/nuclei_{self.domain}.json"
        self.run_tool(
            f"nuclei -u {self.target} -t cves/ -severity critical,high -json -o {nuclei_report}",
            "Nuclei"
        )
        
        if os.path.exists(nuclei_report):
            with open(nuclei_report) as f:
                for line in f:
                    try:
                        vuln = json.loads(line)
                        self.add_vulnerability(
                            vuln.get("templateID", "unknown"),
                            vuln.get("info", {}).get("name", "Unknown vulnerability"),
                            vuln.get("severity", "medium").lower(),
                            vuln
                        )
                    except json.JSONDecodeError:
                        continue
        
        # SQL Injection Testing
        sqlmap_report = f"{REPORT_DIR}/sqlmap_{self.domain}.log"
        sqlmap_result = self.run_tool(
            f"python {TOOLS_DIR}/sqlmap/sqlmap.py -u {self.target} --batch --crawl=1 --level=3 --risk=2 --output-dir={REPORT_DIR}",
            "SQLMap",
            output_file=sqlmap_report
        )
        
        if sqlmap_result and "sqlmap identified the following injection points" in " ".join(sqlmap_result):
            self.add_vulnerability(
                "SQL Injection",
                "SQL injection vulnerabilities detected",
                "high",
                {"tool": "sqlmap", "report": sqlmap_report}
            )
        
        # Directory Bruteforcing
        ffuf_report = f"{REPORT_DIR}/ffuf_{self.domain}.json"
        self.run_tool(
            f"ffuf -u {self.target}/FUZZ -w {WORDLISTS_DIR}/web_content.txt -t {THREADS} -o {ffuf_report} -of json",
            "FFUF"
        )
        
        if os.path.exists(ffuf_report):
            with open(ffuf_report) as f:
                data = json.load(f)
                if data.get("results"):
                    interesting = [res for res in data["results"] if res["status"] in (200, 403, 500)]
                    self.add_information("directory_bruteforce", interesting)

    def web_application_analysis(self):
        Logger.info("Analyzing web application...")
        
        try:
            response = self.session.get(self.target, timeout=TIMEOUT)
            
            # Technology Stack Detection
            tech_stack = {
                "server": response.headers.get("Server", ""),
                "cms": self.detect_cms(response.text),
                "frameworks": self.detect_frameworks(response.text),
                "security_headers": self.check_security_headers(response.headers)
            }
            self.add_information("technology_stack", tech_stack)
            
            # Sensitive Files Discovery
            sensitive_files = self.find_sensitive_files()
            if sensitive_files:
                self.add_vulnerability(
                    "sensitive_files_exposure",
                    f"Found sensitive files: {', '.join(sensitive_files)}",
                    "medium",
                    {"files": sensitive_files}
                )
            
            # API Endpoint Discovery
            api_endpoints = self.find_api_endpoints(response.text)
            if api_endpoints:
                self.add_information("api_endpoints", api_endpoints)
                
        except Exception as e:
            Logger.debug(f"Web analysis error: {str(e)}")

    def detect_cms(self, html):
        cms = []
        if "wp-content" in html or "wp-includes" in html:
            cms.append("WordPress")
        if "joomla" in html.lower() or "/media/system/js/" in html:
            cms.append("Joomla")
        if "drupal" in html.lower() or "/sites/default/files/" in html:
            cms.append("Drupal")
        return cms if cms else None

    def detect_frameworks(self, html):
        frameworks = []
        if "React" in html:
            frameworks.append("React")
        if "Vue" in html:
            frameworks.append("Vue.js")
        if "Angular" in html:
            frameworks.append("Angular")
        return frameworks if frameworks else None

    def check_security_headers(self, headers):
        security_headers = {
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": None,
            "Strict-Transport-Security": None,
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff"
        }
        
        results = {}
        for header, expected in security_headers.items():
            if header not in headers:
                results[header] = "missing"
            elif expected and headers[header] != expected:
                results[header] = f"incorrect (current: {headers[header]})"
            else:
                results[header] = "ok"
        
        return results

    def find_sensitive_files(self):
        files = [
            "robots.txt", ".env", "package.json", "composer.json",
            "web.config", "phpinfo.php", ".git/HEAD"
        ]
        
        found = []
        for file in files:
            try:
                url = urljoin(self.target, file)
                resp = self.session.head(url, timeout=5)
                if resp.status_code == 200:
                    found.append(url)
            except:
                continue
        
        return found if found else None

    def find_api_endpoints(self, html):
        endpoints = set()
        patterns = [
            r'fetch\(["\'](.*?)["\']',
            r'axios\.get\(["\'](.*?)["\']',
            r'url:\s*["\'](.*?)["\']',
            r'api/v\d+/[a-zA-Z0-9_/-]+'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, html)
            for match in matches:
                endpoint = match.group(1) if match.groups() else match.group(0)
                if endpoint.startswith(("http://", "https://")):
                    endpoints.add(endpoint)
                else:
                    endpoints.add(urljoin(self.target, endpoint))
        
        return list(endpoints) if endpoints else None

    def run_full_scan(self):
        start_time = time.time()
        
        try:
            with ThreadPoolExecutor(max_workers=THREADS) as executor:
                executor.submit(self.passive_reconnaissance)
                executor.submit(self.active_scanning)
                executor.submit(self.web_application_analysis)
            
            self.report_data["metadata"]["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
            self.report_data["metadata"]["duration"] = f"{round(time.time() - start_time, 2)} seconds"
            
            vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for vuln in self.report_data["results"]["vulnerabilities"]:
                vuln_counts[vuln["severity"]] += 1
            
            self.report_data["summary"] = {
                "total_vulnerabilities": len(self.report_data["results"]["vulnerabilities"]),
                "vulnerability_counts": vuln_counts,
                "information_items": len(self.report_data["results"]["information"])
            }
            
            report_path = self.save_report()
            
            print("\n" + "═"*60)
            print(f"{TermuxColors.BANNER} SCAN SUMMARY {Style.RESET_ALL}")
            print("═"*60)
            print(f"Target: {self.target}")
            print(f"Duration: {self.report_data['metadata']['duration']}")
            print(f"\n{TermuxColors.CRITICAL}Critical: {vuln_counts['critical']}{Style.RESET_ALL}")
            print(f"{TermuxColors.HIGH}High: {vuln_counts['high']}{Style.RESET_ALL}")
            print(f"{TermuxColors.MEDIUM}Medium: {vuln_counts['medium']}{Style.RESET_ALL}")
            print(f"{TermuxColors.LOW}Low: {vuln_counts['low']}{Style.RESET_ALL}")
            print("\n" + "═"*60)
            
            return report_path
            
        except Exception as e:
            Logger.critical(f"Scan failed: {str(e)}")
            return None

def main_menu():
    print_banner()
    
    # Setup environment and tools
    if not TermuxManager.setup_environment():
        sys.exit(1)
    
    if not TermuxManager.setup_tools():
        sys.exit(1)
    
    TermuxManager.download_wordlists()
    
    while True:
        print(f"\n{TermuxColors.INFO}Main Menu:{Style.RESET_ALL}")
        print(f"1. Single Target Scan")
        print(f"2. Multi-Target Scan (file)")
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
            file_path = input(f"{TermuxColors.INFO}[?] Enter targets file path: {Style.RESET_ALL}").strip()
            if not os.path.exists(file_path):
                Logger.critical("File not found!")
                continue
                
            with open(file_path) as f:
                targets = [line.strip() for line in f if line.strip()]
            
            for i, target in enumerate(targets, 1):
                Logger.info(f"\nProcessing target {i}/{len(targets)}: {target}")
                scanner = AdvancedScanner(target)
                scanner.run_full_scan()
                
        elif choice == "3":
            Logger.info("Updating tools...")
            TermuxManager.setup_tools()
            
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