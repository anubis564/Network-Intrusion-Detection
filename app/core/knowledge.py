"""Attack knowledge base: what each attack is, how it shows up in flow features, and how to respond.

Indicators come from the exploratory analysis in the notebook (section 1.7).
Response steps are defensive guidance for a SOC analyst; actions in the app are simulated.
"""

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
SEVERITY_ACTION = {"Critical": "Blocked", "High": "Blocked", "Medium": "Logged", "Low": "Logged"}

FAMILIES = {
    "Benign": {"color": "#3b82f6", "icon": ":material/verified_user:"},
    "DoS": {"color": "#f97316", "icon": ":material/bolt:"},
    "DDoS": {"color": "#ef4444", "icon": ":material/hub:"},
    "PortScan": {"color": "#eab308", "icon": ":material/radar:"},
    "Brute Force": {"color": "#a855f7", "icon": ":material/key:"},
    "Web Attack": {"color": "#ec4899", "icon": ":material/code:"},
    "Bot": {"color": "#14b8a6", "icon": ":material/smart_toy:"},
    "Infiltration": {"color": "#8b5cf6", "icon": ":material/bug_report:"},
    "Heartbleed": {"color": "#dc2626", "icon": ":material/heart_broken:"},
}

_DOS_RESPONSE = [
    "Confirm the target service (port 80 in this dataset) and check its CPU, memory and open-connection count.",
    "Rate-limit or temporarily block the source IP at the firewall or load balancer.",
    "Enable connection limits and shorter timeouts on the web server (e.g. per-IP connection caps).",
    "If the service is degraded, move traffic behind a reverse proxy / CDN with DoS protection.",
    "Keep the flow records and server logs for the incident report.",
]
_DOS_PREVENT = [
    "Per-IP rate limiting and connection caps on public web servers.",
    "Reverse proxy or CDN with application-layer DoS protection.",
    "Alerting on sudden jumps in flows per minute to the same service.",
]

ATTACKS = {
    "BENIGN": {
        "family": "Benign", "name": "Benign traffic", "severity": "Low", "mitre": [],
        "summary": "Normal network activity with no sign of malicious behaviour.",
        "how": "Everyday traffic: web browsing, DNS and NTP lookups, file shares, e-mail and similar services.",
        "indicators": [
            "Varied behaviour: flows are spread over many durations, sizes and ports.",
            "About 60% of benign flows in CICIDS2017 are UDP (DNS, NTP and similar).",
            "Median flow: about 61 ms, 2 packets each way, 82 bytes forward.",
        ],
        "impact": "None.",
        "response": ["No action needed. If you believe this flow is malicious, report it as a false negative."],
        "prevention": [],
    },
    "DoS Hulk": {
        "family": "DoS", "name": "DoS Hulk (HTTP flood)", "severity": "High",
        "mitre": [("T1499.002", "Endpoint DoS: Service Exhaustion Flood")],
        "summary": "Floods a web server with a huge number of unique HTTP requests to exhaust its resources.",
        "how": "The HULK tool generates large volumes of HTTP GET requests with randomised URLs and headers, so caching and simple filters do not help and the server spends all its resources answering them.",
        "indicators": [
            "All flows target port 80 (HTTP) over TCP.",
            "Very high flow rate: above 40,000 flows per 5 minutes at its peak, more than all benign traffic.",
            "Large backward volume (the server returning pages) and RST at the end of almost every flow.",
        ],
        "impact": "Web service slows down or becomes unavailable for legitimate users.",
        "response": _DOS_RESPONSE, "prevention": _DOS_PREVENT,
    },
    "DoS GoldenEye": {
        "family": "DoS", "name": "DoS GoldenEye", "severity": "High",
        "mitre": [("T1499.002", "Endpoint DoS: Service Exhaustion Flood")],
        "summary": "HTTP DoS tool that keeps many connections alive with keep-alive and no-cache headers.",
        "how": "GoldenEye opens many HTTP connections and abuses Keep-Alive and Cache-Control headers so each connection stays busy and bypasses caches, exhausting the server's connection pool.",
        "indicators": [
            "Targets port 80 over TCP from a single attacker host.",
            "Many medium-length flows with repeated request patterns.",
            "Connections typically end with RST.",
        ],
        "impact": "Web server runs out of worker connections; legitimate requests time out.",
        "response": _DOS_RESPONSE, "prevention": _DOS_PREVENT,
    },
    "DoS slowloris": {
        "family": "DoS", "name": "DoS Slowloris", "severity": "High",
        "mitre": [("T1499.002", "Endpoint DoS: Service Exhaustion Flood")],
        "summary": "Low-bandwidth DoS that keeps many HTTP connections open by sending headers very slowly.",
        "how": "Slowloris opens connections and sends partial HTTP headers, adding one more header every few seconds so the request never completes. The server keeps every connection open until no slots are left.",
        "indicators": [
            "Long flows with very few packets and tiny payloads.",
            "Long gaps between packets (high inter-arrival times).",
            "Many concurrent connections from one source to port 80.",
        ],
        "impact": "Server connection slots are exhausted with very little traffic, so volume-based alarms may miss it.",
        "response": _DOS_RESPONSE + ["Lower the request-header timeout on the web server (e.g. Apache mod_reqtimeout)."],
        "prevention": _DOS_PREVENT + ["Use an event-driven server or reverse proxy that is not vulnerable to slow headers."],
    },
    "DoS Slowhttptest": {
        "family": "DoS", "name": "DoS SlowHTTPTest", "severity": "High",
        "mitre": [("T1499.002", "Endpoint DoS: Service Exhaustion Flood")],
        "summary": "Slow HTTP attack (slow headers, slow body or slow read) generated with the slowhttptest tool.",
        "how": "Like Slowloris, the attacker sends or reads HTTP data extremely slowly to tie up server connections for as long as possible.",
        "indicators": [
            "Long-lived flows to port 80 with very low packet rate.",
            "Small forward payloads and large idle periods.",
        ],
        "impact": "Connection pool exhaustion with low bandwidth.",
        "response": _DOS_RESPONSE + ["Enforce minimum data rates and body/read timeouts on the web server."],
        "prevention": _DOS_PREVENT,
    },
    "DDoS": {
        "family": "DDoS", "name": "DDoS (LOIC HTTP flood)", "severity": "Critical",
        "mitre": [("T1498", "Network Denial of Service"), ("T1499.002", "Endpoint DoS: Service Exhaustion Flood")],
        "summary": "Distributed flood of HTTP requests from several machines against one web server.",
        "how": "In CICIDS2017 several Windows machines ran LOIC at the same time to flood the victim web server. Because the traffic comes from many sources, blocking a single IP is not enough.",
        "indicators": [
            "All flows to port 80 over TCP, every flow containing SYN, ACK, PSH, FIN and RST.",
            "Reaches 10^4-10^5 flows per 5 minutes in a 20-minute burst.",
            "Median 8 packets forward, 11.6 KB backward per flow (the server answering).",
        ],
        "impact": "Full outage of the targeted service; upstream bandwidth can also be saturated.",
        "response": [
            "Declare an incident: a distributed flood will not stop by blocking one IP.",
            "Contact the upstream provider / DDoS protection service to filter traffic before it reaches the network.",
            "Apply rate limits and geo/ASN filtering at the edge; prioritise known-good clients.",
            "Scale out or fail over the affected service if possible.",
            "Collect the list of attacking source IPs from the flow records for blocking and reporting.",
        ],
        "prevention": ["Always-on DDoS mitigation (CDN / scrubbing service).", "Capacity planning and auto-scaling for public services."],
    },
    "PortScan": {
        "family": "PortScan", "name": "Port scan", "severity": "Medium",
        "mitre": [("T1046", "Network Service Discovery")],
        "summary": "Reconnaissance: probing many ports to discover which services are running.",
        "how": "The attacker (Nmap in CICIDS2017) sends connection attempts to a long list of ports. Open ports answer, closed ports reset the connection. It usually comes before a real attack.",
        "indicators": [
            "One flow per probe: 1 packet each way, zero payload, about 47 microseconds.",
            "SYN + RST in every flow, but never PSH or FIN (no data is ever sent).",
            "The same source touches more than 1,000 different destination ports.",
        ],
        "impact": "No direct damage, but the attacker learns which services are exposed and may attack them next.",
        "response": [
            "Identify the scanning source IP and check whether it is internal (compromised host?) or external.",
            "Block or rate-limit the source at the firewall.",
            "Review which ports were found open and close anything that should not be exposed.",
            "Watch the same source for follow-up attacks over the next hours.",
        ],
        "prevention": ["Default-deny firewall policy; expose only the services you need.", "Port-scan detection and automatic temporary blocking."],
    },
    "FTP-Patator": {
        "family": "Brute Force", "name": "FTP brute force (Patator)", "severity": "Medium",
        "mitre": [("T1110.001", "Brute Force: Password Guessing")],
        "summary": "Automated password guessing against an FTP server.",
        "how": "Patator tries thousands of username/password combinations against FTP (port 21), one login attempt per connection.",
        "indicators": [
            "All flows to port 21 over TCP from one source.",
            "Long (about 10 s) but slow flows: 3-4 packets per second, small payloads.",
            "Connections opened and closed cleanly (SYN ... FIN), repeated at a steady rate.",
        ],
        "impact": "If a weak password is guessed, the attacker gains file access on the server.",
        "response": [
            "Block the source IP and check the FTP server logs for any successful login from it.",
            "If a login succeeded, disable that account, reset its password and review what was accessed.",
            "Enable account lockout / fail2ban on the FTP service.",
        ],
        "prevention": ["Replace FTP with SFTP/FTPS.", "Strong passwords, lockout after failed attempts, allow-list of client IPs."],
    },
    "SSH-Patator": {
        "family": "Brute Force", "name": "SSH brute force (Patator)", "severity": "High",
        "mitre": [("T1110.001", "Brute Force: Password Guessing")],
        "summary": "Automated password guessing against an SSH server.",
        "how": "Patator repeatedly tries credentials against SSH (port 22). A successful guess gives the attacker a shell on the server.",
        "indicators": [
            "All flows to port 22 over TCP from one source.",
            "Many similar flows with small encrypted payloads at a regular rhythm.",
            "Roughly one hour of continuous attempts in the dataset.",
        ],
        "impact": "Remote shell access to the server if any password is guessed.",
        "response": [
            "Block the source IP and search auth logs for 'Accepted password' from it.",
            "If any login succeeded, isolate the host and treat it as compromised.",
            "Enable fail2ban or equivalent rate limiting on SSH.",
        ],
        "prevention": ["Key-based SSH authentication only; disable password login.", "Restrict SSH to a VPN or management network."],
    },
    "Web Attack - Brute Force": {
        "family": "Web Attack", "name": "Web login brute force", "severity": "Medium",
        "mitre": [("T1110.001", "Brute Force: Password Guessing")],
        "summary": "Repeated login attempts against a web application's login form.",
        "how": "The attacker submits many username/password combinations to a web login page (DVWA in CICIDS2017).",
        "indicators": [
            "Flows to port 80 with small, repeated POST-sized payloads.",
            "Long, slow flows similar to other brute-force attacks.",
            "Low volume: hidden inside normal web traffic, so volume alone does not reveal it.",
        ],
        "impact": "Account takeover on the web application.",
        "response": [
            "Block the source IP and check the application logs for successful logins.",
            "Lock or reset any account that was accessed.",
            "Add rate limiting / CAPTCHA to the login form.",
        ],
        "prevention": ["Multi-factor authentication.", "Login rate limiting and account lockout.", "Web application firewall (WAF)."],
    },
    "Web Attack - XSS": {
        "family": "Web Attack", "name": "Cross-site scripting (XSS)", "severity": "High",
        "mitre": [("T1059.007", "Command and Scripting Interpreter: JavaScript"), ("T1189", "Drive-by Compromise")],
        "summary": "Injecting malicious JavaScript into a web page so it runs in other users' browsers.",
        "how": "The attacker sends input containing script code to a vulnerable page. If the application reflects or stores it without encoding, the script runs in the victim's browser and can steal sessions or perform actions.",
        "indicators": [
            "Flows to port 80 with unusual request sizes compared with normal browsing.",
            "Very few flows (27 in the dataset): only detectable from per-flow behaviour, not volume.",
        ],
        "impact": "Session theft, defacement or actions performed in the name of other users.",
        "response": [
            "Find the vulnerable page/parameter in the web server logs for this source IP.",
            "Remove any stored malicious content and invalidate affected sessions.",
            "Patch the application: encode output and validate input.",
        ],
        "prevention": ["Output encoding and input validation.", "Content-Security-Policy header.", "WAF rules for XSS patterns."],
    },
    "Web Attack - Sql Injection": {
        "family": "Web Attack", "name": "SQL injection", "severity": "Critical",
        "mitre": [("T1190", "Exploit Public-Facing Application")],
        "summary": "Injecting SQL code into application input to read or modify the database.",
        "how": "The attacker places SQL fragments in form fields or URL parameters. If the application builds queries by string concatenation, the injected SQL runs on the database.",
        "indicators": [
            "Flows to port 80 with request payloads larger or shaped differently from normal requests.",
            "Extremely rare in the dataset (12 flows), so it sits inside normal web traffic.",
        ],
        "impact": "Data theft, data modification or full database compromise.",
        "response": [
            "Treat as critical: check database and application logs for the injected queries.",
            "Assume data exposure until proven otherwise; rotate database credentials.",
            "Patch the vulnerable query (parameterised queries) and add a WAF rule meanwhile.",
        ],
        "prevention": ["Parameterised queries / ORM.", "Least-privilege database accounts.", "WAF with SQLi rules."],
    },
    "Infiltration": {
        "family": "Infiltration", "name": "Infiltration (internal compromise)", "severity": "Critical",
        "mitre": [("T1204.002", "User Execution: Malicious File"), ("T1071.001", "Application Layer Protocol: Web Protocols")],
        "summary": "A victim inside the network runs a malicious file, giving the attacker a foothold that is then used to explore the internal network.",
        "how": "In CICIDS2017 a victim downloads and opens an infected file; the attacker then uses the compromised machine to scan and attack other internal hosts.",
        "indicators": [
            "Very long flows (100-120 s, cut by the 2-minute flow timeout).",
            "Only 10-16% of flows contain SYN or FIN: they continue long-lived connections.",
            "Traffic to an unusual port (444 in this dataset).",
        ],
        "impact": "Attacker has a foothold inside the network and can move laterally.",
        "response": [
            "Isolate the internal host immediately (network quarantine).",
            "Capture memory/disk for forensics before cleaning.",
            "Find the initial infection (downloaded file, e-mail) and block it everywhere.",
            "Hunt for the same indicators on other hosts.",
        ],
        "prevention": ["Endpoint protection and application allow-listing.", "User awareness training.", "Network segmentation."],
    },
    "Bot": {
        "family": "Bot", "name": "Botnet (Ares)", "severity": "Critical",
        "mitre": [("T1071.001", "Application Layer Protocol: Web Protocols")],
        "summary": "Infected hosts regularly contact a command-and-control (C2) server for instructions.",
        "how": "The Ares botnet in CICIDS2017 makes infected machines poll a C2 server over HTTP (port 8080) to receive commands, upload screenshots or exfiltrate files.",
        "indicators": [
            "All flows to port 8080 over TCP.",
            "Feature values close to normal web traffic: one of the hardest families to detect.",
            "Regular, repeated connections (beaconing) from the same internal hosts.",
        ],
        "impact": "Compromised hosts are under remote control and may leak data or join attacks.",
        "response": [
            "Block the C2 destination IP/port at the firewall and DNS.",
            "Isolate and reimage every internal host that contacted the C2 server.",
            "Search other hosts for the same beaconing pattern.",
        ],
        "prevention": ["Egress filtering (only allow needed outbound ports).", "Endpoint detection and response (EDR)."],
    },
    "Heartbleed": {
        "family": "Heartbleed", "name": "Heartbleed (CVE-2014-0160)", "severity": "Critical",
        "mitre": [("T1190", "Exploit Public-Facing Application")],
        "summary": "Exploits a bug in OpenSSL's heartbeat extension to read the server's memory.",
        "how": "The attacker sends malformed TLS heartbeat requests claiming a large payload length; vulnerable OpenSSL versions answer with up to 64 KB of server memory each time, which can contain keys and passwords.",
        "indicators": [
            "Very long flows (about 120 s) with huge backward volume: median 7.9 MB from the server.",
            "Traffic to port 444 in this dataset.",
            "Only 7 flows after cleaning: extremely rare.",
        ],
        "impact": "Leak of private keys, session cookies and passwords from server memory.",
        "response": [
            "Patch OpenSSL immediately on the affected server.",
            "Revoke and reissue TLS certificates; rotate keys and passwords that could have leaked.",
            "Invalidate all active sessions.",
        ],
        "prevention": ["Keep TLS libraries patched.", "Vulnerability scanning of public services."],
    },
}

# Labels written differently in some files
_ALIASES = {"DoS Slowloris": "DoS slowloris", "DoS SlowHttpTest": "DoS Slowhttptest",
            "Web Attack - SQL Injection": "Web Attack - Sql Injection", "Portscan": "PortScan"}


def base_label(label: str) -> str:
    label = str(label).replace(" - Attempted", "")
    return _ALIASES.get(label, label)


def info(label: str) -> dict:
    label = base_label(label)
    return ATTACKS.get(label, {
        "family": "Unknown", "name": label, "severity": "Medium", "mitre": [], "summary": "Unknown attack type.",
        "how": "", "indicators": [], "impact": "", "response": [], "prevention": [],
    })


def family_of(label: str) -> str:
    return info(label)["family"]


def severity_of(label: str) -> str:
    return info(label)["severity"]


def family_color(family: str) -> str:
    return FAMILIES.get(family, {"color": "#94a3b8"})["color"]


def as_documents() -> list[dict]:
    """Knowledge base entries as text documents for retrieval."""
    docs = []
    for label, a in ATTACKS.items():
        mitre = ", ".join(f"{tid} {name}" for tid, name in a["mitre"]) or "none"
        text = (
            f"{a['name']} ({label}). Family: {a['family']}. Severity: {a['severity']}. MITRE ATT&CK: {mitre}.\n"
            f"Summary: {a['summary']}\nHow it works: {a['how']}\n"
            f"Indicators in network flows: " + " ".join(a["indicators"]) + f"\nImpact: {a['impact']}\n"
            f"How to respond: " + " ".join(a["response"]) + "\n"
            f"Prevention: " + " ".join(a["prevention"])
        )
        docs.append({"source": f"Attack library - {a['name']}", "text": text})
    return docs
