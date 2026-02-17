from flask import Flask, request, jsonify
from flask_cors import CORS
from pathlib import Path
import ipaddress
import json
import re
import socket
import subprocess
import threading
import uuid
import nmap
import xml.etree.ElementTree as ET
import urllib.error
import urllib.request
from datetime import datetime, timezone

app = Flask(__name__)
# Allow the local frontend to call this API (including preflight OPTIONS).
CORS(app, resources={r"/*": {"origins": "https://cyber-project-one.vercel.app/*"}})
data_lock = threading.Lock()
data_dir = Path(__file__).resolve().parent / "data"
data_file = data_dir / "scan_results.json"


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def ensure_data_file():
    data_dir.mkdir(exist_ok=True)
    if not data_file.exists():
        data_file.write_text(json.dumps({"scans": []}, indent=2), encoding="utf-8")


def load_store_unlocked():
    ensure_data_file()
    try:
        store = json.loads(data_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        store = {"scans": []}
    if not isinstance(store, dict) or not isinstance(store.get("scans"), list):
        store = {"scans": []}
    return store


def save_store_unlocked(store):
    ensure_data_file()
    data_file.write_text(json.dumps(store, indent=2), encoding="utf-8")


def run_shell_command(command, timeout_seconds=30):
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return {
            "ok": completed.returncode == 0,
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
            "returncode": completed.returncode,
        }
    except FileNotFoundError:
        return {"ok": False, "stdout": "", "stderr": "command not found", "returncode": 127}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "command timeout", "returncode": 124}


def parse_nmap_xml(xml_text):
    hosts = []
    if not xml_text.strip():
        return hosts
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts

    for host in root.findall("host"):
        status_node = host.find("status")
        status = status_node.get("state") if status_node is not None else "unknown"
        if status != "up":
            continue

        ipv4 = "Unknown"
        mac = "Unknown"
        vendor = "Unknown"
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type == "ipv4":
                ipv4 = addr.get("addr", "Unknown")
            if addr_type == "mac":
                mac = addr.get("addr", "Unknown")
                vendor = addr.get("vendor", "Unknown")

        hostname = "Unknown"
        hostnames_node = host.find("hostnames")
        if hostnames_node is not None:
            host_name_node = hostnames_node.find("hostname")
            if host_name_node is not None:
                hostname = host_name_node.get("name") or "Unknown"

        open_ports = []
        ports_node = host.find("ports")
        if ports_node is not None:
            for port_node in ports_node.findall("port"):
                state_node = port_node.find("state")
                if state_node is None or state_node.get("state") != "open":
                    continue
                service_node = port_node.find("service")
                service_name = "unknown"
                version = "unknown"
                product = ""
                if service_node is not None:
                    service_name = service_node.get("name", "unknown")
                    product = service_node.get("product", "")
                    version = service_node.get("version", "") or "unknown"
                open_ports.append(
                    {
                        "port": int(port_node.get("portid", "0")),
                        "protocol": port_node.get("protocol", "tcp"),
                        "service": service_name,
                        "product": product,
                        "version": version,
                    }
                )

        hosts.append(
            {
                "ip": ipv4,
                "hostname": hostname,
                "mac": mac,
                "vendor": vendor,
                "open_ports": open_ports,
            }
        )
    return hosts


def parse_whois_output(whois_text):
    def first_match(patterns):
        for pattern in patterns:
            match = re.search(pattern, whois_text, flags=re.IGNORECASE | re.MULTILINE)
            if match:
                return match.group(1).strip()
        return "Unknown"

    def all_matches(patterns):
        values = []
        for pattern in patterns:
            matches = re.findall(pattern, whois_text, flags=re.IGNORECASE | re.MULTILINE)
            values.extend([value.strip() for value in matches if value.strip()])
        return sorted(list(set(values)))

    return {
        "registrar": first_match([r"^\s*Registrar:\s*(.+)$", r"^\s*Sponsoring Registrar:\s*(.+)$"]),
        "created": first_match([r"^\s*Creation Date:\s*(.+)$", r"^\s*Created On:\s*(.+)$"]),
        "expires": first_match([r"^\s*Registry Expiry Date:\s*(.+)$", r"^\s*Registrar Registration Expiration Date:\s*(.+)$", r"^\s*Expiry Date:\s*(.+)$"]),
        "organization": first_match([r"^\s*Registrant Organization:\s*(.+)$", r"^\s*OrgName:\s*(.+)$"]),
        "whois_server": first_match([r"^\s*Whois Server:\s*(.+)$", r"^\s*Registrar WHOIS Server:\s*(.+)$"]),
        "status": all_matches([r"^\s*Domain Status:\s*(.+)$", r"^\s*Status:\s*(.+)$"]),
        "nameservers": all_matches([r"^\s*Name Server:\s*(.+)$", r"^\s*nserver:\s*(.+)$"]),
    }


def parse_nslookup_records(nslookup_text, record_type):
    records = []
    nameservers = []
    normalized_type = record_type.upper()

    for line in nslookup_text.splitlines():
        trimmed = line.strip()
        if not trimmed:
            continue

        if normalized_type == "NS":
            ns_match = re.search(r"(?:nameserver|name server)\s*=\s*(\S+)", trimmed, flags=re.IGNORECASE)
            if ns_match:
                value = ns_match.group(1).strip().rstrip(".")
                nameservers.append(value)
                records.append({"type": "NS", "value": value})
                continue

        if normalized_type == "MX":
            mx_match = re.search(r"mail exchanger\s*=\s*(\S+)", trimmed, flags=re.IGNORECASE)
            if mx_match:
                value = mx_match.group(1).strip().rstrip(".")
                records.append({"type": "MX", "value": value})
                continue

        if normalized_type == "TXT":
            txt_match = re.search(r'text\s*=\s*"?(.*?)"?$', trimmed, flags=re.IGNORECASE)
            if txt_match and txt_match.group(1):
                records.append({"type": "TXT", "value": txt_match.group(1).strip()})
                continue

        if normalized_type == "CNAME":
            cname_match = re.search(r"canonical name\s*=\s*(\S+)", trimmed, flags=re.IGNORECASE)
            if cname_match:
                value = cname_match.group(1).strip().rstrip(".")
                records.append({"type": "CNAME", "value": value})
                continue

        if normalized_type == "SOA":
            if "origin =" in trimmed.lower():
                value = trimmed.split("=", 1)[-1].strip().rstrip(".")
                records.append({"type": "SOA", "value": value})
                continue

    unique_records = []
    seen = set()
    for record in records:
        key = (record["type"], record["value"])
        if key in seen:
            continue
        seen.add(key)
        unique_records.append(record)

    return {"records": unique_records, "nameservers": sorted(list(set(nameservers)))}


def query_nslookup(domain):
    record_types = ["NS", "MX", "TXT", "CNAME", "SOA"]
    all_records = []
    nameservers = []
    executed = False
    errors = []

    for record_type in record_types:
        result = run_shell_command(["nslookup", f"-type={record_type}", domain], timeout_seconds=15)
        if result["ok"]:
            executed = True
            parsed = parse_nslookup_records(result["stdout"], record_type)
            all_records.extend(parsed["records"])
            nameservers.extend(parsed["nameservers"])
        elif result["returncode"] != 127:
            errors.append(f"{record_type}: {result['stderr']}")
        else:
            errors.append(result["stderr"])

    dedup_records = []
    seen = set()
    for record in all_records:
        key = (record["type"], record["value"])
        if key in seen:
            continue
        seen.add(key)
        dedup_records.append(record)

    return {
        "ok": executed,
        "records": dedup_records,
        "nameservers": sorted(list(set([item.rstrip(".") for item in nameservers]))),
        "message": "; ".join(errors),
    }


def extract_rdap_entity_name(entity):
    vcard = entity.get("vcardArray") or []
    card_entries = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list) else []
    for field in card_entries:
        if not isinstance(field, list) or len(field) < 4:
            continue
        key = str(field[0]).lower()
        if key == "fn":
            return str(field[3]).strip()
        if key == "org":
            value = field[3]
            if isinstance(value, list) and value:
                return str(value[0]).strip()
            return str(value).strip()
    return entity.get("handle") or "Unknown"


def fetch_rdap_domain_info(domain):
    endpoints = [
        f"https://rdap.org/domain/{domain}",
        f"https://rdap.verisign.com/com/v1/domain/{domain}",
        f"https://rdap.verisign.com/net/v1/domain/{domain}",
    ]
    default = {
        "ok": False,
        "registrar": "Unknown",
        "created": "Unknown",
        "expires": "Unknown",
        "organization": "Unknown",
        "status": [],
        "nameservers": [],
        "source": "",
        "message": "",
    }

    for endpoint in endpoints:
        try:
            req = urllib.request.Request(
                endpoint,
                headers={"User-Agent": "CyberProject-Recon/1.0", "Accept": "application/rdap+json, application/json"},
            )
            with urllib.request.urlopen(req, timeout=12) as response:
                payload = json.loads(response.read().decode("utf-8", errors="ignore"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as error:
            default["message"] = str(error)
            continue

        events = payload.get("events") or []
        created = "Unknown"
        expires = "Unknown"
        for event in events:
            action = str(event.get("eventAction", "")).lower()
            date = event.get("eventDate") or "Unknown"
            if action in {"registration", "registered"} and created == "Unknown":
                created = date
            if action in {"expiration", "expiry"} and expires == "Unknown":
                expires = date

        registrar = "Unknown"
        organization = "Unknown"
        entities = payload.get("entities") or []
        for entity in entities:
            roles = {str(role).lower() for role in (entity.get("roles") or [])}
            name = extract_rdap_entity_name(entity)
            if "registrar" in roles and registrar == "Unknown":
                registrar = name
            if ("registrant" in roles or "administrative" in roles) and organization == "Unknown":
                organization = name

        nameservers = []
        for ns in payload.get("nameservers") or []:
            name = ns.get("ldhName") or ""
            if name:
                nameservers.append(name.rstrip("."))

        return {
            "ok": True,
            "registrar": registrar,
            "created": created,
            "expires": expires,
            "organization": organization,
            "status": payload.get("status") or [],
            "nameservers": sorted(list(set(nameservers))),
            "source": endpoint,
            "message": "",
        }

    return default


def infer_port_risk(port, service):
    high_risk_ports = {23, 3306, 5432, 3389, 445}
    medium_risk_ports = {21, 25, 8080}
    service_name = (service or "").lower()

    if port in high_risk_ports or service_name in {"telnet", "mysql", "postgresql", "rdp", "smb"}:
        return "high"
    if port in medium_risk_ports or service_name in {"ftp", "smtp", "http-alt"}:
        return "medium"
    return "low"


def scan_ports(target, ports):
    results = []
    for port in ports:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))
            status = "OPEN" if result == 0 else "CLOSED"

            # Detect service safely
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "Unknown"

            results.append(
                {
                    "port": port,
                    "status": status,
                    "service": service,
                    "banner": f"{service} Server Ready" if status == "OPEN" else None,
                    "risk": infer_port_risk(port, service),
                }
            )
        except Exception:
            results.append({"port": port, "status": "ERROR", "service": "Unknown", "banner": None, "risk": "low"})
        finally:
            if s:
                s.close()
    return results


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400

    raw_ports = data.get("ports", [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306])
    if not isinstance(raw_ports, list):
        return jsonify({"error": "ports must be an array of integers"}), 400

    ports = []
    for value in raw_ports:
        try:
            port = int(value)
            if 1 <= port <= 65535:
                ports.append(port)
        except (TypeError, ValueError):
            continue

    if not ports:
        return jsonify({"error": "at least one valid port is required"}), 400

    results = []

    def worker():
        nonlocal results
        results = scan_ports(target, ports)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    return jsonify({"target": target, "results": results})

def map_vulnerabilities(service_name, port):
    service_name = (service_name or "").lower()
    if service_name in ["ftp", "telnet"]:
        return {"severity": "critical", "cvss": 9.0, "description": f"{service_name.upper()} is insecure", "remediation": "Disable or secure service"}
    if service_name in ["http", "https"]:
        return {"severity": "high", "cvss": 7.5, "description": f"Check web service on port {port} for outdated software", "remediation": "Update web server and apply security patches"}
    if service_name in ["ssh"]:
        return {"severity": "medium", "cvss": 5.0, "description": f"SSH running on port {port}", "remediation": "Ensure strong passwords and key-based auth"}
    return {"severity": "low", "cvss": 3.0, "description": f"{service_name or 'Unknown service'} detected", "remediation": "Check configuration"}

@app.route("/scan/vuln-scan", methods=["POST"])
def vuln_scan():
    data = request.get_json()
    target = data.get("target")
    if not target:
        return jsonify({"error": "Target is required"}), 400

    scan_id = str(uuid.uuid4())
    nm = nmap.PortScanner()
    try:
        # Run a SYN scan with service/version detection
        nm.scan(hosts=target, arguments='-sV -T4')
    except Exception as e:
        return jsonify({"error": f"Nmap scan failed: {str(e)}"}), 500

    results = []
    host_info = nm.all_hosts()
    for host in host_info:
        if 'tcp' not in nm[host]:
            continue
        for port in nm[host]['tcp']:
            port_data = nm[host]['tcp'][port]
            service_name = port_data.get('name')
            version = port_data.get('version')
            vuln_info = map_vulnerabilities(service_name, port)
            results.append({
                "port": port,
                "service": service_name,
                "version": version,
                "status": "OPEN",
                "severity": vuln_info["severity"],
                "cvss": vuln_info["cvss"],
                "description": vuln_info["description"],
                "remediation": vuln_info["remediation"]
            })

    response = {
        "id": scan_id,
        "target": target,
        "scan_type": "vulnerability",
        "status": "completed",
        "created_at": utc_now_iso(),
        "completed_at": utc_now_iso(),
        "results": results
    }

    return jsonify(response)


@app.route("/api/network-recon", methods=["POST"])
def network_recon():
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()
    scan_type = (payload.get("scan_type") or "subnet").strip().lower()

    if not target:
        return jsonify({"error": "target is required"}), 400
    if scan_type not in {"subnet", "domain"}:
        return jsonify({"error": "scan_type must be subnet or domain"}), 400

    if scan_type == "subnet":
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            return jsonify({"error": "invalid subnet format (example: 192.168.1.0/24)"}), 400

        nmap_ping = run_shell_command(["nmap", "-sn", target, "-oX", "-"], timeout_seconds=45)
        hosts = parse_nmap_xml(nmap_ping["stdout"]) if nmap_ping["ok"] else []

        if not hosts:
            # Fallback to python-nmap if command-line nmap is unavailable.
            nm = nmap.PortScanner()
            try:
                nm.scan(hosts=target, arguments="-sn")
                for host in nm.all_hosts():
                    addresses = nm[host].get("addresses", {})
                    mac = addresses.get("mac", "Unknown")
                    vendor_map = nm[host].get("vendor", {})
                    vendor = vendor_map.get(mac, "Unknown")
                    hostnames = nm[host].get("hostnames", [])
                    hostname = hostnames[0].get("name") if hostnames else "Unknown"
                    hosts.append(
                        {
                            "ip": host,
                            "hostname": hostname or "Unknown",
                            "mac": mac,
                            "vendor": vendor,
                            "open_ports": [],
                        }
                    )
            except Exception as error:
                return jsonify({"error": f"network reconnaissance failed: {str(error)}"}), 500

        return jsonify(
            {
                "target": target,
                "scan_type": "reconnaissance",
                "mode": "subnet",
                "created_at": utc_now_iso(),
                "results": {
                    "hosts": hosts,
                    "tooling": {
                        "nmap_cli": nmap_ping["ok"],
                        "nmap_cli_message": nmap_ping["stderr"] if not nmap_ping["ok"] else "",
                    },
                },
            }
        )

    # Domain reconnaissance
    try:
        ipv4_records = sorted({item[4][0] for item in socket.getaddrinfo(target, None, socket.AF_INET)})
    except socket.gaierror as error:
        return jsonify({"error": f"domain lookup failed: {str(error)}"}), 400

    try:
        ipv6_records = sorted({item[4][0] for item in socket.getaddrinfo(target, None, socket.AF_INET6)})
    except socket.gaierror:
        ipv6_records = []

    dns_records = [{"type": "A", "value": ip} for ip in ipv4_records]
    dns_records.extend({"type": "AAAA", "value": ip} for ip in ipv6_records)

    whois_result = run_shell_command(["whois", target], timeout_seconds=25)
    whois_data = parse_whois_output(whois_result["stdout"]) if whois_result["ok"] else {
        "registrar": "Unknown",
        "created": "Unknown",
        "expires": "Unknown",
        "organization": "Unknown",
        "whois_server": "Unknown",
        "status": [],
        "nameservers": [],
    }
    rdap_data = fetch_rdap_domain_info(target)
    nslookup_data = query_nslookup(target)
    dns_records.extend(nslookup_data["records"])

    dedup_dns = []
    seen_dns = set()
    for record in dns_records:
        key = (record.get("type", ""), record.get("value", ""))
        if key in seen_dns:
            continue
        seen_dns.add(key)
        dedup_dns.append(record)
    dns_records = dedup_dns

    nmap_fast_scan = run_shell_command(["nmap", "-F", target, "-oX", "-"], timeout_seconds=35)
    nmap_hosts = parse_nmap_xml(nmap_fast_scan["stdout"]) if nmap_fast_scan["ok"] else []
    open_ports = []
    if nmap_hosts:
        open_ports = nmap_hosts[0].get("open_ports", [])

    # Prefer WHOIS CLI, then RDAP, then nslookup for nameservers.
    merged_nameservers = whois_data["nameservers"] if whois_data["nameservers"] else rdap_data["nameservers"]
    if not merged_nameservers:
        merged_nameservers = nslookup_data["nameservers"]

    registrar = whois_data["registrar"] if whois_data["registrar"] != "Unknown" else rdap_data["registrar"]
    created = whois_data["created"] if whois_data["created"] != "Unknown" else rdap_data["created"]
    expires = whois_data["expires"] if whois_data["expires"] != "Unknown" else rdap_data["expires"]
    organization = whois_data["organization"] if whois_data["organization"] != "Unknown" else rdap_data["organization"]
    status = whois_data["status"] if whois_data["status"] else rdap_data["status"]

    domain = {
        "domain": target,
        "registrar": registrar,
        "created": created,
        "expires": expires,
        "organization": organization,
        "whois_server": whois_data["whois_server"],
        "status": status,
        "nameservers": merged_nameservers,
        "dnsRecords": dns_records,
        "openPorts": open_ports,
        "tooling": {
            "whois_cli": whois_result["ok"],
            "whois_message": whois_result["stderr"] if not whois_result["ok"] else "",
            "rdap_used": rdap_data["ok"],
            "rdap_source": rdap_data["source"],
            "rdap_message": rdap_data["message"],
            "nslookup_used": nslookup_data["ok"],
            "nslookup_message": nslookup_data["message"],
            "nmap_cli": nmap_fast_scan["ok"],
            "nmap_message": nmap_fast_scan["stderr"] if not nmap_fast_scan["ok"] else "",
        },
    }

    return jsonify(
        {
            "target": target,
            "scan_type": "reconnaissance",
            "mode": "domain",
            "created_at": utc_now_iso(),
            "results": {"domain": domain},
        }
    )


@app.route("/api/vulnerability-scan", methods=["POST"])
def vulnerability_scan():
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()

    if not target:
        return jsonify({"error": "target is required"}), 400

    vulnerabilities = []
    nmap_service_scan = run_shell_command(["nmap", "-sV", "-T4", target, "-oX", "-"], timeout_seconds=75)
    hosts = parse_nmap_xml(nmap_service_scan["stdout"]) if nmap_service_scan["ok"] else []

    if not hosts:
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=target, arguments="-sV -T4")
            for host in nm.all_hosts():
                if "tcp" not in nm[host]:
                    continue
                host_ports = []
                for port in sorted(nm[host]["tcp"].keys()):
                    port_data = nm[host]["tcp"][port]
                    if port_data.get("state") != "open":
                        continue
                    host_ports.append(
                        {
                            "port": port,
                            "protocol": "tcp",
                            "service": port_data.get("name") or "unknown",
                            "product": port_data.get("product") or "",
                            "version": port_data.get("version") or "unknown",
                        }
                    )
                hosts.append(
                    {
                        "ip": host,
                        "hostname": host,
                        "mac": "Unknown",
                        "vendor": "Unknown",
                        "open_ports": host_ports,
                    }
                )
        except Exception as error:
            return jsonify({"error": f"vulnerability scan failed: {str(error)}"}), 500

    finding_index = 1
    for host in hosts:
        for port_data in host.get("open_ports", []):
            service_name = port_data.get("service") or "unknown"
            version = port_data.get("version") or "unknown"
            port_number = int(port_data.get("port", 0))
            vuln_info = map_vulnerabilities(service_name, port_number)
            vulnerabilities.append(
                {
                    "id": f"AUTO-{finding_index:04d}",
                    "title": f"Potential exposure: {service_name.upper()} on port {port_number}",
                    "description": f"{vuln_info['description']} (detected version: {version})",
                    "severity": vuln_info["severity"],
                    "cvss": vuln_info["cvss"],
                    "remediation": vuln_info["remediation"],
                    "port": port_number,
                    "service": service_name,
                    "product": port_data.get("product", ""),
                    "host": host.get("ip", target),
                    "status": "OPEN",
                }
            )
            finding_index += 1

    return jsonify(
        {
            "target": target,
            "scan_type": "vulnerability",
            "created_at": utc_now_iso(),
            "results": {
                "total_checks": len(vulnerabilities),
                "vulnerabilities_found": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
                "tooling": {
                    "nmap_cli": nmap_service_scan["ok"],
                    "nmap_message": nmap_service_scan["stderr"] if not nmap_service_scan["ok"] else "",
                },
            },
        }
    )


@app.route("/api/scans", methods=["GET"])
def get_scans():
    with data_lock:
        store = load_store_unlocked()
    scans = sorted(store["scans"], key=lambda item: item.get("created_at", ""), reverse=True)
    return jsonify(scans)


@app.route("/api/scans", methods=["POST"])
def create_scan():
    payload = request.get_json(silent=True) or {}
    target = payload.get("target", "").strip()
    scan_type = payload.get("scan_type", "").strip()

    if not target or not scan_type:
        return jsonify({"error": "target and scan_type are required"}), 400

    scan = {
        "id": str(uuid.uuid4()),
        "scan_type": scan_type,
        "target": target,
        "status": payload.get("status", "running"),
        "results": payload.get("results") or {},
        "created_at": payload.get("created_at") or utc_now_iso(),
        "completed_at": payload.get("completed_at"),
    }

    with data_lock:
        store = load_store_unlocked()
        store["scans"].append(scan)
        save_store_unlocked(store)

    return jsonify(scan), 201


@app.route("/api/scans/<scan_id>", methods=["PATCH"])
def update_scan(scan_id):
    payload = request.get_json(silent=True) or {}
    mutable_fields = {"scan_type", "target", "status", "results", "completed_at"}

    with data_lock:
        store = load_store_unlocked()
        scan = next((item for item in store["scans"] if item.get("id") == scan_id), None)
        if not scan:
            return jsonify({"error": "scan not found"}), 404

        for key, value in payload.items():
            if key in mutable_fields:
                scan[key] = value

        save_store_unlocked(store)

    return jsonify(scan)


@app.route("/api/scans/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    with data_lock:
        store = load_store_unlocked()
        initial_count = len(store["scans"])
        store["scans"] = [item for item in store["scans"] if item.get("id") != scan_id]
        if len(store["scans"]) == initial_count:
            return jsonify({"error": "scan not found"}), 404
        save_store_unlocked(store)

    return "", 204

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
