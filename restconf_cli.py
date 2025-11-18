#!/usr/bin/env python3
import argparse
import requests
import urllib3
import json
import sys

# Disable SSL warnings (equivalent to curl -k)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HOST = "10.10.20.48"
DEFAULT_USER = "developer"
DEFAULT_PASS = "C1sco12345"

ACCEPT_HDR = {"Accept": "application/yang-data+json"}
JSON_HDRS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json"
}

# ------------------------------------------
# Generic function for RESTCONF requests
# ------------------------------------------
def restconf_request(method, host, path, auth, data=None, verify=False, headers=None):
    url = f"https://{host}/restconf/data/{path}"
    headers = headers or ACCEPT_HDR
    try:
        if data is not None and isinstance(data, (dict, list)):
            data = json.dumps(data)
        r = requests.request(method, url, headers=headers, auth=auth,
                             data=data, verify=verify, timeout=30)
        return r
    except requests.exceptions.RequestException as e:
        print(f"Error de conexión: {e}")
        sys.exit(2)

def pretty_print(data):
    print(json.dumps(data, indent=2, ensure_ascii=False))

# ------------------------------------------
# Functions for each GET operation
# ------------------------------------------
def get_interfaces(host, auth, raw):
    path = "ietf-interfaces:interfaces-state/interface?fields=name;oper-status"
    r = restconf_request("GET", host, path, auth)
    if r.status_code != 200:
        print(f"Error ({r.status_code}): {r.text}")
        return
    interfaces = r.json().get("ietf-interfaces:interface", [])
    if raw:
        pretty_print(interfaces)
        return
    print("\nInterface Status:\n")
    for i in interfaces:
        print(f"{i['name']:24} -> {i['oper-status']}")

def get_interfaces_config(host, auth, raw):
    path = "ietf-interfaces:interfaces"
    r = restconf_request("GET", host, path, auth)
    if r.status_code != 200:
        print(f"Error ({r.status_code}): {r.text}")
        return
    if raw:
        pretty_print(r.json())
        return
    interfaces = r.json().get("ietf-interfaces:interfaces", {}).get("interface", [])
    print("\nInterface Configuration:\n")
    for i in interfaces:
        print(f"{i['name']:24} desc='{i.get('description','')}' enabled={i.get('enabled',True)}")

def get_routing(host, auth, raw):
    path = "ietf-routing:routing-state"
    r = restconf_request("GET", host, path, auth)
    if r.status_code == 200:
        if raw:
            pretty_print(r.json())
        else:
            print("\nRouting state (JSON completo):\n")
            pretty_print(r.json())
    else:
        print(f"Error ({r.status_code}): {r.text}")

def get_arp(host, auth, raw):
    path = "Cisco-IOS-XE-arp-oper:arp-data/arp-vrf"
    r = restconf_request("GET", host, path, auth)
    if r.status_code != 200:
        print(f"Error ({r.status_code}): {r.text}")
        return
    if raw:
        pretty_print(r.json())
        return
    print("\nARP Table:\n")
    vrfs = r.json().get("Cisco-IOS-XE-arp-oper:arp-vrf", [])
    for vrf in vrfs:
        for e in vrf.get("arp-oper", []):
            for entry in e.get("arp-entry", []):
                print(f"{entry['address']:16} {entry['hardware']:17} {entry['interface']}")

def get_cdp(host, auth, raw):
    path = "Cisco-IOS-XE-cdp-oper:cdp-neighbor-details"
    r = restconf_request("GET", host, path, auth)
    if r.status_code != 200:
        print(f"Error ({r.status_code}): {r.text}")
        return
    if raw:
        pretty_print(r.json())
        return
    print("\nCDP Neighbors:\n")
    neigh = r.json().get("Cisco-IOS-XE-cdp-oper:cdp-neighbor-details", {}).get("cdp-neighbor-detail", [])
    for n in neigh:
        print(f"{n['local-intf-name']:12} -> {n['device-id']:20} ({n['port-id']})")

def get_cpu(host, auth, raw):
    path = "Cisco-IOS-XE-process-cpu-oper:cpu-usage/cpu-utilization"
    r = restconf_request("GET", host, path, auth)
    if r.status_code != 200:
        print(f"Error ({r.status_code}): {r.text}")
        return
    cpu = r.json().get("Cisco-IOS-XE-process-cpu-oper:cpu-utilization", {})
    if raw:
        pretty_print(cpu)
        return
    print(f"\nCPU Utilization: 5s={cpu.get('five-seconds')}%  1m={cpu.get('one-minute')}%  5m={cpu.get('five-minutes')}%")

def get_memory(host, auth, raw):
    path = "Cisco-IOS-XE-process-memory-oper:memory-usage-processes/memory-usage-process"
    r = restconf_request("GET", host, path, auth)
    if r.status_code != 200:
        print(f"Error ({r.status_code}): {r.text}")
        return
    procs = r.json().get("Cisco-IOS-XE-process-memory-oper:memory-usage-process", [])
    if raw:
        pretty_print(procs)
        return
    print("\nMemory by Process:\n")
    for p in procs:
        print(f"{p['pid']:6} {p['name']:32} mem={p.get('allocated-memory','?')}")

def get_bgp(host, auth, raw):
    path = "Cisco-IOS-XE-bgp-oper:bgp-state-data"
    r = restconf_request("GET", host, path, auth)
    if r.status_code == 200:
        if raw:
            pretty_print(r.json())
        else:
            print("\nBGP State:\n")
            pretty_print(r.json())
    else:
        print(f"Error ({r.status_code}): {r.text}")

# ------------------------------------------
# QoS helpers (read/put/replicate)
# ------------------------------------------
def get_qos(host, auth, raw, yang_path=None):
    """Get QoS configuration/state via RESTCONF.

    yang_path: optional RESTCONF data path for QoS (module:path). If None,
    defaults to Cisco-IOS-XE-native:native/policy which shows only QoS
    policy configuration.
    """
    path = yang_path or "Cisco-IOS-XE-native:native/policy"
    r = restconf_request("GET", host, path, auth)
    if r.status_code == 204:
        print(f"No QoS policies configured on {host}")
        return None
    if r.status_code != 200:
        print(f"Error ({r.status_code}) getting QoS from {host}: {r.text}")
        return None
    if raw:
        pretty_print(r.json())
    return r.json()


def list_yang_modules(host, auth, raw, filter_kw=None):
    """List YANG modules advertised by the device (ietf-yang-library).

    If filter_kw is provided, only modules containing that substring
    (case-insensitive) will be printed.
    """
    path = "ietf-yang-library:modules-state/module"
    r = restconf_request("GET", host, path, auth)
    if r.status_code != 200:
        print(f"Error ({r.status_code}) getting YANG modules: {r.text}")
        return None
    data = r.json()
    modules = data.get("ietf-yang-library:module", []) or data.get("module", [])
    results = []
    for m in modules:
        name = m.get("name") or m.get("module-name") or ""
        rev = m.get("revision", "")
        entry = f"{name} {rev}".strip()
        if filter_kw:
            if filter_kw.lower() in entry.lower():
                results.append(entry)
        else:
            results.append(entry)
    if raw:
        pretty_print(modules)
    else:
        print("\nYANG modules:")
        for e in results:
            print(f" - {e}")
    return results


def auto_probe_qos(host, auth, verify=False, filter_kw=None, max_modules=20):
    """Automatically discover QoS data containers by inspecting modules and probing generated paths.

    - Queries the device YANG library for modules
    - Selects modules that match common QoS-related keywords (or an optional filter)
    - Generates a list of candidate data paths for each module and probes them
    """
    print("Querying device for YANG modules...")
    path = "ietf-yang-library:modules-state/module"
    r = restconf_request("GET", host, path, auth, verify=verify)
    if r is None or r.status_code != 200:
        print(f"Error ({getattr(r,'status_code', 'N/A')}) getting modules: {getattr(r,'text', '')}")
        return
    data = r.json()
    modules = data.get("ietf-yang-library:module") or data.get("module") or []

    # collect candidate module names
    candidates_modules = []
    for m in modules:
        name = m.get("name") or m.get("module-name")
        if not name:
            continue
        if filter_kw:
            if filter_kw.lower() in name.lower():
                candidates_modules.append(name)
        else:
            # common keywords often related to QoS
            kws = ["qos", "policy", "class", "service", "native", "policy-map"]
            if any(k in name.lower() for k in kws):
                candidates_modules.append(name)
        if len(candidates_modules) >= max_modules:
            break

    if not candidates_modules:
        print("No candidate modules found (try a different filter or check module list manually).")
        return

    print(f"Found {len(candidates_modules)} candidate modules: {', '.join(candidates_modules)}")
    print("\nProbing candidate paths (this may take a moment)...\n")

    # build candidate paths from each module
    path_templates = [
        ":qos",
        ":policy-maps",
        ":policy-maps/policy-map",
        ":policies",
        ":policy",
        ":class-maps",
        ":class-maps/class-map",
        ":service-policies",
        ":native",
        ":qos-oper",
        ":qos-state",
    ]

    found_any = False
    for mod in candidates_modules:
        for t in path_templates:
            candidate_path = f"{mod}{t}"
            r = restconf_request("GET", host, candidate_path, auth, verify=verify)
            if r and r.status_code == 200:
                found_any = True
                print(f"✓ SUCCESS: {candidate_path}")
                try:
                    data = r.json()
                    if isinstance(data, dict):
                        keys = list(data.keys())
                        print(f"  Top-level keys: {', '.join(keys)}")
                        if keys:
                            first = data[keys[0]]
                            if isinstance(first, list):
                                print(f"  {keys[0]}: list with {len(first)} elements")
                            else:
                                print(f"  {keys[0]}: {type(first).__name__}")
                except Exception:
                    pass
                print()
    
    if not found_any:
        print("No paths returned HTTP 200. The device may not expose QoS via RESTCONF at these paths.")
        print("Try: python3 restconf_cli.py list-modules --filter native")
        print("Then manually probe Cisco-IOS-XE-native:native or similar paths.")


def configure_qos(host, auth, class_name, policy_name, interface_name, 
                  bandwidth_percent=None, protocols=None, verify=False, 
                  yang_path=None, dry_run=False):
    """Configure QoS policy via RESTCONF on Cisco IOS-XE devices.
    
    Creates:
    - class-map with match protocols
    - policy-map with bandwidth allocation
    - service-policy applied to interface
    
    Args:
        host: Device IP/hostname
        auth: (username, password) tuple
        class_name: Name for the class-map
        policy_name: Name for the policy-map
        interface_name: Interface to apply service-policy (e.g., "GigabitEthernet2")
        bandwidth_percent: Bandwidth percentage to allocate (default: 50)
        protocols: List of protocols to match (default: ["http", "dns"])
        verify: SSL verification (default: False)
        yang_path: RESTCONF path (default: "Cisco-IOS-XE-native:native")
        dry_run: If True, only print payload without applying
    """
    if bandwidth_percent is None:
        bandwidth_percent = 50
    if protocols is None:
        protocols = ["http", "dns"]
    
    path = yang_path or "Cisco-IOS-XE-native:native"
    
    # Build QoS payload
    # Note: match protocol is not included due to YANG model limitations via RESTCONF
    # You can add protocol matches via CLI after creation
    payload = {
        "Cisco-IOS-XE-native:native": {
            "policy": {
                "Cisco-IOS-XE-policy:class-map": [
                    {
                        "name": class_name,
                        "prematch": "match-any"
                    }
                ],
                "Cisco-IOS-XE-policy:policy-map": [
                    {
                        "name": policy_name,
                        "class": [
                            {
                                "name": class_name,
                                "action-list": [
                                    {
                                        "action-type": "bandwidth",
                                        "bandwidth": {
                                            "percent": bandwidth_percent
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        }
    }
    
    if dry_run:
        print("=== DRY RUN: QoS Configuration Payload ===")
        pretty_print(payload)
        print("\n=== Would apply service-policy to interface ===")
        print(f"Interface: {interface_name}")
        print(f"Service Policy: output {policy_name}")
        return
    
    # Step 1: Configure class-map and policy-map
    print(f"Configuring QoS on {host}...")
    print(f"  - Class-map: {class_name} (match-any)")
    print(f"  - Policy-map: {policy_name} (bandwidth: {bandwidth_percent}%)")
    print(f"  Note: Protocol matches ({', '.join(protocols)}) must be added via CLI")
    
    r = restconf_request("PATCH", host, path, auth, data=payload, 
                        verify=verify, headers=JSON_HDRS)
    
    if r.status_code not in [200, 201, 204]:
        print(f"Error ({r.status_code}) configuring QoS policy: {r.text}")
        return
    
    print("  ✓ QoS policy configured successfully")
    
    # Step 2: Apply service-policy to interface
    # Parse interface type and number
    interface_parts = interface_name.split()
    if len(interface_parts) == 1:
        # Try to split by number
        import re
        match = re.match(r'([a-zA-Z]+)(\d+)', interface_name)
        if match:
            iface_type = match.group(1)
            iface_num = match.group(2)
        else:
            print(f"Error: Invalid interface format '{interface_name}'")
            return
    else:
        iface_type = interface_parts[0]
        iface_num = interface_parts[1]
    
    # Map common interface type names
    iface_type_map = {
        "gi": "GigabitEthernet",
        "gigabitethernet": "GigabitEthernet",
        "te": "TenGigabitEthernet",
        "tengigabitethernet": "TenGigabitEthernet",
        "lo": "Loopback",
        "loopback": "Loopback",
    }
    iface_type_normalized = iface_type_map.get(iface_type.lower(), iface_type)
    
    interface_payload = {
        "Cisco-IOS-XE-native:native": {
            "interface": {
                iface_type_normalized: [
                    {
                        "name": iface_num,
                        "Cisco-IOS-XE-policy:service-policy": {
                            "output": policy_name
                        }
                    }
                ]
            }
        }
    }
    
    print(f"  - Applying service-policy to {iface_type_normalized}{iface_num}")
    
    r = restconf_request("PATCH", host, path, auth, data=interface_payload,
                        verify=verify, headers=JSON_HDRS)
    
    if r.status_code not in [200, 201, 204]:
        print(f"Error ({r.status_code}) applying service-policy to interface: {r.text}")
        return
    
    print(f"  ✓ Service-policy applied to {iface_type_normalized}{iface_num}")
    print("\n✓ QoS configuration completed successfully!")


def push_qos(host, auth, qos_payload, verify=False, yang_path=None):
    """Push QoS configuration via RESTCONF. Uses PATCH for incremental updates.

    Args:
        host: Device IP/hostname
        auth: (username, password) tuple
        qos_payload: Dictionary containing the QoS configuration
        verify: SSL verification (default: False)
        yang_path: RESTCONF path (default: "Cisco-IOS-XE-native:native")
    
    Returns:
        requests.Response object
    """
    path = yang_path or "Cisco-IOS-XE-native:native"
    r = restconf_request("PATCH", host, path, auth, data=qos_payload, verify=verify, headers=JSON_HDRS)
    return r


def replicate_qos(source_host, target_hosts, auth, verify=False, yang_path=None, dry_run=False):
    """Replicate QoS from source_host to each host in target_hosts.

    This function performs a GET on the source, optionally extracts the
    relevant subtree, and PUTs it to each target. It does not perform
    fine-grained diffs or transactional rollbacks — treat this as a
    simple replication helper and test in a lab first.
    
    If dry_run=True, prints the payload that would be sent without making changes.
    """
    print(f"Obtaining QoS from source {source_host}...")
    src = get_qos(source_host, auth, raw=False, yang_path=yang_path)
    if not src:
        print("Failed to obtain QoS from source — aborting replication.")
        return

    # Prepare payload for PATCH operation
    # get_qos returns: {"Cisco-IOS-XE-native:policy": {...}}
    # push_qos needs: {"Cisco-IOS-XE-native:native": {"policy": {...}}}
    if isinstance(src, dict):
        if "Cisco-IOS-XE-native:policy" in src:
            # Wrap it in the native container
            payload = {
                "Cisco-IOS-XE-native:native": {
                    "policy": src["Cisco-IOS-XE-native:policy"]
                }
            }
        else:
            # Use as-is if already wrapped or different structure
            payload = src
    else:
        payload = src

    if dry_run:
        print("\n[DRY-RUN MODE] Would send the following payload to each target:")
        pretty_print(payload)
        print(f"\nTargets: {', '.join(target_hosts)}")
        print(f"YANG path: {yang_path or 'Cisco-IOS-XE-native:native/policy'}")
        print("\nNo changes were made. Re-run without --dry-run to apply.")
        return

    for th in target_hosts:
        print(f"Pushing QoS to {th}...")
        r = push_qos(th, auth, payload, verify=verify, yang_path=yang_path)
        if r is None:
            print(f"No response from {th}")
            continue
        if r.status_code in (200, 201, 204):
            print(f"Successfully replicated QoS to {th} (HTTP {r.status_code}).")
        else:
            print(f"Failed to push to {th}: HTTP {r.status_code} - {r.text}")

# ------------------------------------------
# POST and DELETE Loopback (only change operations)
# ------------------------------------------
def post_loopback(host, auth, name, ip, desc, verify):
    payload = {
        "ietf-interfaces:interface": {
            "name": name,
            "type": "iana-if-type:softwareLoopback",
            "enabled": True,
            "description": desc
        }
    }
    if ip:
        payload["ietf-interfaces:interface"]["ietf-ip:ipv4"] = {
            "address": [{"ip": ip, "netmask": "255.255.255.255"}]
        }
    r = restconf_request("POST", host, "ietf-interfaces:interfaces", auth, data=payload, verify=verify, headers=JSON_HDRS)
    if r.status_code in (200, 201, 204):
        print(f"Loopback {name} created successfully.")
    else:
        print(f"Error ({r.status_code}): {r.text}")

def delete_loopback(host, auth, name, verify):
    r = restconf_request("DELETE", host, f"ietf-interfaces:interfaces/interface={name}", auth, verify=verify)
    if r.status_code in (200, 204):
        print(f"Loopback {name} deleted successfully.")
    else:
        print(f"Error ({r.status_code}): {r.text}")

# ------------------------------------------
# CLI with subcommands
# ------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="RESTCONF CLI for Cisco IOS XE — view status or create/delete Loopbacks.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Opciones globales (pueden ir antes del subcomando)
    parser.add_argument("--host", default=DEFAULT_HOST, help="Device IP or FQDN")
    parser.add_argument("--user", default=DEFAULT_USER, help="RESTCONF username")
    parser.add_argument("--password", default=DEFAULT_PASS, help="RESTCONF password")
    parser.add_argument("--raw", action="store_true", help="Print raw JSON response (unformatted).")
    parser.add_argument("--secure", action="store_true", help="Verify SSL certificate (disabled by default).")

    subparsers = parser.add_subparsers(dest="command", metavar="{get-interfaces,...}")

    # Subcomandos GET (sin args extra)
    subparsers.add_parser("get-interfaces", help="Show operational status of interfaces (up/down).")
    subparsers.add_parser("get-interfaces-config", help="Show interface configuration (IETF).")
    subparsers.add_parser("get-routing", help="View routing state.")
    subparsers.add_parser("get-arp", help="View ARP table.")
    subparsers.add_parser("get-cdp", help="View CDP neighbors.")
    subparsers.add_parser("get-lldp", help="View LLDP.")
    subparsers.add_parser("get-cpu", help="Show CPU usage.")
    subparsers.add_parser("get-memory", help="Show memory usage by process.")
    subparsers.add_parser("get-bgp", help="Show BGP state (oper).")
    
    # Subcomando get-qos
    sp_qget = subparsers.add_parser("get-qos", help="Get QoS configuration/state from the device.")
    sp_qget.add_argument("--yang-path", help="Optional RESTCONF data path for QoS (e.g. Cisco-IOS-XE-qos:qos)")
    
    # Subcomando list-modules
    sp_list = subparsers.add_parser("list-modules", help="List YANG modules advertised by the device (use --filter to narrow results).")
    sp_list.add_argument("--filter", help="Filter keyword to search module names/revisions (e.g. 'qos', 'native')")
    
    # Subcomando auto-probe-qos
    sp_auto = subparsers.add_parser("auto-probe-qos", help="Auto-discover QoS data nodes by scanning advertised modules and probing generated paths.")
    sp_auto.add_argument("--filter", help="Filter module names (substring) to narrow search, e.g. 'native' or 'qos'")
    sp_auto.add_argument("--max-modules", type=int, default=20, help="Maximum number of modules to consider when generating candidates")

    # Subcomando configure-qos
    sp_cfg = subparsers.add_parser("configure-qos", help="Configure QoS policy on a device (class-map, policy-map, service-policy).")
    sp_cfg.add_argument("--class-name", required=True, help="Name for the class-map (e.g., CLASE-CRITICA)")
    sp_cfg.add_argument("--policy-name", required=True, help="Name for the policy-map (e.g., POLITICA-QOS-DEMO)")
    sp_cfg.add_argument("--interface", required=True, help="Interface to apply service-policy (e.g., GigabitEthernet2 or Gi2)")
    sp_cfg.add_argument("--bandwidth-percent", type=int, default=50, help="Bandwidth percentage to allocate (default: 50)")
    sp_cfg.add_argument("--protocols", nargs='+', default=["http", "dns"], help="Protocols to match in class-map (space separated, default: http dns)")
    sp_cfg.add_argument("--yang-path", help="Optional RESTCONF data path (default: Cisco-IOS-XE-native:native)")
    sp_cfg.add_argument("--dry-run", action="store_true", help="Show configuration payload without applying")

    # Subcomando push-qos: envía un payload JSON desde archivo
    sp_push = subparsers.add_parser("push-qos", help="Push QoS configuration from a JSON file to a device.")
    sp_push.add_argument("--file", required=True, help="Path to JSON file containing QoS payload")
    sp_push.add_argument("--yang-path", help="Optional RESTCONF data path (default: Cisco-IOS-XE-native:native)")
    sp_push.add_argument("--dry-run", action="store_true", help="Show payload without applying")

    # Subcomando POST loopback (con sus propias opciones)
    sp_post = subparsers.add_parser("post-loopback", help="Create a Loopback interface.")
    sp_post.add_argument("--name", required=True, help="Loopback name (e.g. Loopback123)")
    sp_post.add_argument("--ip", help="IP /32 for the Loopback (optional, e.g. 10.123.123.123)")
    sp_post.add_argument("--desc", default="Created via RESTCONF", help="Loopback description")

    # Subcomando replicate-qos: obtiene QoS de un origen y lo replica a uno o más destinos
    sp_q = subparsers.add_parser("replicate-qos", help="Replicate QoS from a source router to one or more targets.")
    sp_q.add_argument("--source", required=True, help="Source host (IP or FQDN) to read QoS from")
    sp_q.add_argument("--targets", required=True, nargs='+', help="One or more target hosts to apply QoS to (space separated)")
    sp_q.add_argument("--yang-path", help="Optional RESTCONF data path for QoS (e.g. Cisco-IOS-XE-qos:qos)")
    sp_q.add_argument("--dry-run", action="store_true", help="Show what would be sent without making changes")

    # Subcomando DELETE loopback (con sus propias opciones)
    sp_del = subparsers.add_parser("delete-loopback", help="Delete a Loopback interface.")
    sp_del.add_argument("--name", required=True, help="Name of the Loopback to delete")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    auth = (args.user, args.password)
    verify = args.secure
    raw = args.raw
    cmd = args.command

    # Subcommand router
    if cmd == "get-interfaces":
        get_interfaces(args.host, auth, raw)
    elif cmd == "get-interfaces-config":
        get_interfaces_config(args.host, auth, raw)
    elif cmd == "get-routing":
        get_routing(args.host, auth, raw)
    elif cmd == "get-arp":
        get_arp(args.host, auth, raw)
    elif cmd == "get-cdp":
        get_cdp(args.host, auth, raw)
    elif cmd == "get-lldp":
        # Reuse LLDP handler for raw JSON output
        path = "ietf-lldp:lldp"
        r = restconf_request("GET", args.host, path, auth)
        if r.status_code != 200:
            print(f"Error ({r.status_code}): {r.text}")
        else:
            pretty_print(r.json() if raw else r.json())
    elif cmd == "get-cpu":
        get_cpu(args.host, auth, raw)
    elif cmd == "get-memory":
        get_memory(args.host, auth, raw)
    elif cmd == "get-bgp":
        get_bgp(args.host, auth, raw)
    elif cmd == "get-qos":
        yang_path = getattr(args, 'yang_path', None)
        res = get_qos(args.host, auth, raw, yang_path=yang_path)
        if res is not None and not raw:
            pretty_print(res)
    elif cmd == "list-modules":
        flt = getattr(args, 'filter', None)
        list_yang_modules(args.host, auth, raw, filter_kw=flt)
    elif cmd == "auto-probe-qos":
        flt = getattr(args, 'filter', None)
        maxm = getattr(args, 'max_modules', 20)
        auto_probe_qos(args.host, auth, verify=verify, filter_kw=flt, max_modules=maxm)
    elif cmd == "configure-qos":
        yang_path = getattr(args, 'yang_path', None)
        dry_run = getattr(args, 'dry_run', False)
        configure_qos(args.host, auth, args.class_name, args.policy_name, 
                     args.interface, bandwidth_percent=args.bandwidth_percent,
                     protocols=args.protocols, verify=verify, 
                     yang_path=yang_path, dry_run=dry_run)
    elif cmd == "push-qos":
        # Read JSON payload from file and push to device
        yang_path = getattr(args, 'yang_path', None) or "Cisco-IOS-XE-native:native"
        dry_run = getattr(args, 'dry_run', False)
        try:
            with open(args.file, 'r') as f:
                payload = json.load(f)
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found.")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in '{args.file}': {e}")
            sys.exit(1)
        
        if dry_run:
            print(f"=== DRY RUN: Would push to {args.host} at path {yang_path} ===")
            pretty_print(payload)
        else:
            print(f"Pushing QoS configuration from '{args.file}' to {args.host}...")
            r = push_qos(args.host, auth, payload, verify=verify, yang_path=yang_path)
            if r.status_code in [200, 201, 204]:
                print(f"✓ Successfully pushed QoS configuration (HTTP {r.status_code})")
            else:
                print(f"✗ Error ({r.status_code}): {r.text}")
    elif cmd == "post-loopback":
        post_loopback(args.host, auth, args.name, args.ip, args.desc, verify)
    elif cmd == "delete-loopback":
        delete_loopback(args.host, auth, args.name, verify)
    elif cmd == "replicate-qos":
        # Read QoS from source and push to targets
        yang_path = getattr(args, 'yang_path', None)
        dry_run = getattr(args, 'dry_run', False)
        replicate_qos(args.source, args.targets, auth, verify=verify, yang_path=yang_path, dry_run=dry_run)

if __name__ == "__main__":
    main()
