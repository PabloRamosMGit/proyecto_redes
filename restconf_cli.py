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

    # Subcomando POST loopback (con sus propias opciones)
    sp_post = subparsers.add_parser("post-loopback", help="Create a Loopback interface.")
    sp_post.add_argument("--name", required=True, help="Loopback name (e.g. Loopback123)")
    sp_post.add_argument("--ip", help="IP /32 for the Loopback (optional, e.g. 10.123.123.123)")
    sp_post.add_argument("--desc", default="Created via RESTCONF", help="Loopback description")

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
    elif cmd == "post-loopback":
        post_loopback(args.host, auth, args.name, args.ip, args.desc, verify)
    elif cmd == "delete-loopback":
        delete_loopback(args.host, auth, args.name, verify)

if __name__ == "__main__":
    main()
