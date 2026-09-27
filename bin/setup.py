#!/usr/bin/env python3
"""Meraki Health setup: pick the org/network to watch and record a baseline. Read-only (GET only).

  setup.py --check-key                       # exit 0 if a key is available (never prints it)
  setup.py --list                            # list orgs and their networks (JSON)
  setup.py --org <ORG_ID> --network <NAME_OR_ID> [--force]
                                             # write /workspace/meraki/config.json + seed state

Network names match case-insensitively. If the name is not in the given org, all orgs are searched
and the matches are reported (nothing is written). Exit codes: 0 ok, 1 usage/not found,
3 missing key, 4 auth failure.
"""
import argparse, collections, datetime as dt, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mclient  # noqa: E402
import check    # noqa: E402


def list_all():
    orgs = mclient.get("/organizations")
    if not mclient.ok(orgs):
        return {"error": orgs}
    out = []
    for o in orgs:
        nets = mclient.get(f"/organizations/{o['id']}/networks", {"perPage": 1000}, True)
        sts = mclient.get(f"/organizations/{o['id']}/devices/statuses", {"perPage": 1000}, True)
        per = collections.defaultdict(collections.Counter)
        for s in sts if mclient.ok(sts) else []:
            per[s.get("networkId")][s.get("status")] += 1
        out.append({"org_id": o["id"], "org_name": o["name"], "api_enabled": (o.get("api") or {}).get("enabled"),
                    "networks": [{"network_id": n["id"], "name": n["name"], "productTypes": n.get("productTypes"),
                                  "devices": dict(per.get(n["id"], {}))} for n in (nets if mclient.ok(nets) else [])]})
    return out


def find_network(org_id, needle):
    nets = mclient.get(f"/organizations/{org_id}/networks", {"perPage": 1000}, True)
    if not mclient.ok(nets):
        return None, nets
    n = needle.strip().lower()
    for x in nets:
        if x["id"].lower() == n or x["name"].strip().lower() == n:
            return x, None
    return None, None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check-key", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--org")
    ap.add_argument("--network")
    ap.add_argument("--force", action="store_true", help="overwrite an existing config")
    a = ap.parse_args()
    try:
        if a.check_key:
            ok = mclient.key_available()
            print("KEY_PRESENT" if ok else "MISSING_KEY")
            sys.exit(0 if ok else 3)
        if a.list:
            print(json.dumps(list_all(), indent=1))
            return
        if not (a.org and a.network):
            ap.print_help()
            sys.exit(1)
        existing = check.load_json(check.CONFIG)
        if existing and not a.force:
            print(f"CONFIG_EXISTS: {check.CONFIG} already targets '{existing.get('network_name')}'. Use --force to replace it.")
            sys.exit(1)
        org = mclient.get(f"/organizations/{a.org}")
        if not mclient.ok(org):
            print(f"ORG_NOT_FOUND: {a.org} ({org.get('_error')})")
            sys.exit(1)
        net, err = find_network(a.org, a.network)
        if not net:
            hits = []
            for o in mclient.get("/organizations"):
                x, _ = find_network(o["id"], a.network)
                if x:
                    hits.append({"org_id": o["id"], "org_name": o["name"], "network_id": x["id"], "name": x["name"]})
            print(json.dumps({"NETWORK_NOT_FOUND_IN_ORG": a.org, "matches_in_other_orgs": hits}, indent=1))
            sys.exit(1)
        cfg = {"org_id": a.org, "org_name": org.get("name"), "network_id": net["id"], "network_name": net["name"],
               "product_types": net.get("productTypes"), "timezone": net.get("timeZone"),
               "created": check.iso(check.now_utc()), "thresholds": dict(check.DEFAULT_THRESHOLDS)}
        cfg["baseline"] = {"created": cfg["created"], "wan_7d": check.wan_baseline(cfg)}
        known = check.known_client_macs(cfg) or []
        tracked = check.tracked_devices(cfg) or []
        cfg["baseline"].update({"known_clients_30d": len(known), "tracked_devices": len(tracked)})
        check.save_json(check.CONFIG, cfg)
        os.makedirs(check.STATE, exist_ok=True)
        check.save_json(os.path.join(check.STATE, "known_clients.json"), known)
        check.save_json(os.path.join(check.STATE, "monitor_state.json"),
                        {"active": {}, "tracked_devices": tracked, "known_clients": known, "created": cfg["created"]})
        print(json.dumps({"CONFIG_WRITTEN": check.CONFIG, "org": cfg["org_name"], "network": cfg["network_name"],
                          "product_types": cfg["product_types"], "baseline": cfg["baseline"]}, indent=1))
    except mclient.MissingKey:
        print("MISSING_KEY: MERAKI_API_KEY is not set. Ask the operator for it via a secure secret request named MERAKI_API_KEY.")
        sys.exit(3)
    except mclient.AuthError as e:
        print(f"AUTH_ERROR: {e}. Check the key and that Dashboard API access is enabled (Organization > Settings). Not retrying.")
        sys.exit(4)


if __name__ == "__main__":
    main()
