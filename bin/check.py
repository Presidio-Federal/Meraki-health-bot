#!/usr/bin/env python3
"""Meraki Health check: read-only (GET only).

Usage:
  check.py --mode full      # deep health check -> findings JSON + draft report
  check.py --mode monitor   # quick threshold check; prints only NEW/CHANGED/RESOLVED problems or NOTHING_NEW
  check.py --mode weekly    # firmware, licenses, sensor batteries, WAN trend vs baseline

Reads /workspace/meraki/config.json (written by setup.py). State lives in /workspace/meraki/state/.
Override the home dir with env MERAKI_HOME.
Exit codes: 0 ok, 2 no config, 3 missing API key, 4 auth failure (401/403).
"""
import argparse, collections, datetime as dt, ipaddress, json, os, shutil, statistics as st, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mclient  # noqa: E402

HOME = os.environ.get("MERAKI_HOME", "/workspace/meraki")
CONFIG = os.path.join(HOME, "config.json")
STATE = os.path.join(HOME, "state")
RUNS = os.path.join(HOME, "runs")
WEEK = 604800

DEFAULT_THRESHOLDS = {
    "wan_loss_pct": 2.0,          # monitor: loss above this...
    "wan_latency_ms": 50.0,       # ...or latency above this...
    "wan_sustain_points": 4,      # ...in at least N of the last 5 one-minute samples
    "wifi_success_pct": 97.0,     # hourly connection success below this
    "wifi_min_attempts": 50,      # ...only if at least this many attempts
    "wifi_authfail_per_hour": 10, # WPA/802.1X auth failures in the last hour
    "ap_latency_ms": 30.0,        # full: per-AP best-effort latency average (7d)
    "util_24_pct": 50.0,          # full: 2.4 GHz channel utilization (7d avg)
    "util_5_pct": 40.0,
    "license_days": 60,
    "sensor_battery_pct": 20,
    "sensor_stale_hours": 24,
    "sensor_temp_f_max": 85,
    "trend_latency_pct": 25.0,    # weekly: 7d avg latency this much above baseline
    "trend_loss_pct": 0.5,        # weekly: 7d avg loss above this (absolute %)
}

IOT_HINTS = ["espressif", "tuya", "simplisafe", "ecobee", "ring", "nest", "google", "amazon", "wyze",
             "sonos", "roku", "chamberlain", "murata", "texas instruments", "quectel", "withings",
             "tesla", "lg innotek", "samsung", "philips", "signify", "lutron", "irobot", "shelly",
             "azurewave", "realtek", "hon hai", "belkin", "tp-link", "arlo", "eufy", "august",
             "rachio", "hue", "broadlink", "sunpower", "enphase", "rheem", "rinnai"]
PERSONAL_OS = ["ios", "iphone", "ipad", "mac os", "macos", "windows", "chrome os", "android"]


# ---------------------------------------------------------------- helpers
def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(ts):
    if not ts:
        return None
    try:
        return dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def local(ts):
    d = parse_ts(ts) if isinstance(ts, str) else ts
    return d.astimezone().strftime("%b %d %Y, %I:%M %p %Z") if d else None


def load_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1, default=str)
    os.replace(tmp, path)


def load_config():
    cfg = load_json(CONFIG)
    if not cfg or not cfg.get("network_id"):
        print("NO_CONFIG: run setup.py first (see SKILL.md 'First run').")
        sys.exit(2)
    th = dict(DEFAULT_THRESHOLDS)
    th.update(cfg.get("thresholds") or {})
    cfg["thresholds"] = th
    return cfg


class Collector:
    """Wraps mclient.get, records skipped endpoints, optionally saves raw JSON."""

    def __init__(self, raw_dir=None):
        self.raw_dir = raw_dir
        self.unavailable = []
        if raw_dir:
            os.makedirs(raw_dir, exist_ok=True)

    def get(self, name, path, params=None, allpages=False):
        d = mclient.get(path, params, allpages)
        if self.raw_dir:
            save_json(os.path.join(self.raw_dir, name + ".json"), d)
        if not mclient.ok(d):
            self.unavailable.append({"name": name, "path": path, "status": d["_error"],
                                     "reason": (d.get("_msg") or "")[:200]})
            return None
        return d


def dev_label(s):
    return f"{s.get('name') or s.get('mac') or s.get('serial')} ({s.get('model')}, {s.get('serial')})"


def wan_history_stats(hist):
    pts = [x for x in (hist or []) if x.get("latencyMs") is not None]
    if not pts:
        return None
    loss = [x.get("lossPercent") or 0 for x in pts]
    lat = sorted(x["latencyMs"] for x in pts)
    jit = [x["jitter"] for x in pts if x.get("jitter") is not None]
    return {"points": len(pts), "loss_avg_pct": round(st.mean(loss), 3), "loss_max_pct": round(max(loss), 2),
            "hours_loss_over_1pct": sum(1 for v in loss if v > 1),
            "latency_avg_ms": round(st.mean(lat), 1), "latency_p95_ms": round(lat[int(0.95 * (len(lat) - 1))], 1),
            "latency_max_ms": round(lat[-1], 1),
            "jitter_avg_ms": round(st.mean(jit), 2) if jit else None,
            "from": pts[0].get("startTs"), "to": pts[-1].get("endTs")}


def psu_problem(ps):
    """True if a PSU slot needs attention. An empty slot (status 'disconnected'/'not connected'
    with no serial) is normal on single-PSU installs and is ignored."""
    stt = (ps.get("status") or "").lower()
    if stt in ("powering", ""):
        return False
    if stt in ("disconnected", "not connected") and not ps.get("serial"):
        return False
    return True


def appliance_serials(statuses):
    return [s["serial"] for s in statuses or [] if s.get("productType") == "appliance"
            and s.get("status") in ("online", "alerting")]


def wan_baseline(cfg):
    """7-day WAN stats per appliance to 8.8.8.8 (used by setup and weekly)."""
    O, N = cfg["org_id"], cfg["network_id"]
    sts = mclient.get(f"/organizations/{O}/devices/statuses", {"networkIds[]": N, "perPage": 1000}, True)
    out = {}
    for s in appliance_serials(sts if mclient.ok(sts) else []):
        h = mclient.get(f"/devices/{s}/lossAndLatencyHistory", {"ip": "8.8.8.8", "timespan": WEEK, "resolution": 3600})
        if mclient.ok(h):
            stats = wan_history_stats(h)
            if stats:
                out[s] = stats
    return out


def known_client_macs(cfg, timespan=2592000):
    d = mclient.get(f"/networks/{cfg['network_id']}/clients", {"timespan": timespan, "perPage": 1000}, True)
    return sorted({c["mac"].lower() for c in d if c.get("mac")}) if mclient.ok(d) else None


def tracked_devices(cfg):
    d = mclient.get(f"/organizations/{cfg['org_id']}/devices/statuses", {"networkIds[]": cfg["network_id"], "perPage": 1000}, True)
    if not mclient.ok(d):
        return None
    # offline = recently seen (not yet dormant), so it is still a device we care about
    return sorted(s["serial"] for s in d if s.get("status") in ("online", "alerting", "offline"))


# ---------------------------------------------------------------- findings
class Findings:
    SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

    def __init__(self):
        self.items = []
        self.metrics = {}

    def add(self, sev, area, title, evidence, where=None, fix=None):
        self.items.append({"severity": sev, "area": area, "title": title, "evidence": evidence,
                           "dashboard": where, "fix": fix})

    def sorted(self):
        return sorted(self.items, key=lambda x: self.SEV_ORDER.get(x["severity"], 9))


ALERT_TYPES_BY_PRODUCT = {
    "appliance": ["applianceDown", "ipConflict", "rogueDhcp", "dhcpNoLeases", "failoverEvent"],
    "wireless": ["repeaterDown"],
    "switch": ["switchDown", "powerSupplyDown", "portDown"],
    "camera": ["cameraDown"],
    "sensor": ["sensorDown", "sensorBatteryPercentage"],
    "cellularGateway": ["cellularGatewayDown"],
    "_all": ["settingsChanged"],
}


def check_alerts(c, f, N, product_types):
    a = c.get("alerts_settings", f"/networks/{N}/alerts/settings")
    if not a:
        return
    wanted = set(ALERT_TYPES_BY_PRODUCT["_all"])
    for p in product_types:
        wanted |= set(ALERT_TYPES_BY_PRODUCT.get(p, []))
    by_type = {x["type"]: x for x in a.get("alerts", [])}
    disabled = sorted(t for t in wanted if t in by_type and not by_type[t].get("enabled"))
    enabled = sorted(x["type"] for x in a.get("alerts", []) if x.get("enabled"))
    dd = a.get("defaultDestinations") or {}
    has_default_dest = bool(dd.get("emails") or dd.get("allAdmins") or dd.get("httpServerIds") or dd.get("snmp"))
    f.metrics["alerts"] = {"enabled": enabled, "key_disabled": disabled, "default_destinations_set": has_default_dest}
    if disabled:
        sev = "high" if len(disabled) >= 3 else "medium"
        f.add(sev, "Firmware/alerting", f"{len(disabled)} key Dashboard alerts are disabled",
              f"Disabled: {', '.join(disabled)}. Enabled: {', '.join(enabled) or 'none'}.",
              "Network-wide > Configure > Alerts",
              "Enable device-down alerts (5-10 min timeout), power supply, sensor battery, rogue DHCP, IP conflict, DHCP exhaustion and settings-changed; send to email/app.")
    if not has_default_dest:
        f.add("medium", "Firmware/alerting", "Alerts have no default recipients",
              "defaultDestinations has no emails, admins, webhooks or SNMP.", "Network-wide > Configure > Alerts",
              "Set default recipients (All network admins or your email).")


def check_inventory(c, f, O, N, T):
    sts = c.get("device_statuses", f"/organizations/{O}/devices/statuses", {"networkIds[]": N, "perPage": 1000}, True) or []
    devs = c.get("devices", f"/organizations/{O}/devices", {"networkIds[]": N, "perPage": 1000}, True) or []
    cnt = collections.Counter(s.get("status") for s in sts)
    f.metrics["devices"] = {"total": len(sts), "by_status": dict(cnt),
                            "list": [{"serial": s["serial"], "name": s.get("name"), "model": s.get("model"),
                                      "status": s.get("status"), "lastReported": local(s.get("lastReportedAt"))} for s in sts]}
    for s in sts:
        if s.get("status") == "offline":
            f.add("high", "Inventory", f"Device offline: {dev_label(s)}",
                  f"Last reported {local(s.get('lastReportedAt'))}.", "Network-wide > Monitor > Devices / product device page",
                  "Check power/PoE and cabling; power-cycle the port or device.")
        elif s.get("status") == "alerting":
            f.add("high", "Inventory", f"Device alerting: {dev_label(s)}",
                  "Status 'alerting' (see health alerts / power supplies).", "Device status page", "Resolve the underlying alert.")
        for ps in (s.get("components") or {}).get("powerSupplies", []) or []:
            if psu_problem(ps):
                f.add("high", "Inventory", f"Power supply not powering on {dev_label(s)}",
                      f"Slot {ps.get('slot')} status '{ps.get('status')}', model '{ps.get('model') or 'unknown'}'.",
                      "Device status page", "Check AC cord/circuit and module seating; replace the PSU if faulty.")
    dormant = [s for s in sts if s.get("status") == "dormant"]
    if dormant:
        f.add("low", "Inventory", f"{len(dormant)} dormant devices clutter the network",
              "Dormant: " + ", ".join(dev_label(s) for s in dormant[:20]) + (" ..." if len(dormant) > 20 else ""),
              "Organization > Configure > Inventory", "Remove retired hardware from the network so status and alerts reflect reality.")
    # firmware mismatch per device
    for d in devs:
        s = next((x for x in sts if x["serial"] == d["serial"]), {})
        if s.get("status") in ("online", "alerting") and d.get("firmware") == "Not running configured version":
            f.add("medium", "Firmware/alerting", f"Device not running configured firmware: {dev_label(s)}",
                  "firmware = 'Not running configured version'.", "Network-wide > General > Firmware upgrades", "Check upgrade status / model support.")
    ha = c.get("health_alerts", f"/networks/{N}/health/alerts")
    if ha:
        f.metrics["health_alerts"] = [{"type": x.get("type"), "severity": x.get("severity"), "category": x.get("category"),
                                       "devices": [d.get("name") or d.get("serial") for d in (x.get("scope") or {}).get("devices", [])]} for x in ha]
    ch = c.get("availability_changes", f"/organizations/{O}/devices/availabilities/changeHistory",
               {"networkIds[]": N, "timespan": WEEK, "perPage": 1000})
    if ch:
        flaps = collections.Counter(x["device"]["serial"] for x in ch
                                    if any(v.get("value") == "offline" for v in x.get("details", {}).get("new", [])))
        f.metrics["offline_transitions_7d"] = dict(flaps)
    return sts, devs


def check_wan(c, f, O, N, sts, T):
    up = c.get("appliance_uplink_statuses", f"/organizations/{O}/appliance/uplink/statuses", {"networkIds[]": N, "perPage": 1000})
    active = []
    if up:
        for a in up:
            for u in a.get("uplinks", []):
                if u.get("status") == "active":
                    active.append(f"{a['serial']}:{u['interface']}")
        f.metrics["uplinks"] = [{"serial": a["serial"], "model": a.get("model"),
                                 "uplinks": [{k: u.get(k) for k in ("interface", "status", "publicIp", "ipAssignedBy")} for u in a.get("uplinks", [])]}
                                for a in up]
        if len(active) == 1:
            f.add("low", "WAN/uplink", "Single active WAN uplink (no failover)", f"Active uplinks: {len(active)}.",
                  "Security & SD-WAN > Monitor > Appliance status", "Optional: add a second ISP or cellular (MG / USB) for failover.")
    lat = c.get("uplinks_loss_latency_5min", f"/organizations/{O}/devices/uplinksLossAndLatency", {"timespan": 300})
    if lat:
        f.metrics["wan_last_5min"] = [{"serial": x["serial"], "uplink": x.get("uplink"), "ip": x.get("ip"),
                                       "loss_avg": round(st.mean([p["lossPercent"] for p in x["timeSeries"] if p.get("lossPercent") is not None] or [0]), 2),
                                       "latency_avg": round(st.mean([p["latencyMs"] for p in x["timeSeries"] if p.get("latencyMs") is not None] or [0]), 1)}
                                      for x in lat if x.get("networkId") == N and x.get("uplink")]
    wan7 = {}
    for s in appliance_serials(sts):
        h = c.get(f"loss_latency_7d_{s}", f"/devices/{s}/lossAndLatencyHistory", {"ip": "8.8.8.8", "timespan": WEEK, "resolution": 3600})
        stats = wan_history_stats(h) if h else None
        if stats:
            wan7[s] = stats
            if stats["loss_avg_pct"] > 0.5 or stats["hours_loss_over_1pct"] > 5:
                f.add("medium", "WAN/uplink", f"Elevated WAN packet loss on {s}",
                      f"7d avg loss {stats['loss_avg_pct']}%, worst hour {stats['loss_max_pct']}%, {stats['hours_loss_over_1pct']} hours >1%.",
                      "Security & SD-WAN > Monitor > Appliance status > Uplink", "Check modem/ISP line quality; open an ISP ticket with this evidence.")
            if stats["latency_p95_ms"] > T["wan_latency_ms"]:
                f.add("medium", "WAN/uplink", f"High WAN latency on {s}",
                      f"7d p95 latency {stats['latency_p95_ms']} ms (avg {stats['latency_avg_ms']} ms).",
                      "Security & SD-WAN > Monitor > Appliance status > Uplink", "Check for bufferbloat; set real uplink bandwidth and enable traffic shaping.")
        c.get(f"appliance_performance_{s}", f"/devices/{s}/appliance/performance", {"timespan": WEEK})
    f.metrics["wan_7d"] = wan7
    bw = c.get("uplink_bandwidth", f"/networks/{N}/appliance/trafficShaping/uplinkBandwidth")
    if bw:
        f.metrics["uplink_bandwidth_kbps"] = bw.get("bandwidthLimits")
        lims = [v.get("limitDown") for k, v in (bw.get("bandwidthLimits") or {}).items() if k.startswith("wan") and v.get("limitDown")]
        if lims and max(lims) >= 5_000_000:
            f.add("low", "WAN/uplink", "Uplink bandwidth limits are not set to real ISP speeds",
                  f"Configured WAN limits (kbps): {bw.get('bandwidthLimits')}.",
                  "Security & SD-WAN > SD-WAN & traffic shaping > Uplink configuration",
                  "Enter actual ISP up/down speeds so traffic shaping/QoS works.")
    c.get("uplink_selection", f"/networks/{N}/appliance/trafficShaping/uplinkSelection")
    rules = c.get("traffic_shaping_rules", f"/networks/{N}/appliance/trafficShaping/rules")
    if rules is not None and not rules.get("rules"):
        f.add("info", "WAN/uplink", "No custom traffic-shaping rules", "Only default rules are active.",
              "Security & SD-WAN > SD-WAN & traffic shaping", "Optionally prioritize voice/video conferencing.")
    c.get("warm_spare", f"/networks/{N}/appliance/warmSpare")


def _nets(cidr_field):
    out = []
    for part in str(cidr_field or "").split(","):
        part = part.strip()
        if not part or part.lower() == "any":
            continue
        try:
            out.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            pass
    return out


def check_security(c, f, N, T):
    l3 = c.get("fw_l3", f"/networks/{N}/appliance/firewall/l3FirewallRules")
    c.get("fw_l7", f"/networks/{N}/appliance/firewall/l7FirewallRules")
    c.get("fw_inbound", f"/networks/{N}/appliance/firewall/inboundFirewallRules")
    pf = c.get("port_forwarding", f"/networks/{N}/appliance/firewall/portForwardingRules")
    nat11 = c.get("one_to_one_nat", f"/networks/{N}/appliance/firewall/oneToOneNatRules")
    svc = c.get("firewalled_services", f"/networks/{N}/appliance/firewall/firewalledServices")
    ips = c.get("intrusion", f"/networks/{N}/appliance/security/intrusion")
    amp = c.get("malware", f"/networks/{N}/appliance/security/malware")
    cf = c.get("content_filtering", f"/networks/{N}/appliance/contentFiltering")
    vs = c.get("vlans_settings", f"/networks/{N}/appliance/vlans/settings")
    vlans = c.get("vlans", f"/networks/{N}/appliance/vlans") if (vs or {}).get("vlansEnabled") else None
    if vs and not vs.get("vlansEnabled"):
        c.get("single_lan", f"/networks/{N}/appliance/singleLan")
    ev = c.get("security_events_7d", f"/networks/{N}/appliance/security/events", {"timespan": WEEK, "perPage": 1000})
    for name, p in (("syslog", "/syslogServers"), ("snmp", "/snmp"), ("netflow", "/netflow")):
        c.get(name, f"/networks/{N}{p}")
    syslog = load_json(os.path.join(c.raw_dir, "syslog.json")) if c.raw_dir else None

    if ev is not None:
        f.metrics["security_events_7d"] = len(ev)
        if ev:
            types = collections.Counter(e.get("eventType") or e.get("type") for e in ev)
            f.add("high", "Security", f"{len(ev)} IDS/AMP security events in 7 days", f"By type: {dict(types)}.",
                  "Security & SD-WAN > Monitor > Security center", "Review sources/destinations; isolate affected clients.")
    if ips is not None:
        f.metrics["ips"] = ips
        if ips.get("mode") != "prevention":
            f.add("medium", "Security", "Intrusion prevention is not in prevention mode", f"IDS mode: {ips.get('mode')}.",
                  "Security & SD-WAN > Configure > Threat protection", "Set Intrusion detection and prevention to Prevention.")
    if amp is not None:
        f.metrics["amp"] = amp.get("mode")
        if amp.get("mode") != "enabled":
            f.add("medium", "Security", "AMP malware protection disabled", f"AMP mode: {amp.get('mode')}.",
                  "Security & SD-WAN > Configure > Threat protection", "Enable AMP.")
    for r in (pf or {}).get("rules", []):
        if any(str(x).lower() == "any" for x in r.get("allowedIps", [])):
            f.add("medium", "Security", f"Port forward open to any source: {r.get('name') or ''} {r.get('protocol')}/{r.get('publicPort')}",
                  f"Forwards public {r.get('protocol')} {r.get('publicPort')} -> {r.get('lanIp')}:{r.get('localPort')}, allowed IPs: any.",
                  "Security & SD-WAN > Configure > Firewall > Port forwarding",
                  "Restrict Allowed remote IPs, or replace with a VPN / vendor relay.")
    for r in (nat11 or {}).get("rules", []):
        for a in r.get("allowedInbound", []):
            if any(str(x).lower() == "any" for x in a.get("allowedIps", [])):
                f.add("medium", "Security", f"1:1 NAT open to any source: {r.get('name')}", json.dumps(a),
                      "Security & SD-WAN > Configure > Firewall > 1:1 NAT", "Restrict allowed remote IPs.")
    for s in svc or []:
        if s.get("service") == "web" and s.get("access") == "unrestricted":
            f.add("medium", "Security", "MX local status page reachable from the internet", "firewalledServices web = unrestricted.",
                  "Security & SD-WAN > Configure > Firewall > Layer 3 > Appliance services", "Set Web (local status & configuration) to None/blocked.")
    if cf is not None and not cf.get("blockedUrlCategories"):
        f.add("info", "Security", "No content-filtering categories blocked", "blockedUrlCategories is empty.",
              "Security & SD-WAN > Configure > Content filtering", "Optional: block malware/phishing categories.")
    if syslog is not None and not syslog.get("servers"):
        f.add("low", "Security", "No syslog server configured", "syslogServers is empty; no off-box logs.",
              "Network-wide > Configure > General > Reporting", "Optional: send logs to a syslog server.")
    # VLAN segmentation heuristic
    if vlans:
        subnets = {}
        for v in vlans:
            try:
                subnets[v["id"]] = ipaddress.ip_network(v["subnet"], strict=False)
            except (KeyError, ValueError):
                pass
        f.metrics["vlans"] = [{"id": v["id"], "name": v.get("name"), "subnet": v.get("subnet"),
                               "dhcp": v.get("dhcpHandling"), "dns": v.get("dnsNameservers")} for v in vlans]
        inter = stale = 0
        for r in (l3 or {}).get("rules", []):
            if r.get("comment") == "Default rule":
                continue
            src, dst = _nets(r.get("srcCidr")), _nets(r.get("destCidr"))
            dst_internal = [d for d in dst if any(d.overlaps(s) for s in subnets.values())]
            src_any = str(r.get("srcCidr", "")).strip().lower() == "any"
            src_internal = src_any or "VLAN(" in str(r.get("srcCidr")) or any(n.overlaps(v) for n in src for v in subnets.values())
            if r.get("policy") == "deny" and src_internal and (dst_internal or "VLAN(" in str(r.get("destCidr"))):
                inter += 1
            for n in src + dst:
                if n.is_private and not any(n.overlaps(s) for s in subnets.values()):
                    stale += 1
                    break
        f.metrics["l3_rules"] = {"count": len((l3 or {}).get("rules", [])), "inter_vlan_denies": inter, "rules_with_unknown_private_subnets": stale}
        if len(subnets) >= 2 and inter == 0:
            f.add("medium", "Security", "No inter-VLAN restrictions in the L3 firewall",
                  f"{len(subnets)} VLANs configured, 0 deny rules targeting internal subnets; final rule allows any.",
                  "Security & SD-WAN > Configure > Firewall > Layer 3",
                  "Add deny rules from IoT/guest/camera VLANs to trusted VLANs, allowing only needed flows.")
        if stale:
            f.add("low", "Security", f"{stale} L3 rules reference private subnets that match no VLAN",
                  "Likely stale rules.", "Security & SD-WAN > Configure > Firewall > Layer 3", "Review and remove stale rules.")
    return vlans


def check_wireless(c, f, O, N, sts, T):
    ssids = c.get("ssids", f"/networks/{N}/wireless/ssids") or []
    c.get("rf_profiles", f"/networks/{N}/wireless/rfProfiles")
    c.get("wireless_settings", f"/networks/{N}/wireless/settings")
    cs = c.get("connection_stats_7d", f"/networks/{N}/wireless/connectionStats", {"timespan": WEEK})
    fc = c.get("failed_connections_7d", f"/networks/{N}/wireless/failedConnections", {"timespan": WEEK})
    c.get("latency_stats_7d", f"/networks/{N}/wireless/latencyStats", {"timespan": WEEK})
    dl = c.get("device_latency_7d", f"/networks/{N}/wireless/devices/latencyStats", {"timespan": WEEK})
    cu = c.get("channel_util_7d", f"/organizations/{O}/wireless/devices/channelUtilization/byDevice",
               {"networkIds[]": N, "timespan": WEEK, "perPage": 1000})
    names = {s["serial"]: s.get("name") or s["serial"] for s in sts}
    for s in ssids:
        if not s.get("enabled"):
            continue
        n = s.get("name")
        if s.get("authMode") == "open" and s.get("splashPage") in (None, "None"):
            f.add("high", "Wireless", f"Open SSID without splash/encryption: {n}", f"authMode open, splash {s.get('splashPage')}.",
                  "Wireless > Configure > Access control", "Use WPA2/WPA3-PSK or enable OWE/enhanced open.")
        if s.get("authMode") in ("psk", "8021x-radius", "8021x-meraki") and s.get("wpaEncryptionMode") in ("WPA2 only", "WPA1 and WPA2", "WPA1 only"):
            f.add("low", "Wireless", f"SSID '{n}' uses {s.get('wpaEncryptionMode')} (no WPA3)",
                  f"802.11w: {s.get('dot11w')}.", "Wireless > Configure > Access control",
                  "Use WPA2/WPA3 transition mode with 802.11w optional (test legacy IoT first).")
        if not s.get("availableOnAllAps") and s.get("availabilityTags"):
            f.add("info", "Wireless", f"SSID '{n}' limited to APs tagged {s.get('availabilityTags')}",
                  "availableOnAllAps = false.", "Wireless > Configure > SSID availability", "Confirm this is intended.")
    f.metrics["ssids"] = [{k: s.get(k) for k in ("number", "name", "enabled", "authMode", "wpaEncryptionMode", "bandSelection",
                                                "visible", "availableOnAllAps", "ipAssignmentMode", "defaultVlanId")} for s in ssids if s.get("enabled")]
    if cs:
        fails = sum(cs.get(k, 0) for k in ("assoc", "auth", "dhcp", "dns"))
        tot = fails + cs.get("success", 0)
        pct = round(100 * cs.get("success", 0) / tot, 1) if tot else None
        f.metrics["wifi_connection_7d"] = dict(cs, success_pct=pct)
        if pct is not None and tot >= T["wifi_min_attempts"] and pct < T["wifi_success_pct"]:
            f.add("medium", "Wireless", f"Wi-Fi connection success {pct}% (7d)", json.dumps(cs), "Wireless > Monitor > Wireless health",
                  "Drill into the failing step (assoc/auth/DHCP/DNS).")
    if fc is not None:
        f.metrics["failed_connections_7d"] = {"total": len(fc),
                                              "by_step": dict(collections.Counter(x.get("failureStep") for x in fc)),
                                              "by_ap": {names.get(k, k): v for k, v in collections.Counter(x.get("serial") for x in fc).items()}}
    for d in dl or []:
        be = ((d.get("latencyStats") or {}).get("bestEffortTraffic") or {}).get("avg")
        if be is not None and be > T["ap_latency_ms"]:
            f.add("medium", "Wireless", f"High Wi-Fi latency on AP {names.get(d['serial'], d['serial'])}",
                  f"7d best-effort latency avg {be:.1f} ms (threshold {T['ap_latency_ms']} ms).",
                  "Wireless > Monitor > Wireless health > Latency", "Check AP placement, 2.4 GHz clients, interference, and power.")
    f.metrics["ap_latency_best_effort_7d"] = {names.get(d["serial"], d["serial"]): ((d.get("latencyStats") or {}).get("bestEffortTraffic") or {}).get("avg") for d in dl or []}
    util = {}
    for d in cu or []:
        for b in d.get("byBand", []):
            tot = (b.get("total") or {}).get("percentage")
            util.setdefault(names.get(d["serial"], d["serial"]), {})[b["band"]] = tot
            lim = T["util_24_pct"] if b["band"] == "2.4" else T["util_5_pct"]
            if tot is not None and tot > lim:
                f.add("medium", "Wireless", f"High {b['band']} GHz channel utilization on {names.get(d['serial'], d['serial'])}",
                      f"7d avg {tot}% (wifi {(b.get('wifi') or {}).get('percentage')}%, non-wifi {(b.get('nonWifi') or {}).get('percentage')}%).",
                      "Wireless > Configure > Radio settings", "Move clients to 5/6 GHz, lower 2.4 GHz power, restrict to channels 1/6/11.")
    f.metrics["channel_util_7d_pct"] = util
    radios = {}
    for s in sts:
        if s.get("productType") == "wireless" and s.get("status") in ("online", "alerting"):
            w = c.get(f"wireless_status_{s['serial']}", f"/devices/{s['serial']}/wireless/status")
            for b in (w or {}).get("basicServiceSets", []):
                if b.get("broadcasting"):
                    radios.setdefault(names.get(s["serial"]), {})[b.get("band")] = {"channel": b.get("channel"), "width": b.get("channelWidth"), "power": b.get("power")}
    f.metrics["radios"] = radios
    ch24 = collections.Counter(v.get("2.4 GHz", {}).get("channel") for v in radios.values() if v.get("2.4 GHz"))
    shared = {ch: n for ch, n in ch24.items() if n > 1}
    if shared and len(radios) <= 3:
        f.add("low", "Wireless", "APs share a 2.4 GHz channel", f"2.4 GHz channel counts: {dict(ch24)}.",
              "Wireless > Configure > Radio settings", "Use an RF profile limited to 1/6/11 with lower 2.4 GHz power.")


def check_switch(c, f, O, N, sts):
    for name, p in (("switch_settings", "/switch/settings"), ("switch_stp", "/switch/stp"),
                    ("switch_dhcp_server_policy", "/switch/dhcpServerPolicy"), ("switch_storm_control", "/switch/stormControl")):
        c.get(name, f"/networks/{N}{p}")
    dsp = load_json(os.path.join(c.raw_dir, "switch_dhcp_server_policy.json")) if c.raw_dir else None
    if isinstance(dsp, dict) and dsp.get("defaultPolicy") == "allow" and not dsp.get("allowedServers"):
        f.add("low", "Switch", "Switch DHCP server policy allows any DHCP server",
              "defaultPolicy allow, no allowed servers, alerts " + str((dsp.get("alerts") or {}).get("email", {}).get("enabled")),
              "Switching > Configure > DHCP servers & ARP", "Allow only your router's DHCP server and enable alerts.")
    for s in sts:
        if s.get("productType") != "switch" or s.get("status") not in ("online", "alerting"):
            continue
        ser = s["serial"]
        ps = c.get(f"switch_port_statuses_{ser}", f"/devices/{ser}/switch/ports/statuses", {"timespan": 86400}) or []
        pc = {p["portId"]: p for p in (c.get(f"switch_ports_{ser}", f"/devices/{ser}/switch/ports") or [])}
        errs, slow, noguard = [], [], 0
        for p in ps:
            e = [x for x in (p.get("errors") or []) if x != "Port disconnected"]
            if e or p.get("warnings"):
                errs.append(f"port {p['portId']}: {e + (p.get('warnings') or [])}")
            if p.get("status") == "Connected" and p.get("speed") in ("10 Mbps", "100 Mbps") and (p.get("lldp") or p.get("cdp")):
                nb = (p.get("lldp") or {}).get("systemName") or (p.get("cdp") or {}).get("deviceId")
                slow.append(f"port {p['portId']} ({nb}) at {p.get('speed')}")
            cfgp = pc.get(p["portId"], {})
            if cfgp.get("type") == "access" and cfgp.get("stpGuard") in ("disabled", None) and not p.get("isUplink"):
                noguard += 1
        if errs:
            f.add("medium", "Switch", f"Port errors/warnings on {dev_label(s)}", "; ".join(errs[:10]),
                  "Switching > Monitor > Switch ports", "Check cabling/SFPs; look at CRC and flapping ports.")
        if slow:
            f.add("low", "Switch", f"Links negotiating below 1 Gbps on {dev_label(s)}", "; ".join(slow),
                  "Switching > Monitor > Switch ports", "If the device is gigabit-capable, re-terminate/replace the cable.")
        if noguard:
            f.add("low", "Switch", f"{noguard} access ports without BPDU guard on {dev_label(s)}", "stpGuard disabled on access ports.",
                  "Switching > Configure > Switch ports", "Enable BPDU guard on edge/access ports.")


def check_firmware(c, f, N, devs, sts):
    fw = c.get("firmware_upgrades", f"/networks/{N}/firmwareUpgrades")
    out = {}
    if not fw:
        return out
    for prod, v in (fw.get("products") or {}).items():
        cur = v.get("currentVersion") or {}
        newer = [a for a in v.get("availableVersions", []) if a.get("releaseType") == "stable" and a.get("id") != cur.get("id")
                 and (a.get("releaseDate") or "") > (cur.get("releaseDate") or "")]
        out[prod] = {"current": cur.get("shortName"), "current_type": cur.get("releaseType"),
                     "newer_stable": [a.get("shortName") for a in newer], "next": (v.get("nextUpgrade") or {}).get("time") or None}
        if cur.get("releaseType") in ("candidate", "beta"):
            f.add("medium", "Firmware/alerting", f"{prod} runs a {cur.get('releaseType')} build ({cur.get('shortName')})",
                  f"Stable available: {', '.join(out[prod]['newer_stable']) or 'n/a'}.",
                  "Organization > Monitor > Firmware upgrades", "Schedule the latest stable release.")
        elif newer:
            f.add("low", "Firmware/alerting", f"{prod}: newer stable firmware available",
                  f"Running {cur.get('shortName')}; stable available {', '.join(out[prod]['newer_stable'])}.",
                  "Organization > Monitor > Firmware upgrades", "Schedule it for your upgrade window.")
    f.metrics["firmware"] = out
    f.metrics["upgrade_window"] = fw.get("upgradeWindow")
    return out


def check_licenses(c, f, O, devs, sts, T):
    org = c.get("organization", f"/organizations/{O}") or {}
    model = (org.get("licensing") or {}).get("model")
    f.metrics["licensing_model"] = model
    horizon = now_utc() + dt.timedelta(days=T["license_days"])
    serials = {d["serial"] for d in devs}
    exp = []
    if model == "per-device":
        lic = c.get("licenses", f"/organizations/{O}/licenses", {"perPage": 1000}, True) or []
        assigned = {l.get("deviceSerial") for l in lic if l.get("deviceSerial")}
        for l in lic:
            e = parse_ts(l.get("expirationDate"))
            if l.get("deviceSerial") in serials and e and e < horizon:
                exp.append(f"{l.get('licenseType')} on {l.get('deviceSerial')} expires {local(e)}")
        unused = collections.Counter(l.get("licenseType") for l in lic if l.get("state") == "unusedActive")
        f.metrics["licenses_unused_active"] = dict(unused)
        unlic = [s for s in sts if s.get("status") in ("online", "alerting") and s["serial"] not in assigned]
        if unlic:
            f.add("info", "Licensing", f"{len(unlic)} online devices show no assigned license in the API",
                  ", ".join(dev_label(s) for s in unlic[:15]), "Organization > Configure > License info",
                  "Verify coverage in License info (the API list may be incomplete).")
    elif model == "co-term":
        ov = c.get("licenses_overview", f"/organizations/{O}/licenses/overview") or {}
        e = parse_ts(str(ov.get("expirationDate", "")).replace(" UTC", "Z")) if ov.get("expirationDate") else None
        f.metrics["coterm_expiration"] = ov.get("expirationDate")
        if e and e < horizon:
            exp.append(f"Co-term license expires {ov.get('expirationDate')}")
    else:
        subs = c.get("subscriptions", "/administered/licensing/subscription/subscriptions", {"organizationIds[]": O}) or []
        for s in subs if isinstance(subs, list) else []:
            e = parse_ts(s.get("endDate"))
            if e and e < horizon:
                exp.append(f"Subscription {s.get('name') or s.get('subscriptionId')} ends {local(e)}")
    if exp:
        soon = any("expires" in x for x in exp)
        f.add("high" if soon else "medium", "Licensing", f"{len(exp)} license(s) expiring within {T['license_days']} days", "; ".join(exp),
              "Organization > Configure > License info", "Renew or assign an unused license before expiry.")
    return exp


def check_sensors(c, f, O, N, T, sts=None):
    names = {x["serial"]: x.get("name") or x["serial"] for x in sts or []}

    def lbl(serial):
        n = names.get(serial, serial)
        return n if n.lower().startswith("sensor") else f"Sensor {n}"
    rd = c.get("sensor_readings", f"/organizations/{O}/sensor/readings/latest", {"networkIds[]": N, "perPage": 100})
    if rd is None:
        return []
    probs = []
    stale_cut = now_utc() - dt.timedelta(hours=T["sensor_stale_hours"])
    for s in rd:
        r = {x["metric"]: x for x in s.get("readings", [])}
        last = max((parse_ts(x.get("ts")) for x in s.get("readings", []) if x.get("ts")), default=None)
        b = ((r.get("battery") or {}).get("battery") or {}).get("percentage")
        t = ((r.get("temperature") or {}).get("temperature") or {}).get("fahrenheit")
        bits = []
        if b is not None and b < T["sensor_battery_pct"]:
            bits.append(f"battery {b}%")
        if last and last < stale_cut:
            bits.append(f"no report since {local(last)}")
        if bits:
            probs.append(("low", f"{lbl(s['serial'])}: {', '.join(bits)}", f"last reading {local(last)}"))
        if t is not None and t > T["sensor_temp_f_max"]:
            probs.append(("info", f"{lbl(s['serial'])} reads {t} F", f"threshold {T['sensor_temp_f_max']} F"))
    for sev, title, ev in probs:
        f.add(sev, "Sensors", title, ev, "Sensors > Monitor", "Replace batteries / check placement; enable sensor alerts.")
    return probs


def check_clients(c, f, N, vlans):
    cl = c.get("clients_7d", f"/networks/{N}/clients", {"timespan": WEEK, "perPage": 1000}, True)
    if cl is None:
        return
    unnamed = [x for x in cl if not x.get("description")]
    byvlan = collections.defaultdict(lambda: {"total": 0, "iot": [], "personal": 0})
    for x in cl:
        v = str(x.get("vlan"))
        byvlan[v]["total"] += 1
        m = (x.get("manufacturer") or "").lower()
        o = (x.get("os") or "").lower()
        if any(h in m for h in IOT_HINTS) and not any(p in o for p in PERSONAL_OS):
            byvlan[v]["iot"].append(x.get("description") or x.get("manufacturer"))
        elif any(p in o for p in PERSONAL_OS):
            byvlan[v]["personal"] += 1
    usage = sum((x.get("usage") or {}).get("total", 0) for x in cl)
    f.metrics["clients_7d"] = {"total": len(cl), "wireless": sum(1 for x in cl if x.get("recentDeviceConnection") == "Wireless"),
                               "unnamed": len(unnamed), "usage_gb": round(usage / 1024 / 1024, 1),
                               "by_vlan": {k: {"total": v["total"], "iot_like": len(v["iot"]), "personal": v["personal"]} for k, v in byvlan.items()},
                               "top_users": [{"name": x.get("description") or x.get("manufacturer") or "unnamed",
                                              "gb": round((x.get("usage") or {}).get("total", 0) / 1024 / 1024, 1)}
                                             for x in sorted(cl, key=lambda x: -(x.get("usage") or {}).get("total", 0))[:5]]}
    mixed = [(k, v) for k, v in byvlan.items() if len(v["iot"]) >= 3 and v["personal"] >= 2]
    for k, v in mixed:
        f.add("medium", "Clients", f"IoT devices share VLAN {k} with phones/laptops",
              f"{len(v['iot'])} IoT-like devices (e.g. {', '.join(map(str, v['iot'][:8]))}) and {v['personal']} personal devices on VLAN {k}.",
              "Wireless > SSIDs (IoT SSID/VLAN) + Security & SD-WAN > Firewall", "Move IoT to its own SSID/VLAN and block IoT -> trusted.")
    if unnamed:
        f.add("low", "Clients", f"{len(unnamed)} clients have no name",
              "Unnamed: " + ", ".join(f"{x.get('manufacturer') or 'unknown'} ({x.get('mac')})" for x in unnamed[:12]),
              "Network-wide > Monitor > Clients", "Name known devices so new/unknown ones stand out.")


def check_events(c, f, N, product_types):
    if "appliance" not in product_types:
        return
    d = c.get("events_appliance", f"/networks/{N}/events", {"productType": "appliance", "perPage": 1000})
    if not d:
        return
    ev = d.get("events", [])
    cnt = collections.Counter(e.get("type") for e in ev)
    f.metrics["appliance_events"] = {"window": [local(d.get("pageStartAt")), local(d.get("pageEndAt"))], "counts": dict(cnt)}
    if cnt.get("martian_vlan", 0) > 50:
        srcs = collections.Counter((e.get("eventData") or {}).get("MAC") for e in ev if e.get("type") == "martian_vlan" and (e.get("eventData") or {}).get("MAC"))
        f.add("low", "Security", f"{cnt['martian_vlan']} 'Source IP/VLAN mismatch' events",
              f"Top source MACs: {dict(srcs.most_common(5))}.", "Network-wide > Monitor > Event log",
              "Check those devices for wrong VLAN/static IPs or self-assigned (169.254) addresses.")
    for t in ("rogue_dhcp", "dhcp_no_leases"):
        if cnt.get(t):
            f.add("medium", "Security", f"{cnt[t]} '{t}' events", "", "Network-wide > Monitor > Event log", "Investigate.")


# ---------------------------------------------------------------- modes
def draft_report(cfg, f, unavailable, path):
    items = f.sorted()
    hi = sum(1 for i in items if i["severity"] == "high")
    me = sum(1 for i in items if i["severity"] == "medium")
    dev = f.metrics.get("devices", {}).get("by_status", {})
    lines = [f"# Meraki health report: {cfg['network_name']}", "",
             f"_Generated {local(now_utc())} from read-only Dashboard API data._", "",
             "## Verdict", "",
             f"{hi} high and {me} medium findings. Devices: {dev}.", "",
             "## Top 5 fixes", ""]
    for i, x in enumerate(items[:5], 1):
        lines += [f"{i}. **{x['title']}** ({x['severity']}, {x['area']})", f"   - Evidence: {x['evidence']}",
                  f"   - Fix: {x['fix']}", f"   - Where: {x['dashboard']}"]
    lines += ["", "## Other findings", ""]
    for x in items[5:]:
        lines.append(f"- [{x['severity']}] {x['area']}: {x['title']}. {x['evidence']} -> {x['fix']} ({x['dashboard']})")
    lines += ["", "## Key metrics", "", "```json", json.dumps(f.metrics, indent=1, default=str)[:12000], "```", "",
              "## Could not check", ""]
    lines += [f"- {u['name']}: HTTP {u['status']} {u['reason']}" for u in unavailable] or ["- (none)"]
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


def mode_full(cfg):
    O, N, T = cfg["org_id"], cfg["network_id"], cfg["thresholds"]
    stamp = now_utc().strftime("%Y%m%dT%H%M%SZ")
    run = os.path.join(RUNS, stamp)
    c = Collector(os.path.join(run, "raw"))
    f = Findings()
    net = c.get("network", f"/networks/{N}") or {}
    pts = net.get("productTypes", [])
    check_alerts(c, f, N, pts)
    sts, devs = check_inventory(c, f, O, N, T)
    if "appliance" in pts:
        check_wan(c, f, O, N, sts, T)
        vlans = check_security(c, f, N, T)
        check_events(c, f, N, pts)
    else:
        vlans = None
    if "wireless" in pts:
        check_wireless(c, f, O, N, sts, T)
    if "switch" in pts:
        check_switch(c, f, O, N, sts)
    check_firmware(c, f, N, devs, sts)
    check_licenses(c, f, O, devs, sts, T)
    if "sensor" in pts:
        check_sensors(c, f, O, N, T, sts)
    check_clients(c, f, N, vlans)
    out = {"mode": "full", "generated": iso(now_utc()), "network": cfg["network_name"], "product_types": pts,
           "findings": f.sorted(), "metrics": f.metrics, "unavailable": c.unavailable}
    save_json(os.path.join(run, "findings.json"), out)
    save_json(os.path.join(STATE, "last_full.json"), out)
    draft_report(cfg, f, c.unavailable, os.path.join(run, "report_draft.md"))
    # retention: keep last 10 runs
    runs = sorted(os.listdir(RUNS))
    for old in runs[:-10]:
        shutil.rmtree(os.path.join(RUNS, old), ignore_errors=True)
    sev = collections.Counter(x["severity"] for x in f.items)
    print(json.dumps({"mode": "full", "findings_by_severity": dict(sev), "unavailable": len(c.unavailable),
                      "findings_json": os.path.join(run, "findings.json"),
                      "draft_report": os.path.join(run, "report_draft.md")}, indent=1))


def mode_monitor(cfg):
    O, N, T = cfg["org_id"], cfg["network_id"], cfg["thresholds"]
    path = os.path.join(STATE, "monitor_state.json")
    state = load_json(path, {}) or {}
    prev = state.get("active", {})
    tracked = set(state.get("tracked_devices") or [])
    known = set(state.get("known_clients") or load_json(os.path.join(STATE, "known_clients.json"), []) or [])
    cur, events, failed_sources = {}, [], set()

    def issue(key, sev, text):
        cur[key] = {"severity": sev, "text": text}

    # 1) devices + PSUs
    sts = mclient.get(f"/organizations/{O}/devices/statuses", {"networkIds[]": N, "perPage": 1000}, True)
    if mclient.ok(sts):
        for s in sts:
            st_ = s.get("status")
            if st_ in ("online", "alerting", "offline"):
                tracked.add(s["serial"])
            if s["serial"] in tracked and st_ in ("offline", "dormant"):
                issue(f"device_offline:{s['serial']}", "high", f"Device offline: {dev_label(s)}, last seen {local(s.get('lastReportedAt'))}")
            elif st_ == "alerting":
                issue(f"device_alerting:{s['serial']}", "high", f"Device alerting: {dev_label(s)}")
            for ps in (s.get("components") or {}).get("powerSupplies", []) or []:
                if psu_problem(ps):
                    issue(f"psu:{s['serial']}:{ps.get('slot')}", "high",
                          f"Power supply slot {ps.get('slot')} '{ps.get('status')}' on {dev_label(s)}")
    else:
        failed_sources |= {"device_offline", "device_alerting", "psu"}
        sts = []
    mx = [s["serial"] for s in sts if s.get("productType") == "appliance"]

    # 2) WAN loss/latency (last 5 min) + uplink state
    if mx:
        lat = mclient.get(f"/organizations/{O}/devices/uplinksLossAndLatency", {"timespan": 300})
        if mclient.ok(lat):
            for x in lat:
                if x.get("serial") not in mx or not x.get("uplink"):
                    continue
                pts = [p for p in x.get("timeSeries", []) if p.get("latencyMs") is not None or p.get("lossPercent") is not None]
                bad_loss = [p["lossPercent"] for p in pts if (p.get("lossPercent") or 0) > T["wan_loss_pct"]]
                bad_lat = [p["latencyMs"] for p in pts if (p.get("latencyMs") or 0) > T["wan_latency_ms"]]
                k = f"{x['serial']}:{x['uplink']}:{x.get('ip')}"
                if len(bad_loss) >= T["wan_sustain_points"]:
                    issue(f"wan_loss:{k}", "high", f"WAN loss on {x['uplink']} to {x.get('ip')}: {len(bad_loss)}/{len(pts)} min above {T['wan_loss_pct']}% (max {max(bad_loss)}%)")
                if len(bad_lat) >= T["wan_sustain_points"]:
                    issue(f"wan_latency:{k}", "medium", f"WAN latency on {x['uplink']} to {x.get('ip')}: {len(bad_lat)}/{len(pts)} min above {T['wan_latency_ms']} ms (max {max(bad_lat):.0f} ms)")
        else:
            failed_sources |= {"wan_loss", "wan_latency"}
        up = mclient.get(f"/organizations/{O}/appliance/uplink/statuses", {"networkIds[]": N, "perPage": 1000})
        if mclient.ok(up):
            base = set(state.get("active_uplinks") or [])
            now_active = {f"{a['serial']}:{u['interface']}" for a in up for u in a.get("uplinks", []) if u.get("status") == "active"}
            if not base:
                base = now_active
            for k in sorted(base - now_active):
                issue(f"uplink_down:{k}", "high", f"WAN uplink {k.split(':')[1]} on {k.split(':')[0]} is no longer active")
            state["active_uplinks"] = sorted(base | now_active)
        else:
            failed_sources.add("uplink_down")
        for s in sts:
            if s.get("usingCellularFailover"):
                issue(f"cellular_failover:{s['serial']}", "high", f"{dev_label(s)} is using cellular failover")

    # 3) Wi-Fi last hour
    cs = mclient.get(f"/networks/{N}/wireless/connectionStats", {"timespan": 3600})
    if mclient.ok(cs) and isinstance(cs, dict):
        fails = sum(cs.get(k, 0) for k in ("assoc", "auth", "dhcp", "dns"))
        tot = fails + cs.get("success", 0)
        if tot >= T["wifi_min_attempts"] and 100 * cs.get("success", 0) / tot < T["wifi_success_pct"]:
            issue("wifi_success_low", "medium", f"Wi-Fi connection success {100 * cs.get('success', 0) / tot:.1f}% in the last hour ({fails} failures of {tot})")
        if cs.get("auth", 0) > T["wifi_authfail_per_hour"]:
            issue("wifi_authfail", "medium", f"{cs.get('auth')} Wi-Fi auth failures in the last hour (possible wrong/guessed PSK)")
    elif not mclient.ok(cs) and cs.get("_error") not in (400, 404):
        failed_sources |= {"wifi_success_low", "wifi_authfail"}

    # 4) New clients (one-shot events, deduped via known list)
    cl = mclient.get(f"/networks/{N}/clients", {"timespan": 3600, "perPage": 1000}, True)
    if mclient.ok(cl):
        for x in cl:
            m = (x.get("mac") or "").lower()
            if m and m not in known:
                known.add(m)
                events.append(f"New client: {x.get('description') or 'unnamed'} | {x.get('manufacturer') or 'unknown vendor'} | "
                              f"os={x.get('os')} | mac={m} | ip={x.get('ip')} | vlan={x.get('vlan')} | ssid={x.get('ssid')} | first seen {local(x.get('firstSeen'))}")

    # 5) Security events since last check (one-shot)
    if mx:
        t0 = state.get("security_cursor") or iso(now_utc() - dt.timedelta(hours=1))
        se = mclient.get(f"/networks/{N}/appliance/security/events", {"t0": t0, "perPage": 1000}, True)
        if mclient.ok(se):
            newest = t0
            for e in se:
                ts = e.get("ts") or ""
                if ts <= t0:
                    continue
                newest = max(newest, ts)
                events.append(f"Security event: {e.get('eventType')} {e.get('message') or e.get('signature') or ''} "
                              f"src={e.get('srcIp')} dst={e.get('destIp')} client={e.get('clientName') or e.get('clientMac')} "
                              f"action={e.get('blocked') and 'blocked' or e.get('action')} at {local(ts)}")
            state["security_cursor"] = newest if newest != t0 else iso(now_utc())

    # carry over issues whose data source failed this run (don't falsely "resolve")
    for k, v in prev.items():
        if k.split(":")[0] in failed_sources and k not in cur:
            cur[k] = v
    for k, v in cur.items():
        v["first_seen"] = (prev.get(k) or {}).get("first_seen") or iso(now_utc())

    new = [k for k in cur if k not in prev]
    changed = [k for k in cur if k in prev and prev[k].get("severity") != cur[k]["severity"]]
    resolved = [k for k in prev if k not in cur]
    lines = [f"NEW [{cur[k]['severity']}] {cur[k]['text']}" for k in new]
    lines += [f"CHANGED [{cur[k]['severity']}] {cur[k]['text']}" for k in changed]
    lines += [f"RESOLVED {prev[k]['text']} (since {local(prev[k].get('first_seen'))})" for k in resolved]
    lines += [f"EVENT {e}" for e in events]
    if failed_sources:
        lines_note = f"(note: data unavailable this run for {sorted(failed_sources)}; prior issues carried over)"
    else:
        lines_note = None

    state.update({"active": cur, "tracked_devices": sorted(tracked), "known_clients": sorted(known), "last_run": iso(now_utc())})
    save_json(path, state)
    save_json(os.path.join(STATE, "monitor_last_output.json"), {"ts": iso(now_utc()), "lines": lines, "active_count": len(cur)})
    if lines:
        print("\n".join(lines))
        if lines_note:
            print(lines_note)
    else:
        print("NOTHING_NEW")


def mode_weekly(cfg):
    O, N, T = cfg["org_id"], cfg["network_id"], cfg["thresholds"]
    c = Collector(None)
    f = Findings()
    sts = c.get("device_statuses", f"/organizations/{O}/devices/statuses", {"networkIds[]": N, "perPage": 1000}, True) or []
    devs = c.get("devices", f"/organizations/{O}/devices", {"networkIds[]": N, "perPage": 1000}, True) or []
    net = c.get("network", f"/networks/{N}") or {}
    fw = check_firmware(c, f, N, devs, sts)
    lic = check_licenses(c, f, O, devs, sts, T)
    sens = check_sensors(c, f, O, N, T, sts) if "sensor" in net.get("productTypes", []) else []
    base = (cfg.get("baseline") or {}).get("wan_7d", {})
    trend = {}
    for s in appliance_serials(sts):
        h = c.get(f"wan_{s}", f"/devices/{s}/lossAndLatencyHistory", {"ip": "8.8.8.8", "timespan": WEEK, "resolution": 3600})
        now = wan_history_stats(h) if h else None
        b = base.get(s)
        if now:
            t = {"now": now, "baseline": b}
            if b and b.get("latency_avg_ms"):
                t["latency_change_pct"] = round(100 * (now["latency_avg_ms"] - b["latency_avg_ms"]) / b["latency_avg_ms"], 1)
                if t["latency_change_pct"] > T["trend_latency_pct"]:
                    f.add("medium", "WAN/uplink", f"WAN latency up {t['latency_change_pct']}% vs baseline on {s}",
                          f"7d avg {now['latency_avg_ms']} ms vs baseline {b['latency_avg_ms']} ms.", "Appliance status > Uplink", "Check ISP / bufferbloat.")
            if now["loss_avg_pct"] > T["trend_loss_pct"]:
                f.add("medium", "WAN/uplink", f"WAN loss {now['loss_avg_pct']}% (7d avg) on {s}", f"Worst hour {now['loss_max_pct']}%.",
                      "Appliance status > Uplink", "Open an ISP ticket.")
            trend[s] = t
    ch = c.get("availability_changes", f"/organizations/{O}/devices/availabilities/changeHistory", {"networkIds[]": N, "timespan": WEEK, "perPage": 1000}) or []
    flaps = collections.Counter(x["device"].get("name") or x["device"]["serial"] for x in ch
                                if any(v.get("value") == "offline" for v in x.get("details", {}).get("new", [])))
    mon = load_json(os.path.join(STATE, "monitor_state.json"), {}) or {}
    out = {"mode": "weekly", "generated": iso(now_utc()), "network": cfg["network_name"],
           "device_status": dict(collections.Counter(s.get("status") for s in sts)),
           "firmware": fw, "licenses_expiring": lic, "sensor_issues": [t for _, t, _ in sens],
           "wan_trend": trend, "offline_transitions_7d": dict(flaps),
           "open_monitor_issues": [v["text"] + f" (since {local(v.get('first_seen'))})" for v in (mon.get("active") or {}).values()],
           "findings": f.sorted(), "unavailable": c.unavailable}
    save_json(os.path.join(STATE, "weekly_last.json"), out)
    print(json.dumps(out, indent=1, default=str))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["full", "monitor", "weekly"], required=True)
    a = ap.parse_args()
    cfg = load_config()
    try:
        {"full": mode_full, "monitor": mode_monitor, "weekly": mode_weekly}[a.mode](cfg)
    except mclient.MissingKey:
        print("MISSING_KEY: MERAKI_API_KEY is not set. Ask the operator for it via a secure secret request named MERAKI_API_KEY.")
        sys.exit(3)
    except mclient.AuthError as e:
        print(f"AUTH_ERROR: {e}. Check the key and that Dashboard API access is enabled for the org. Not retrying.")
        sys.exit(4)


if __name__ == "__main__":
    main()
