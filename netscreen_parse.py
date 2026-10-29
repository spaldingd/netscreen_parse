#!/usr/bin/env python3
"""
netscreen_parse.py - Extract objects and rulebases from Juniper NetScreen / ScreenOS (SSG, ISG,
NetScreen-5000 series) "get config" output and write them to CSV.

Standard library only (Python 3.8+).

Usage:
    python netscreen_parse.py config.txt [-o output] [--expand] [--max-expand N] [--strict]
                              [--csv-nl-sep STR] [--extra-services FILE]
    python netscreen_parse.py --selftest          # run against the embedded sample config

Each run writes to <output>/<YYYY-MM-DD_HH-MM-SS>/ (a new folder per run; add "output/" to
.gitignore):
    objects.csv            addresses, address groups, services, service groups, DIP pools,
                           schedulers (one row per object)
    object_members.csv     direct and fully-resolved members of every group
    rules_security-policy.csv   one row per policy
    rules_nat-mip.csv      Mapped IP (static NAT) entries      (if present)
    rules_nat-vip.csv      Virtual IP (port forwarding) entries (if present)
    rules_expanded.csv     (--expand) policies: one row per src x dst x service
    warnings.csv           unresolved references, cycles, duplicates, unparsed lines

Virtual systems: each "set vsys" ... "exit" block is parsed as its own logical system with its own
address books, services, DIP pools, schedulers and policies (policy IDs restart per vsys).  Every CSV
has a leading logical_system column; it is blank for the root config (change with --root-name).

Input notes
  * Use the output of `get config` (a list of "set ..." commands).  Real Junos "display set"
    output (set security ... / set interfaces ...) is detected and rejected.
  * Prompt lines, "Total Config size" and "--- more ---" lines are ignored.
  * Address books are per zone: a policy's source is looked up in its from-zone book and its
    destination in its to-zone book.
  * Policies are numbered in file order within each zone pair; the ScreenOS policy ID is kept
    in its own column.
"""
import argparse
import csv
import ipaddress
import itertools
import os
import re
import sys
from datetime import datetime

TOOL_VERSION = "0.1.0"

TOKEN_RE = re.compile(r'"([^"]*)"|(\S+)')
ACTIONS = ("permit", "deny", "reject", "tunnel")
TUNNEL_STOP = {"log", "count", "alarm", "schedule", "traffic", "no-session-backup", "auth", "webauth",
               "url-filter", "av", "idp", "attack", "statistics"}
PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 51: "ah", 89: "ospf"}

# Partial table of ScreenOS predefined services (these are NOT shown in `get config`).
# Names missing here are reported as unresolved; add more with --extra-services or by editing.
BUILTIN_SERVICES = {
    "ANY": ["any"], "HTTP": ["tcp/80"], "HTTPS": ["tcp/443"], "FTP": ["tcp/21"], "SSH": ["tcp/22"],
    "TELNET": ["tcp/23"], "SMTP": ["tcp/25"], "DNS": ["tcp/53", "udp/53"], "POP3": ["tcp/110"],
    "IMAP": ["tcp/143"], "LDAP": ["tcp/389"], "NTP": ["udp/123"], "SNMP": ["udp/161"],
    "SYSLOG": ["udp/514"], "TFTP": ["udp/69"], "PING": ["icmp/8"], "ICMP-ANY": ["icmp"],
    "MS-SQL": ["tcp/1433"], "MYSQL": ["tcp/3306"], "RADIUS": ["udp/1812"], "IKE": ["udp/500"],
    "FINGER": ["tcp/79"], "GOPHER": ["tcp/70"], "WHOIS": ["tcp/43"], "NNTP": ["tcp/119"],
}
BUILTIN_ADDRS = ("any", "dial-up vpn")

CSV_NL_SEP = [" | "]
_NL_RE = re.compile(r"\r\n|\r|\n")

OBJECT_COLS = ["logical_system", "scope_type", "scope", "object_type", "name", "description", "value_type", "value",
               "members", "members_resolved", "referenced_by_rules", "other_fields", "source_line"]
MEMBER_COLS = ["logical_system", "scope_type", "scope", "object_type", "object", "level", "member", "via"]
POLICY_COLS = ["logical_system", "scope_type", "scope", "rulebase", "rule_number", "name", "policy_id", "disabled", "action",
               "action_options", "from_zone", "to_zone", "source", "source_resolved", "destination",
               "destination_resolved", "service", "service_resolved", "nat", "nat_resolved", "log", "count",
               "schedule", "options", "other_fields", "parse_error", "source_line", "raw"]
MIP_COLS = ["logical_system", "scope_type", "scope", "rulebase", "rule_number", "name", "mapped_address", "host", "netmask",
            "host_cidr", "vr", "other_fields", "source_line", "raw"]
VIP_COLS = ["logical_system", "scope_type", "scope", "rulebase", "rule_number", "name", "vip_address", "port", "service",
            "service_resolved", "server", "other_fields", "source_line", "raw"]
EXPANDED_COLS = ["logical_system", "scope_type", "scope", "rulebase", "rule_number", "policy_id", "name", "action", "disabled",
                 "from_zone", "to_zone", "source", "destination", "service"]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def tokenize(line):
    return [m.group(1) if m.group(1) is not None else m.group(2) for m in TOKEN_RE.finditer(line)]


def is_ipv4(t):
    try:
        ipaddress.IPv4Address(t)
        return True
    except ValueError:
        return False


def is_netmask(t):
    if not is_ipv4(t):
        return False
    inv = int(ipaddress.IPv4Address(t)) ^ 0xFFFFFFFF
    return (inv & (inv + 1)) == 0


def to_cidr(ip, mask):
    try:
        return str(ipaddress.ip_network("%s/%s" % (ip, mask), strict=False))
    except ValueError:
        return "%s/%s" % (ip, mask)


def kv(items):
    return "; ".join(("%s=%s" % (k, v) if v != "" else k) for k, v in items)


def uniq(pairs):
    seen, out = set(), []
    for text, via in pairs:
        if text and text not in seen:
            seen.add(text)
            out.append((text, via))
    return out


def port_range(p):
    """'80-80' -> '80';  '0-65535' -> '' (any);  '1024-65535' unchanged."""
    if not p:
        return ""
    if p == "0-65535":
        return ""
    if "-" in p:
        a, b = p.split("-", 1)
        return a if a == b else p
    return p


def svc_text(e):
    p = e["proto"]
    if p == "icmp":
        t = e.get("type")
        return "icmp" + ("/%s" % t if t not in (None, "") else "") + \
            (" code %s" % e["code"] if e.get("code") not in (None, "") else "")
    if p in ("tcp", "udp"):
        d, s = port_range(e.get("dst")), port_range(e.get("src"))
        return p + ("/" + d if d else "") + (" (src %s)" % s if s else "")
    return p


def clean_noise(text):
    out = []
    for line in text.splitlines():
        s = line.strip()
        if (re.match(r"^\S*->", s) or s.startswith("Total Config size") or
                re.match(r"^-+\s*more\s*-+", s, re.I)):
            out.append("")
        else:
            out.append(line)
    return out


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
class Ctx:
    """One configuration context: the root, or a virtual system (vsys)."""

    def __init__(self, name):
        self.name = name
        self.zones = {}                       # zone -> {"address": {}, "address-group": {}}
        self.services = {}                    # name -> obj (services and service groups share a namespace)
        self.dips, self.scheds = {}, {}
        self.policies, self.mips, self.vips = [], [], []


class NsParser:
    def __init__(self, expand=False, max_expand=100000, extra_services=None, root_name=""):
        self.expand, self.max_expand, self.root_name = expand, max_expand, root_name
        self.builtin = {k.upper(): list(v) for k, v in BUILTIN_SERVICES.items()}
        for k, v in (extra_services or {}).items():
            self.builtin[k.upper()] = v
        self.meta = {"hostname": None, "version": None}
        self.root = Ctx("")
        self.ctxs, self.by_name = [self.root], {}
        self.st = self.root                   # context that parsing / processing is currently working on
        self.stack = []                       # open "set ... / exit" blocks: vsys, vrouter, protocol, route-map, policy
        self.nest_problems = 0
        self.used = set()
        self.warnings, self._wseen = [], set()
        self.unresolved = self.unparsed = 0
        self.rule_rows, self.expanded = {}, []
        self.object_rows, self.member_rows = [], []
        self._cur = None                      # policy block currently open

    # state of the context being worked on (root or one vsys)
    zones = property(lambda self: self.st.zones)
    services = property(lambda self: self.st.services)
    dips = property(lambda self: self.st.dips)
    scheds = property(lambda self: self.st.scheds)
    policies = property(lambda self: self.st.policies)
    mips = property(lambda self: self.st.mips)
    vips = property(lambda self: self.st.vips)
    label = property(lambda self: self.st.name or self.root_name)

    # ---- diagnostics ----------------------------------------------------- #
    def warn(self, context, msg, line=None):
        key = (self.st.name, context, msg)
        if key not in self._wseen:
            self._wseen.add(key)
            self.warnings.append({"logical_system": self.label, "context": context, "message": msg,
                                  "source_line": line or ""})

    def unres(self, kind, name, rctx):
        self.unresolved += 1
        self.warn(rctx, "unresolved %s reference '%s'" % (kind, name))

    def bad(self, line, msg, raw):
        self.unparsed += 1
        self.warn("line %d" % line, "%s: %s" % (msg, raw[:100]), line)

    # ---- top level ------------------------------------------------------- #
    def parse(self, text):
        lines = clean_noise(text)
        joined = "\n".join(lines)
        if re.search(r"^\s*set (security|system|interfaces|routing-options|firewall)\b", joined, re.M):
            raise ValueError("this looks like Junos 'display set' output (set security ...), not ScreenOS "
                             "'get config' output. Use srx_parse.py, which accepts both 'show configuration' and "
                             "'show configuration | display set' output")
        if not re.search(r"^\s*set (address|policy|service|group|interface)\b", joined, re.M):
            raise ValueError("no ScreenOS 'set address / policy / service / group / interface' commands found - "
                             "is this 'get config' output?")
        m = re.search(r"ScreenOS\s+(\d[\w.\-]*)", text)
        self.meta["version"] = m.group(1) if m else None

        for n, raw in enumerate(lines, 1):
            t = tokenize(raw)
            if not t:
                continue
            try:
                self.handle(n, t, raw.strip())
            except (IndexError, ValueError) as e:
                self.bad(n, "could not parse (%s)" % e, raw.strip())

        if self.stack:
            self.nest_problems += 1
            self.warn("end of file", "%d block(s) still open at end of file (%s): block nesting got out of step, so "
                      "vsys assignment of later lines may be wrong" % (len(self.stack), " > ".join(self.stack)))

        for st in self.ctxs:                  # process every context first, so shared-object usage is known ...
            self.st = st
            self.compute_group_views()
            self.process_policies()
            self.process_nat()
        for st in self.ctxs:                  # ... before the object rows (referenced_by_rules) are written
            self.st = st
            self.build_object_rows()
        self.st = self.root

    # ---- line dispatch --------------------------------------------------- #
    def handle(self, n, t, raw):
        kw = t[0].lower()
        if kw == "exit":
            if not self.stack:
                self.nest_problems += 1
                self.warn("line %d" % n, "'exit' with no open block: block nesting is out of step with the config", n)
                return
            top = self.stack.pop()
            if top == "policy":
                self._cur = None
            elif top == "vsys":
                self.st = self.root
            return
        if kw != "set" or len(t) < 2:
            return
        sub = t[1].lower()
        top = self.stack[-1] if self.stack else ""
        if top == "policy":                            # inside "set policy id N" ... "exit"
            if self._cur is not None:
                self.policy_block_line(t)
            return
        if sub == "vsys" and len(t) > 2:
            self.open_vsys(n, t)
            return
        if sub == "vrouter" and len(t) == 3:           # set vrouter "name"  ...  exit
            self.stack.append("vrouter")
            return
        if top in ("vrouter", "protocol", "route-map"):  # routing config: only nested blocks matter
            if top == "vrouter" and sub == "protocol" and len(t) in (3, 4):
                self.stack.append("protocol")
            elif top == "vrouter" and sub == "route-map" and "name" in [x.lower() for x in t]:
                self.stack.append("route-map")
            return
        if sub == "hostname" and len(t) > 2:
            if self.st is self.root:
                self.meta["hostname"] = t[2]
        elif sub == "zone" and len(t) > 2:
            z = t[2].lower()
            if z == "id" and len(t) > 4:
                self.zone(t[4])
            elif z == "name" and len(t) > 3:
                self.zone(t[3])
            elif z not in ("id", "name"):
                self.zone(t[2])
        elif sub == "address" and len(t) >= 4:
            self.parse_address(n, t, raw)
        elif sub == "group" and len(t) >= 4 and t[2].lower() in ("address", "service"):
            self.parse_group(n, t, raw)
        elif sub == "service" and len(t) >= 3:
            self.parse_service(n, t, raw)
        elif sub == "scheduler" and len(t) >= 3:
            self.parse_scheduler(n, t, raw)
        elif sub == "interface" and len(t) >= 4:
            self.parse_interface(n, t, raw)
        elif sub == "policy":
            self.parse_policy(n, t, raw)

    def open_vsys(self, n, t):
        name = t[2]
        if self.stack:
            self.nest_problems += 1
            self.warn("line %d" % n, "vsys '%s' starts while block(s) are still open (%s): block nesting got out of "
                      "step; resetting" % (name, " > ".join(self.stack)), n)
            self.stack, self._cur = [], None
        st = self.by_name.get(name)
        if st is None:
            st = self.by_name[name] = Ctx(name)
            self.ctxs.append(st)
        self.st = st
        self.stack.append("vsys")

    def zone(self, name):
        return self.zones.setdefault(name, {"address": {}, "address-group": {}})

    def new_obj(self, otype, name, scope_type, scope, line, desc=""):
        return {"type": otype, "name": name, "scope_type": scope_type, "scope": scope, "desc": desc,
                "vt": "", "val": "", "members": [], "other": [], "line": line, "view": None}

    def store(self, store, o):
        if o["name"] in store:
            self.warn("%s/%s" % (o["type"], o["name"]), "duplicate %s name (later definition wins)" % o["type"],
                      o["line"])
        store[o["name"]] = o

    # ---- objects ---------------------------------------------------------- #
    def parse_address(self, n, t, raw):
        zone, name, rest = t[2], t[3], t[4:]
        o = self.new_obj("address", name, "zone", zone, n)
        if rest and rest[0].lower() == "comment":
            o["desc"] = " ".join(rest[1:])
        elif rest and is_ipv4(rest[0]):
            if len(rest) > 1 and is_netmask(rest[1]):
                o["vt"], o["val"] = "ip-netmask", to_cidr(rest[0], rest[1])
                o["desc"] = " ".join(rest[2:])
            else:
                o["vt"], o["val"] = "ip", rest[0]
                o["desc"] = " ".join(rest[1:])
        elif rest and "/" in rest[0] and is_ipv4(rest[0].split("/")[0]):
            o["vt"], o["val"] = "ip-netmask", rest[0]
            o["desc"] = " ".join(rest[1:])
        elif rest:
            o["vt"], o["val"] = "domain-name", rest[0]
            o["desc"] = " ".join(rest[1:])
            if re.match(r"^[\d.]+$", rest[0]):             # looks like an IP but is not a valid one
                o["vt"] = "invalid"
                self.bad(n, "invalid IPv4 address '%s'" % rest[0], raw)
        self.store(self.zone(zone)["address"], o)

    def parse_group(self, n, t, raw):
        kind = t[2].lower()
        if kind == "address":
            zone, name, rest = t[3], t[4], t[5:]
            store, otype, scope_type, scope = self.zone(zone)["address-group"], "address-group", "zone", zone
        else:
            name, rest = t[3], t[4:]
            store, otype, scope_type, scope = self.services, "service-group", "global", ""
        o = store.get(name) if (name in store and store[name]["type"] == otype) else None
        if o is None:
            o = self.new_obj(otype, name, scope_type, scope, n)
            if otype == "service-group" and name in self.services:
                self.warn("%s/%s" % (otype, name), "service group shares a name with a service", n)
            store[name] = o
        if rest and rest[0].lower() == "add" and len(rest) > 1:
            o["members"].append(rest[1])
        elif rest and rest[0].lower() == "comment" and len(rest) > 1:
            o["desc"] = " ".join(rest[1:])
        elif rest:
            o["other"].append((rest[0], " ".join(rest[1:])))

    def parse_service(self, n, t, raw):
        name, rest = t[2], t[3:]
        o = self.services.get(name)
        if o is None or o["type"] != "service":
            o = self.new_obj("service", name, "global", "", n)
            o["entries"] = []
            self.services[name] = o
        if not rest:
            return
        k = rest[0].lower()
        if k in ("protocol", "+", "transport"):
            if len(rest) < 2:
                raise ValueError("service entry without protocol")
            p = rest[1].lower()
            proto = PROTO_NAMES.get(int(p), "proto-%s" % p) if p.isdigit() else p
            e = {"proto": proto, "src": None, "dst": None, "type": None, "code": None}
            i, leftover = 2, []
            while i < len(rest):
                w = rest[i].lower()
                if w in ("src-port", "dst-port") and i + 1 < len(rest):
                    e["src" if w == "src-port" else "dst"] = rest[i + 1]
                    i += 2
                elif w in ("type", "code") and i + 1 < len(rest):
                    e[w] = rest[i + 1]
                    i += 2
                elif w == "timeout" and i + 1 < len(rest):
                    o["other"].append(("timeout", rest[i + 1]))
                    i += 2
                else:
                    leftover.append(rest[i])
                    i += 1
            if len(leftover) == 1 and leftover[0].lower() not in ("session-cache",):
                o["desc"] = leftover[0]
            else:
                o["other"] += [(x, "") for x in leftover]
            o["entries"].append(e)
        elif k == "comment" and len(rest) > 1:
            o["desc"] = " ".join(rest[1:])
        else:
            o["other"].append((rest[0], " ".join(rest[1:])))

    def parse_scheduler(self, n, t, raw):
        o = self.new_obj("scheduler", t[2], "global", "", n)
        rest = t[3:]
        if rest and rest[0].lower() == "comment":
            o["desc"] = " ".join(rest[1:])
        else:
            o["vt"], o["val"] = (rest[0], " ".join(rest[1:])) if rest else ("", "")
        if t[2] in self.scheds and not rest:
            return
        if t[2] in self.scheds:                       # additional lines for the same scheduler
            ex = self.scheds[t[2]]
            if rest and rest[0].lower() == "comment":
                ex["desc"] = o["desc"]
            elif rest:
                ex["val"] = (ex["val"] + "; " if ex["val"] else "") + o["vt"] + " " + o["val"]
            return
        self.scheds[t[2]] = o

    def parse_interface(self, n, t, raw):
        iface, low = t[2], [x.lower() for x in t]
        if t[3].lower() == "mip" and len(t) > 4:
            attrs, other, i = {}, [], 5
            while i < len(t):
                if low[i] in ("host", "netmask", "vr") and i + 1 < len(t):
                    attrs[low[i]] = t[i + 1]
                    i += 2
                else:
                    other.append((t[i], ""))
                    i += 1
            self.mips.append({"iface": iface, "mip": t[4], "attrs": attrs, "other": other, "line": n, "raw": raw})
        elif t[3].lower() == "vip" and len(t) > 6:
            j = 5
            if t[j] == "+":
                j += 1
            self.vips.append({"iface": iface, "vip": t[4], "port": t[j], "svc": t[j + 1], "server": t[j + 2],
                              "other": [(x, "") for x in t[j + 3:]], "line": n, "raw": raw})
        elif "dip" in low:
            k = low.index("dip")
            if k + 1 < len(t) and t[k + 1].isdigit():
                did, ips, extra = t[k + 1], [], []
                for x in t[k + 2:]:
                    if is_ipv4(x) and len(ips) < 2:
                        ips.append(x)
                    else:
                        extra.append((x, ""))
                o = self.new_obj("dip-pool", "dip-%s" % did, "interface", iface, n)
                o["vt"], o["val"] = "address-range", "-".join(ips)
                o["vals"], o["other"] = ["-".join(ips)] if ips else [], extra
                if did in self.dips:
                    self.warn("dip-%s" % did, "duplicate DIP id (later definition wins)", n)
                self.dips[did] = o

    # ---- policies --------------------------------------------------------- #
    def parse_policy(self, n, t, raw):
        i, glob, pid, name = 2, False, "", ""
        if i < len(t) and t[i].lower() == "global":
            glob = True
            i += 1
        if i < len(t) and t[i].lower() == "id" and i + 1 < len(t):
            pid = t[i + 1]
            i += 2
        if i >= len(t):                                  # "set policy id N"  -> opens a block
            self.stack.append("policy")
            self._cur = self.find_policy(pid)
            if self._cur is None:
                self.warn("policy id %s" % pid, "policy block without a definition line", n)
            return
        if t[i].lower() == "name" and i + 1 < len(t):
            name = t[i + 1]
            i += 2
        if t[i].lower() not in ("from",) and not glob:
            # attribute line, e.g. "set policy id 5 disable"
            if not pid:                                  # e.g. "set policy move ..." / "default-permit-all"
                return
            p = self.find_policy(pid)
            if p is None:
                self.warn("policy id %s" % pid, "attribute line without a definition line", n)
            elif t[i].lower() == "disable":
                p["disabled"] = True
            else:
                p["extra"].append((t[i], " ".join(t[i + 1:])))
            return
        pol = {"id": pid, "name": name, "line": n, "raw": raw, "disabled": False, "extra": [], "error": "",
               "src": [], "dst": [], "svc": [], "action": "", "action_opts": [], "nat": [], "log": [],
               "count": False, "sched": "", "options": [], "glob": glob}
        if t[i].lower() == "from":
            if i + 3 < len(t):
                pol["fz"], pol["tz"] = t[i + 1], t[i + 3]
                i += 4
            else:                                        # truncated line: keep the row, flag the error
                pol["fz"], pol["tz"] = (t[i + 1] if i + 1 < len(t) else ""), ""
                i = len(t)
        else:
            pol["fz"] = pol["tz"] = "Global"
        if i + 2 >= len(t):
            pol["error"] = "policy line too short"
            self.unparsed += 1
            self.warn("policy id %s" % pid, "policy line too short", n)
        else:
            pol["src"], pol["dst"], pol["svc"] = [t[i]], [t[i + 1]], [t[i + 2]]
            self.parse_policy_tail(pol, t[i + 3:])
        if pol["fz"] == "Global" and pol["tz"] == "Global":
            pol["glob"] = True
        self.policies.append(pol)

    def parse_policy_tail(self, pol, rest):
        clauses, j = [], 0
        while j < len(rest):
            w = rest[j].lower()
            if w == "nat" and not pol["action"]:
                clauses.append([])
                j += 1
            elif w in ACTIONS and not pol["action"]:
                pol["action"] = w
                j += 1
                if w == "tunnel":
                    while j < len(rest) and rest[j].lower() not in TUNNEL_STOP:
                        pol["action_opts"].append(rest[j])
                        j += 1
            elif clauses and not pol["action"]:
                clauses[-1].append(rest[j])
                j += 1
            elif w == "log":
                pol["log"].append("yes")
                j += 1
            elif w == "count":
                pol["count"] = True
                j += 1
            elif w == "schedule" and j + 1 < len(rest):
                pol["sched"] = rest[j + 1]
                j += 2
            else:
                pol["options"].append(rest[j])
                j += 1
        pol["nat"] = clauses

    def find_policy(self, pid):
        for p in reversed(self.policies):
            if p["id"] == pid:
                return p
        return None

    def policy_block_line(self, t):
        p, kw = self._cur, t[1].lower()
        if kw == "src-address" and len(t) > 2:
            p["src"].append(t[2])
        elif kw == "dst-address" and len(t) > 2:
            p["dst"].append(t[2])
        elif kw == "service" and len(t) > 2:
            p["svc"].append(t[2])
        elif kw == "log" and len(t) > 2:
            p["log"].append(" ".join(t[2:]))
        else:
            p["extra"].append((t[1], " ".join(t[2:])))

    # ---- resolution ------------------------------------------------------- #
    def find_addr(self, zone, name):
        """Returns (object, found_in_root).  A vsys may use root (shared) objects; that is reported."""
        for st in ((self.st,) if self.st is self.root else (self.st, self.root)):
            z = st.zones.get(zone)
            o = z and (z["address"].get(name) or z["address-group"].get(name))
            if o:
                return o, st is not self.st
        return None, False

    def resolve_address(self, name, zone, rctx, path=()):
        if name.lower() in BUILTIN_ADDRS:
            return [("any" if name.lower() == "any" else name, list(path))]
        o, shared = self.find_addr(zone, name)
        if o is None:
            self.unres("address", "%s (zone %s)" % (name, zone), rctx)
            return [("unresolved:" + name, list(path) + [name])]
        if shared:
            self.warn(rctx, "address '%s' (zone %s) is not defined in this vsys; resolved from the root config"
                      % (name, zone))
        if name in path:
            self.warn(rctx, "cycle in address group '%s'" % name)
            return []
        self.used.add(id(o))
        via = list(path) + [name]
        if o["type"] == "address":
            return [(o["val"] or name, via)]
        out = []
        for m in o["members"]:
            out += self.resolve_address(m, zone, rctx, tuple(via))
        return uniq(out)

    def resolve_service(self, name, rctx, path=()):
        o = self.services.get(name)
        if o is None and self.st is not self.root and name in self.root.services:
            o = self.root.services[name]
            self.warn(rctx, "service '%s' is not defined in this vsys; resolved from the root config" % name)
        if o is None:
            b = self.builtin.get(name.upper())
            if b is not None:
                return [(t, list(path)) for t in b]
            self.unres("service", name, rctx)
            return [("unresolved:" + name, list(path) + [name])]
        if name in path:
            self.warn(rctx, "cycle in service group '%s'" % name)
            return []
        self.used.add(id(o))
        via = list(path) + [name]
        if o["type"] == "service":
            return [(svc_text(e), via) for e in o["entries"]] or [(name, via)]
        out = []
        for m in o["members"]:
            out += self.resolve_service(m, rctx, tuple(via))
        return uniq(out)

    def compute_group_views(self):
        saved, self.used = self.used, set()
        for zone, z in self.zones.items():
            for name, o in z["address-group"].items():
                o["view"] = self.resolve_address(name, zone, "group %s" % name)
        for name, o in self.services.items():
            if o["type"] == "service-group":
                o["view"] = self.resolve_service(name, "group %s" % name)
        self.used = saved

    def resolve_nat(self, clauses, rctx):
        out = []
        for c in clauses:
            if not c:
                continue
            kind, low = c[0].lower(), [x.lower() for x in c]
            if kind == "src":
                if "dip-id" in low and low.index("dip-id") + 1 < len(c):
                    did = c[low.index("dip-id") + 1]
                    d = self.dips.get(did)
                    if d is None:
                        self.unres("dip", did, rctx)
                        out.append(("unresolved:dip-%s" % did, []))
                    else:
                        self.used.add(id(d))
                        out += [(v, ["dip-%s" % did]) for v in d["vals"]] or [("dip-%s" % did, [])]
                else:
                    out.append(("interface-ip", []))
            elif kind == "dst" and "ip" in low:
                k = low.index("ip")
                addrs = []
                for x in c[k + 1:]:
                    if x.lower() == "port":
                        break
                    addrs.append(x)
                txt = "-".join(addrs)
                if "port" in low and low.index("port") + 1 < len(c):
                    txt += " (port %s)" % c[low.index("port") + 1]
                out.append((txt, []))
            else:
                out.append((" ".join(c), []))
        return [t for t, _ in uniq(out)]

    def process_policies(self):
        counters = {}
        for p in self.policies:
            scope_type, scope = ("global", "Global") if p["glob"] else ("zone-pair", "%s>%s" % (p["fz"], p["tz"]))
            counters[scope] = counters.get(scope, 0) + 1
            n = counters[scope]
            label = p["name"] or "id %s" % p["id"]
            rctx = "%s/%s" % (scope, label)
            res = {"src": [], "dst": [], "svc": []}
            for a in p["src"]:
                res["src"] += self.resolve_address(a, p["fz"], rctx)
            for a in p["dst"]:
                res["dst"] += self.resolve_address(a, p["tz"], rctx)
            for s in p["svc"]:
                res["svc"] += self.resolve_service(s, rctx)
            res = {k: [t for t, _ in uniq(v)] for k, v in res.items()}
            if p["sched"]:
                o = self.scheds.get(p["sched"])
                if o is None and self.st is not self.root and p["sched"] in self.root.scheds:
                    o = self.root.scheds[p["sched"]]
                    self.warn(rctx, "scheduler '%s' is not defined in this vsys; resolved from the root config"
                              % p["sched"])
                if o:
                    self.used.add(id(o))
                else:
                    self.unres("scheduler", p["sched"], rctx)
            nat_resolved = self.resolve_nat(p["nat"], rctx)

            row = {"logical_system": self.label, "scope_type": scope_type, "scope": scope,
                   "rulebase": "security-policy", "rule_number": n,
                   "name": p["name"], "policy_id": p["id"], "disabled": "yes" if p["disabled"] else "",
                   "action": p["action"], "action_options": " ".join(p["action_opts"]),
                   "from_zone": p["fz"], "to_zone": p["tz"],
                   "source": ";".join(p["src"]), "source_resolved": ";".join(res["src"]),
                   "destination": ";".join(p["dst"]), "destination_resolved": ";".join(res["dst"]),
                   "service": ";".join(p["svc"]), "service_resolved": ";".join(res["svc"]),
                   "nat": "; ".join(" ".join(c) for c in p["nat"]), "nat_resolved": ";".join(nat_resolved),
                   "log": ";".join(p["log"]), "count": "yes" if p["count"] else "", "schedule": p["sched"],
                   "options": " ".join(p["options"]), "other_fields": kv(p["extra"]),
                   "parse_error": p["error"], "source_line": p["line"], "raw": p["raw"]}
            self.rule_rows.setdefault("security-policy", []).append(row)

            if self.expand and not p["error"]:
                lists = [res["src"] or [""], res["dst"] or [""], res["svc"] or [""]]
                total = len(lists[0]) * len(lists[1]) * len(lists[2])
                if total > self.max_expand:
                    self.warn(rctx, "rule expands to %d rows; truncated to %d" % (total, self.max_expand))
                for s, d, v in itertools.islice(itertools.product(*lists), self.max_expand):
                    r = {k: row.get(k, "") for k in EXPANDED_COLS}
                    r.update({"source": s, "destination": d, "service": v})
                    self.expanded.append(r)

    def process_nat(self):
        counters = {}
        for m in self.mips:
            a = m["attrs"]
            counters[m["iface"]] = counters.get(m["iface"], 0) + 1
            self.rule_rows.setdefault("nat-mip", []).append({
                "logical_system": self.label, "scope_type": "interface", "scope": m["iface"], "rulebase": "nat-mip",
                "rule_number": counters[m["iface"]], "name": m["mip"], "mapped_address": m["mip"],
                "host": a.get("host", ""), "netmask": a.get("netmask", ""),
                "host_cidr": to_cidr(a["host"], a["netmask"]) if a.get("host") and a.get("netmask") else a.get("host", ""),
                "vr": a.get("vr", ""), "other_fields": kv(m["other"]), "source_line": m["line"], "raw": m["raw"]})
        counters = {}
        for v in self.vips:
            counters[v["iface"]] = counters.get(v["iface"], 0) + 1
            rctx = "nat-vip/%s/%s" % (v["iface"], v["vip"])
            svc = [t for t, _ in uniq(self.resolve_service(v["svc"], rctx))]
            self.rule_rows.setdefault("nat-vip", []).append({
                "logical_system": self.label, "scope_type": "interface", "scope": v["iface"], "rulebase": "nat-vip",
                "rule_number": counters[v["iface"]], "name": "%s:%s" % (v["vip"], v["port"]),
                "vip_address": v["vip"], "port": v["port"], "service": v["svc"],
                "service_resolved": ";".join(svc), "server": v["server"], "other_fields": kv(v["other"]),
                "source_line": v["line"], "raw": v["raw"]})

    # ---- objects ---------------------------------------------------------- #
    def build_object_rows(self):
        def emit(o):
            view = o.get("view")
            if o["type"] == "service":
                texts = [svc_text(e) for e in o["entries"]]
                o["vt"] = "/".join(dict.fromkeys(e["proto"] for e in o["entries"]))
                o["val"] = "; ".join(texts)
            self.object_rows.append({
                "logical_system": self.label, "scope_type": o["scope_type"], "scope": o["scope"], "object_type": o["type"], "name": o["name"],
                "description": o["desc"], "value_type": o["vt"], "value": o["val"],
                "members": ";".join(o["members"]),
                "members_resolved": ";".join(t for t, _ in view) if view else "",
                "referenced_by_rules": "yes" if id(o) in self.used else "no",
                "other_fields": kv(o["other"]), "source_line": o["line"]})
            ident = {"logical_system": self.label, "scope_type": o["scope_type"], "scope": o["scope"],
                     "object_type": o["type"], "object": o["name"]}
            for m in o["members"]:
                self.member_rows.append(dict(ident, level="direct", member=m, via=""))
            for t, via in (view or []):
                self.member_rows.append(dict(ident, level="resolved", member=t, via=">".join(via)))

        for z in self.zones.values():
            for t in ("address", "address-group"):
                for o in z[t].values():
                    emit(o)
        for o in self.services.values():
            emit(o)
        for o in self.dips.values():
            emit(o)
        for o in self.scheds.values():
            emit(o)


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def write_csv(path, fields, rows):
    """One physical line per record: embedded line breaks are replaced with CSV_NL_SEP."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: (_NL_RE.sub(CSV_NL_SEP[0], v) if isinstance(v, str) else v) for k, v in r.items()})


def make_run_dir(base):
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path, n = os.path.join(base, stamp), 1
    while True:
        try:
            os.makedirs(path)
            return path
        except FileExistsError:
            n += 1
            path = os.path.join(base, "%s_%d" % (stamp, n))


def write_outputs(p, run_dir):
    write_csv(os.path.join(run_dir, "objects.csv"), OBJECT_COLS, p.object_rows)
    write_csv(os.path.join(run_dir, "object_members.csv"), MEMBER_COLS, p.member_rows)
    cols = {"security-policy": POLICY_COLS, "nat-mip": MIP_COLS, "nat-vip": VIP_COLS}
    for rb, rows in p.rule_rows.items():
        write_csv(os.path.join(run_dir, "rules_%s.csv" % rb), cols[rb], rows)
    if p.expand:
        write_csv(os.path.join(run_dir, "rules_expanded.csv"), EXPANDED_COLS, p.expanded)
    write_csv(os.path.join(run_dir, "warnings.csv"), ["logical_system", "context", "message", "source_line"], p.warnings)


def print_summary(p):
    print("Device        : %s (ScreenOS %s)" % (p.meta["hostname"], p.meta["version"] or "version not in config"))
    names = [st.name or p.root_name or "(root)" for st in p.ctxs]
    print("Logical systems: %d  (%s)" % (len(p.ctxs), ", ".join(names)))
    for st, nm in zip(p.ctxs, names):
        lab = st.name or p.root_name
        objs = sum(1 for r in p.object_rows if r["logical_system"] == lab)
        rules = {rb: sum(1 for r in rows if r["logical_system"] == lab) for rb, rows in p.rule_rows.items()}
        print("  %-24s zones=%d  objects=%d  %s" % (nm, len(st.zones), objs,
                                                 "  ".join("%s=%d" % x for x in rules.items() if x[1])))
    counts = {}
    for r in p.object_rows:
        counts[r["object_type"]] = counts.get(r["object_type"], 0) + 1
    print("Objects       : %d  (%s)" % (len(p.object_rows), ", ".join("%s=%d" % x for x in counts.items())))
    for rb, rows in p.rule_rows.items():
        print("Rules         : %-24s %d" % (rb, len(rows)))
    if p.nest_problems:
        print("WARNING       : block nesting got out of step %d time(s); vsys assignment may be wrong, see warnings.csv"
              % p.nest_problems)
    print("Unresolved refs: %d   Unparsed lines: %d   Warnings: %d" % (p.unresolved, p.unparsed, len(p.warnings)))


def load_extra_services(path):
    out = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = [x.strip() for x in v.split(",") if x.strip()]
    return out


# --------------------------------------------------------------------------- #
SAMPLE = """ssg140-> get config
Total Config size 8211:
unset key protection enable sec-level basic
set clock timezone 0
set vrouter trust-vr sharable
set vrouter "untrust-vr"
exit
set vrouter "trust-vr"
exit
set hostname SSG140-FW
set zone "DMZ" vrouter "trust-vr"
set address "Trust" "LAN" 192.168.0.0 255.255.0.0 "Internal LAN"
set address "Trust" "MGMT" 10.9.9.9 255.255.255.255
set address "Trust" "UNUSED-HOST" 192.0.2.99 255.255.255.255
set address "DMZ" "WEB1" 10.1.1.5 255.255.255.255 "Web server 1"
set address "DMZ" "WEB2" 10.1.1.6 255.255.255.255
set address "DMZ" "DMZ-NET" 10.1.1.0 255.255.255.0
set address "Untrust" "PARTNER-A" 203.0.113.10 255.255.255.255
set address "Untrust" "PARTNER-B" 203.0.113.20 255.255.255.255
set address "Untrust" "NET-X" 203.0.113.0 255.255.255.0 "shared zone address used by a vsys"
set address "Untrust" "LOOKUP" www.example.com "Partner portal"
set group address "DMZ" "WEB-SERVERS"
set group address "DMZ" "WEB-SERVERS" comment "DMZ web tier"
set group address "DMZ" "WEB-SERVERS" add "WEB1"
set group address "DMZ" "WEB-SERVERS" add "WEB2"
set group address "DMZ" "LOOP-A"
set group address "DMZ" "LOOP-A" add "LOOP-B"
set group address "DMZ" "LOOP-B"
set group address "DMZ" "LOOP-B" add "LOOP-A"
set group address "Untrust" "PARTNERS"
set group address "Untrust" "PARTNERS" add "PARTNER-A"
set group address "Untrust" "PARTNERS" add "PARTNER-B"
set group address "Untrust" "PARTNERS" add "LOOKUP"
set service "HTTPS-ALT" protocol tcp src-port 1024-65535 dst-port 8443-8443
set service "WEB-RANGE" protocol tcp src-port 0-65535 dst-port 80-80
set service "WEB-RANGE" + tcp src-port 0-65535 dst-port 8080-8090
set service "SVC-DNS" protocol udp src-port 0-65535 dst-port 53-53 "Internal DNS"
set service "PING-ANY" protocol icmp type 8 code 0
set service "SVC-GRE" protocol 47
set group service "WEB-SVCS"
set group service "WEB-SVCS" comment "Web services"
set group service "WEB-SVCS" add "HTTP"
set group service "WEB-SVCS" add "HTTPS"
set group service "WEB-SVCS" add "WEB-RANGE"
set group service "ALL-SVCS"
set group service "ALL-SVCS" add "WEB-SVCS"
set group service "ALL-SVCS" add "SVC-DNS"
set group service "ALL-SVCS" add "HTTPS-ALT"
set scheduler "BUSINESS-HRS" recurrent monday start 08:00 stop 18:00
set interface "ethernet0/1" dip 5 198.51.100.50 198.51.100.55 fix-port
set interface "ethernet0/0" mip 198.51.100.20 host 10.1.1.6 netmask 255.255.255.255 vr "trust-vr"
set interface "ethernet0/0" vip 198.51.100.10 80 "HTTP" 10.1.1.5
set interface "ethernet0/0" vip 198.51.100.10 + 8443 "HTTPS-ALT" 10.1.1.5
set policy id 1 name "Allow web out" from "Trust" to "Untrust"  "LAN" "Any" "HTTP" nat src dip-id 5 permit log
set policy id 1
set service "HTTPS"
set log session-close
exit
set policy id 2 from "Trust" to "Untrust"  "MGMT" "NOSUCH" "SSH" permit
set policy id 2 disable
set policy id 2
exit
set policy id 3 name "Partners to web" from "Untrust" to "DMZ"  "PARTNERS" "WEB-SERVERS" "WEB-SVCS" permit count log
set policy id 3
set dst-address "DMZ-NET"
exit
set policy id 4 from "Untrust" to "DMZ"  "Any" "LOOP-A" "ANY" deny
set policy id 5 from "Trust" to "DMZ"  "LAN" "DMZ-NET" "ALL-SVCS" permit schedule "BUSINESS-HRS" traffic gbw 1000 priority 4 mbw 2000
set policy id 6 name "Port forward" from "Untrust" to "DMZ"  "Any" "WEB1" "HTTP" nat dst ip 10.1.1.6 port 8080 permit
set policy id 7 from "Trust" to "Untrust"  "LAN" "PARTNERS" "ANY" tunnel vpn "VPN-PARTNER" pair-policy 8 log
set policy id 7
exit
set policy id 9 from "Global" to "Global"  "Any" "Any" "ANY" deny log
set policy id 9
exit
set address "Trust" "SRV" 10.1.1.100 255.255.255.255 "root server"
set policy id 10 name "root uses SRV" from "Trust" to "DMZ"  "SRV" "WEB1" "HTTP" permit
set policy id 10
exit
set nsmgmt bulk-cli-timeout 3
set ssh version v2
set vsys "vsys_1"  zone 76 vrouter id 22
set vsys-id 20
set override session-limit max 1000000 alarm 100
set vrouter "vsys_1-vr"
unset auto-route-export
exit
set service "TCP_554" protocol tcp src-port 0-65535 dst-port 554-554 
set service "UDP_554" protocol udp src-port 0-65535 dst-port 554-554 
set auth-server "Local" server-name "Local"
set admin vsys name "vsys_vsys_1"
set zone id 2028 "zone_1-vsys_1"
set zone "Trust-vsys_1" tcp-rst 
unset zone "zone_1-vsys_1" tcp-rst 
set interface "aggregate1.121" tag 121 zone "Trust-vsys_1"
set interface aggregate1.121 ip 192.0.2.1/29
set interface aggregate1.121 route
set vrouter "vsys_1-vr"
set adv-inact-interface
set protocol bgp 65530
set enable
set hold-time 30
set neighbor 192.0.2.2 remote-as 65001
exit
set access-list 10
set access-list 10 permit ip 0.0.0.0/0 10
set route-map name "vsys_1-TRUST" permit 10
set match ip 10
set next-hop 192.0.2.2
exit
set add-default-route vrouter "trust-vr"
exit
set vrouter "untrust-vr"
exit
set vrouter "trust-vr"
exit
set interface aggregate1.121 protocol bgp
set vrouter "vsys_1-vr"
exit
set address "Trust-vsys_1" "SRV" 172.16.1.10 255.255.255.255 "vsys_1 server"
set address "zone_1-vsys_1" "Net_B_28" 172.16.2.0 255.255.255.240
set policy id 1 from "Trust-vsys_1" to "zone_1-vsys_1"  "SRV" "Net_B_28" "HTTPS" permit log 
set policy id 1
set service "TCP_554"
set service "UDP_554"
exit
set policy id 2 from "Trust-vsys_1" to "zone_1-vsys_1"  "Any" "Any" "ANY" deny log 
set policy id 2
exit
set policy id 3 name "uses a root zone" from "Trust-vsys_1" to "Untrust"  "SRV" "NET-X" "HTTP" permit
set policy id 3
exit
exit



set vsys "VSYS_2"  zone 79 vrouter id 23
set vsys-id 21
set vrouter "VSYS_2-vr"

exit
set service "TCP_554" protocol tcp src-port 0-65535 dst-port 5540-5540 
set zone id 2029 "zone_1-VSYS_2"
set zone "Trust-VSYS_2" tcp-rst 
set address "Trust-VSYS_2" "SRV" 172.17.1.10 255.255.255.255 "vsys_2 server"
set address "zone_1-VSYS_2" "Net_B_24" 172.17.2.0 255.255.255.0
set address "zone_1-VSYS_2" "Net_C_24" 172.17.3.0 255.255.255.0
set policy id 1 from "Trust-VSYS_2" to "zone_1-VSYS_2"  "SRV" "Net_B_24" "HTTPS" permit log 
set policy id 1
set dst-address "Net_C_24"
set service "TCP_554"
exit
set policy id 2 from "Trust-VSYS_2" to "zone_1-VSYS_2"  "Any" "Any" "ANY" deny log 
set policy id 2
exit
exit
set vrouter "untrust-vr"
exit
set vrouter "trust-vr"
unset add-default-route
set route 0.0.0.0/0 interface mgt gateway 10.0.0.254 permanent
exit
ssg140->
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description="Parse NetScreen / ScreenOS 'get config' output to CSV")
    ap.add_argument("config", nargs="?", help="path to the 'get config' text file")
    ap.add_argument("-o", "--outdir", default="output",
                    help="base output folder (default 'output'); each run writes to "
                         "<outdir>/YYYY-MM-DD_HH-MM-SS")
    ap.add_argument("--expand", action="store_true",
                    help="also write rules_expanded.csv (one row per src x dst x service)")
    ap.add_argument("--max-expand", type=int, default=100000, help="max expanded rows per policy")
    ap.add_argument("--strict", action="store_true", help="exit 1 on unresolved references or unparsed lines")
    ap.add_argument("--csv-nl-sep", default=" | ",
                    help="string replacing line breaks inside CSV fields (default ' | ')")
    ap.add_argument("--extra-services", metavar="FILE",
                    help="file of extra predefined services, one per line: NAME=tcp/80,udp/53")
    ap.add_argument("--root-name", default="",
                    help="value of the logical_system column for the root config (default: blank)")
    ap.add_argument("--selftest", action="store_true", help="run on the embedded sample config")
    args = ap.parse_args(argv)
    CSV_NL_SEP[0] = args.csv_nl_sep

    extra = {}
    if args.extra_services:
        try:
            extra = load_extra_services(args.extra_services)
        except OSError as e:
            print("Cannot read %s: %s" % (args.extra_services, e), file=sys.stderr)
            return 2

    if args.selftest:
        text, args.expand = SAMPLE, True
    elif args.config:
        try:
            with open(args.config, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            print("Cannot read %s: %s" % (args.config, e), file=sys.stderr)
            return 2
    else:
        ap.error("config file required (or --selftest)")

    p = NsParser(expand=args.expand, max_expand=args.max_expand, extra_services=extra, root_name=args.root_name)
    try:
        p.parse(text)
    except ValueError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 2
    run_dir = make_run_dir(args.outdir)
    write_outputs(p, run_dir)
    print_summary(p)
    print("Output written to: %s" % os.path.abspath(run_dir))
    if args.strict and (p.unresolved or p.unparsed or p.nest_problems):
        print("STRICT: unresolved references, unparsed lines or block-nesting problems found; see warnings.csv.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
