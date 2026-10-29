# netscreen_parse.py

Extracts the **objects** and **rulebase** from Juniper NetScreen / ScreenOS firewalls (SSG series, ISG, NetScreen-5000
series and similar) into CSV files, preserving policy order, policy IDs, names and comments. Address groups and service
groups are resolved so each policy shows the actual addresses and services it matches. **Virtual systems (vsys / logical
systems) are supported**: every vsys is parsed as its own context and each CSV has a leading `logical_system` column.

- Python 3.8+, **standard library only**, no install step
- Reads one text file (`get config` output), writes a new timestamped folder per run
- Does not connect to any device and does not modify anything

Companion scripts with the same output conventions: `asa_parse.py` (Cisco ASA), `pan_parse.py` (Palo Alto) and
`srx_parse.py` (Juniper SRX / Junos).

> **ScreenOS is not Junos.** `get config` output is a list of `set ...` commands, so it looks like Junos
> `show configuration | display set`, but the syntax is different (`set policy id 1 from "Trust" to "Untrust" ...`,
> `set address "Trust" "WEB1" 10.1.1.5 255.255.255.255`). If you give this script real Junos `display set` output it stops
> with an error and points you to `srx_parse.py`.

---

## Contents

1. [Quick start](#1-quick-start)
2. [Input](#2-input)
3. [Command-line options](#3-command-line-options)
4. [What is parsed](#4-what-is-parsed)
5. [Output folder layout](#5-output-folder-layout)
6. [CSV output reference](#6-csv-output-reference)
7. [Behaviour notes](#7-behaviour-notes)
8. [Warnings and troubleshooting](#8-warnings-and-troubleshooting)
9. [Verifying the results](#9-verifying-the-results)
10. [Comparing runs](#10-comparing-runs)
11. [Limitations](#11-limitations)

---

## 1. Quick start

```bash
# Smoke test using the built-in sample config (no input file needed)
python netscreen_parse.py --selftest

# Real run
python netscreen_parse.py get-config.txt

# Real run with the one-row-per-source/destination/service CSV, failing on unresolved references
python netscreen_parse.py get-config.txt --expand --strict
```

Each run creates `output/<YYYY-MM-DD_HH-MM-SS>/` in the current working directory and prints its path.
Add `output/` to your `.gitignore`.

On Windows use `python` or `py`; all examples work unchanged in PowerShell or cmd.

---

## 2. Input

| Item | Detail |
|---|---|
| File | Plain-text output of `get config` (a list of `set ...` commands) |
| Encoding | UTF-8; undecodable bytes are replaced rather than aborting. CRLF or LF line endings both work |
| Ignored | Prompt lines (`hostname->`), `Total Config size ...:` and `--- more ---` lines |
| Virtual systems | `get config` on the root device includes every vsys as a `set vsys "<name>" ...` block, closed by its own `exit`. These are detected automatically (see section 7) |
| Not accepted | Junos `display set` output (`set security ...`, `set interfaces ...`): the script exits with code 2 and suggests `srx_parse.py`. Files with no ScreenOS `set address / policy / service / group / interface` commands are also rejected |

### Getting a clean config file

```
set console page 0
get config
```

`set console page 0` stops `--- more ---` paging so a terminal logger captures everything. The WebUI can also save the
configuration to a file (on most releases under *Configuration > Update > Config File*). Make sure long lines are not
wrapped by your logger; a wrapped `set policy` line will be parsed as two broken lines.

The script does not read passwords, keys or VPN secrets, but the file contains them (admin password hashes, pre-shared
keys, SNMP strings). Remove or protect them before sharing the file.

The ScreenOS version is only reported if the text "ScreenOS x.y..." appears somewhere in the file. `get config` usually
doesn't include it, so the summary may say "version not in config".

---

## 3. Command-line options

```
python netscreen_parse.py [config] [-o OUTDIR] [--expand] [--max-expand N] [--strict]
                          [--csv-nl-sep STR] [--extra-services FILE] [--root-name NAME] [--selftest]
```

| Option | Default | Description |
|---|---|---|
| `config` | (required unless `--selftest`) | Path to the `get config` text file |
| `-o`, `--outdir` | `output` | **Base** folder. Each run writes to `<outdir>/<timestamp>/` |
| `--expand` | off | Also write `rules_expanded.csv` |
| `--max-expand` | `100000` | Maximum expanded rows per policy. Larger policies are truncated and a warning is raised |
| `--strict` | off | Exit code 1 on unresolved references or unparsed lines |
| `--csv-nl-sep` | `" \| "` | Replacement for line breaks inside CSV fields |
| `--extra-services` | none | File of additional predefined services (see below) |
| `--root-name` | blank | Value of the `logical_system` column for the root config (for example `root`). Virtual systems always use their own name |
| `--selftest` | off | Run against the embedded sample config (root plus two vsys); forces `--expand` |

### `--extra-services`

ScreenOS predefined services (`HTTP`, `SSH`, `ANY`...) are not shown in `get config`, so the script has a built-in table of
the common ones. Any other predefined service used in a policy is reported as unresolved. List them in a text file, one per
line, as `NAME=protocol/port[,protocol/port...]`; lines starting with `#` are ignored:

```
# extra predefined services
H.323=tcp/1720,udp/1719
Weird Predef=tcp/7777,udp/7777
```

Names are matched case-insensitively. Services defined in the config always take priority over the table.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed (warnings may still exist; see `warnings.csv`) |
| 1 | `--strict` was set and there were unresolved references, unparsed lines, or block-nesting problems (see section 7) |
| 2 | File unreadable, wrong format (Junos `display set`, not a ScreenOS config), or bad arguments |

Cycles, duplicate names and attribute lines with no matching policy are reported as warnings but do **not** trigger
`--strict` on their own.

---

## 4. What is parsed

### Objects

| Config construct | Captured as |
|---|---|
| `set address "<zone>" "<name>" <ip> <mask> ["comment"]` | `address`, value as CIDR (`10.1.1.5/32`); the comment becomes `description` |
| `set address "<zone>" "<name>" <domain-name>` | `address` with `domain-name` |
| `set group address "<zone>" "<name>"` plus `add "<member>"` and `comment "..."` lines | `address-group` with members, in order |
| `set service "<name>" protocol tcp\|udp\|icmp\|<number> [src-port a-b] [dst-port c-d] [type n code n]` | `service`; additional `+ <protocol> ...` lines add more entries; `timeout` goes to `other_fields`; a single trailing quoted token is the description |
| `set group service "<name>"` plus `add` / `comment` lines | `service-group` |
| `set scheduler "<name>" ...` | `scheduler`; the rest of the line is kept as the value |
| `set interface "<if>" dip <id> <start-ip> [<end-ip>] [options]` | `dip-pool` named `dip-<id>`; options such as `fix-port` go to `other_fields` |

### Rulebases

| Config construct | Output file |
|---|---|
| `set policy id N [name "..."] from "A" to "B" "src" "dst" "service" [nat ...] permit\|deny\|reject\|tunnel ... [options]` and its `set policy id N` ... `exit` block | `rules_security-policy.csv` |
| `set interface "<if>" mip <addr> host <addr> netmask <mask> vr "<vr>"` | `rules_nat-mip.csv` |
| `set interface "<if>" vip <addr\|interface-ip> [+] <port> "<service>" <server>` | `rules_nat-vip.csv` |

Policy details handled:

- Additional source / destination / service entries in the policy block (`set src-address`, `set dst-address`, `set service`)
  are merged with the entries on the definition line.
- `set policy id N disable` sets the disabled flag.
- `nat src`, `nat src dip-id N` and `nat dst ip A [B] [port P]` clauses are kept and resolved (see below).
- `tunnel` actions keep their VPN options (`vpn "NAME" pair-policy 8` ...).
- `log` and `count` flags, `schedule "NAME"`, and any other options (such as `traffic gbw ...`) are kept.
- Policies in the `Global` zone (`from "Global" to "Global"`) are reported as global.
- Any other line inside the policy block (`set log session-close`, `set application "IGNORE"`...) is recorded rather than dropped.

Everything not listed above (VPN, routing, interface settings other than DIP / MIP / VIP, authentication, and so on) is skipped.

### Reference resolution

| Reference | Result |
|---|---|
| Address | Its value (`192.168.0.0/16`, `www.example.com`) |
| Address group | Members expanded recursively and de-duplicated |
| `Any` | Resolved as `any` |
| `Dial-Up VPN` | Kept as written |
| Service | `tcp/8443 (src 1024-65535)`, `tcp/80`, `icmp/8 code 0`; a multi-entry service gives one result per entry. `0-65535` is treated as "any" and `80-80` as `80` |
| Service group | Members expanded recursively |
| Predefined service | Taken from the built-in table (or `--extra-services`) |
| `nat src` (no DIP) | `interface-ip` |
| `nat src dip-id N` | The DIP pool's address range |
| `nat dst ip A port P` | `A (port P)` |
| Anything not found | `unresolved:<name>` and a warning |

**Where addresses are looked up.** Address books are per zone, so a policy's source is looked up in its **from-zone** book
and its destination in its **to-zone** book. Services, service groups, DIP pools and schedulers are global.

---

## 5. Output folder layout

```
output/
  2026-10-03_09-36-16/
    objects.csv
    object_members.csv
    rules_security-policy.csv
    rules_nat-mip.csv           (only if present in the config)
    rules_nat-vip.csv           (only if present)
    rules_expanded.csv          (only with --expand)
    warnings.csv
```

- Folder names use `YYYY-MM-DD_HH-MM-SS` in **local time**, with no characters that are illegal on Windows.
- If two runs start in the same second, the second folder gets `_2`, then `_3`, and so on. Nothing is overwritten.
- The console summary shows the hostname, zones, object counts by type, rule counts per rulebase, and the unresolved /
  unparsed / warning counts, then the full path of the run folder.

All CSVs are UTF-8 with a header row, `\n` line endings and **one physical line per record**. Line breaks inside a value
are replaced with `--csv-nl-sep` (default ` | `). Multi-value cells are joined with `;`.

---

## 6. CSV output reference

### The `logical_system` column

The first column of **every** CSV. It holds the name of the virtual system the row belongs to (`vsys_1`, `VSYS_2`, ...). It is blank for
the root configuration, or the value given with `--root-name`. Everything else in the row (zone, rule number, policy ID, object name) is
scoped to that logical system, so the same zone name, address name or policy ID can appear in several without clashing.

### `objects.csv`

`logical_system, scope_type, scope, object_type, name, description, value_type, value, members, members_resolved, referenced_by_rules, other_fields, source_line`

| Column | Meaning |
|---|---|
| `scope_type`, `scope` | `zone`/`<zone>` for addresses and address groups; `global` for services, service groups and schedulers; `interface`/`<interface>` for DIP pools |
| `object_type` | `address`, `address-group`, `service`, `service-group`, `dip-pool`, `scheduler` |
| `description` | The comment / `comment` text |
| `value_type`, `value` | Address: `ip-netmask` (CIDR), `ip`, `domain-name`, or `invalid` for a malformed IP. Service: protocol(s) and the text, for example `tcp` / `tcp/80; tcp/8080-8090`. DIP pool: `address-range` and `start-end`. Scheduler: its type and times |
| `members` | Direct members of a group, in config order |
| `members_resolved` | Fully flattened members (groups only) |
| `referenced_by_rules` | `yes` if reachable from any policy, MIP/VIP service or policy NAT, otherwise `no` |
| `other_fields` | Attributes not given their own column |
| `source_line` | Line number in the input file (the first line that defines the object) |

### `object_members.csv`

`logical_system, scope_type, scope, object_type, object, level, member, via`

One row per group member. `level` is `direct` or `resolved`; `via` shows the chain of nested groups for resolved rows.

### `rules_security-policy.csv`

`logical_system, scope_type, scope, rulebase, rule_number, name, policy_id, disabled, action, action_options, from_zone, to_zone, source, source_resolved, destination, destination_resolved, service, service_resolved, nat, nat_resolved, log, count, schedule, options, other_fields, parse_error, source_line, raw`

| Column | Meaning |
|---|---|
| `scope_type`, `scope` | `zone-pair` and `Trust>Untrust`, or `global` and `Global` |
| `rulebase` | `security-policy` |
| `rule_number` | 1-based position within the zone pair, in file order |
| `name` | The policy name from `name "..."` (blank if none). This is the only descriptive text ScreenOS keeps per policy |
| `policy_id` | The ScreenOS policy ID (not the same as the position) |
| `disabled` | `yes` if `set policy id N disable` is present |
| `action`, `action_options` | `permit`, `deny`, `reject` or `tunnel`; for tunnel, the VPN options |
| `source`, `destination`, `service` | As configured, with block-added entries appended, joined with `;` |
| `*_resolved` | Flattened contents |
| `nat`, `nat_resolved` | The NAT clause(s) as written, and what they translate to |
| `log` | `yes`, plus any block detail (for example `yes;session-close`) |
| `count` | `yes` if the policy has `count` |
| `schedule` | The scheduler name |
| `options` | Other options from the definition line (for example `traffic gbw 1000 priority 4 mbw 2000`) |
| `other_fields` | Other lines inside the policy block and attribute lines, as `keyword=value; ...` |
| `parse_error` | Blank normally; set if the policy line was truncated |
| `source_line`, `raw` | Line number and the original definition line |

### `rules_nat-mip.csv`

`logical_system, scope_type, scope, rulebase, rule_number, name, mapped_address, host, netmask, host_cidr, vr, other_fields, source_line, raw`

`scope` is the interface, `name` is the mapped (public) address, `host` is the internal address it maps to, and
`host_cidr` combines `host` and `netmask`.

### `rules_nat-vip.csv`

`logical_system, scope_type, scope, rulebase, rule_number, name, vip_address, port, service, service_resolved, server, other_fields, source_line, raw`

`scope` is the interface, `name` is `<vip>:<port>`, `service` is the service name used, and `server` is the internal address.
`vip_address` is `interface-ip` when the VIP uses the interface address.

### `rules_expanded.csv` (with `--expand`)

`logical_system, scope_type, scope, rulebase, rule_number, policy_id, name, action, disabled, from_zone, to_zone, source, destination, service`

One row per source x destination x service combination for each policy. `rule_number` repeats across the rows of the same
policy. Policies with a `parse_error` are omitted. `--max-expand` caps the rows per policy.

### `warnings.csv`

`logical_system, context, message, source_line`

---

## 7. Behaviour notes

### Rule order and numbering
- Policies are numbered **within each zone pair** in the order they appear in the file, which is the order the device
  evaluates them. The ScreenOS ID is kept in `policy_id`; IDs can be in any order if policies have been moved.
- Numbering restarts in **each logical system**: `rule_number` is the position within a zone pair of one vsys, and policy IDs repeat across
  vsys (so `policy_id 1` exists in each). Always use `logical_system` together with `policy_id` or `scope`.
- Global policies are numbered separately. On the device they are evaluated after the zone-pair policies; the script does
  not merge them into one sequence.

### Virtual systems (logical systems)

`get config` on the root device prints each vsys as a block that starts with `set vsys "<name>" zone <id> vrouter id <id>` and ends with its
own `exit`. Inside it are the vsys's own services, zones, addresses, address groups, policies, interfaces and routing config. The script
treats everything between the two as that vsys, and anything outside the blocks (before, between or after) as the root.

- **Separate namespaces.** Each logical system has its own address books, services and service groups, DIP pools, schedulers, MIP / VIP
  entries and policies. Resolution only looks inside the logical system the policy belongs to, so a `SRV` address defined in the root and
  in two vsys resolves to three different values, one per context.
- **Finding the end of a vsys.** A vsys block contains many nested blocks that each end with their own `exit`: `set vrouter "<name>"`,
  `set protocol bgp|ospf|rip ...` inside a vrouter, `set route-map name "<name>" ...` inside a vrouter, and `set policy id <n>`. The script
  keeps a stack of open blocks and pops one on every `exit`, so only the `exit` that returns to the top level ends the vsys. Routing
  configuration inside these blocks is skipped.
- **Shared objects.** If a vsys policy refers to an address or service that is not defined in that vsys but **is** defined in the root
  config (for example an address in a shared zone such as `Untrust`), it is resolved from the root and a warning says so
  (`... is not defined in this vsys; resolved from the root config`). The referenced root object is marked `referenced_by_rules = yes`.
  A reference that exists in neither is reported as unresolved as usual.
- **Nesting checks.** If block nesting gets out of step, the script says so rather than guessing. These cases are reported in
  `warnings.csv` and on the console, and make `--strict` exit with 1:
  an `exit` with no open block; a new `set vsys` while another block is still open (the stack is reset); and blocks still open at the end
  of the file (a truncated capture). The usual cause is a block type the script doesn't know about, or a damaged capture.
- **Repeated vsys name.** A second `set vsys "<same name>"` block is merged into the same logical system.

### Names and comments
- Address, service and group comments are kept in `description`.
- ScreenOS policies have a `name` but no separate comment field, so `name` is the policy's descriptive text.

### `referenced_by_rules`
An object is `yes` when it is reached while resolving a policy, a VIP service, a policy NAT clause (DIP pools) or a
policy schedule. Objects used only elsewhere (VPN proxy IDs, MIP hosts, route or interface config, other config sections)
show `no`. Treat it as "candidate unused", not proof.

### Group resolution
- Nested groups are flattened to any depth and de-duplicated, first occurrence kept.
- Circular references are detected, reported and do not loop.

### Duplicates
If an object is defined twice with the same name in the same scope, the later definition wins and a warning is raised.
Additional `+` lines for a service, and repeated `add` lines for a group, are intended and are not duplicates.

---

## 8. Warnings and troubleshooting

| Message (in `warnings.csv`) | Meaning / action |
|---|---|
| `unresolved address reference 'X (zone Z)'` | The policy names an address that isn't in the from-zone (source) or to-zone (destination) book. Check the zone names on the policy line |
| `unresolved service reference 'X'` | A service or group that isn't defined in the config and isn't in the predefined table. Add it with `--extra-services` if it is a predefined ScreenOS service |
| `unresolved scheduler / dip reference 'X'` | A policy refers to a scheduler or DIP id that isn't defined |
| `cycle in address group / service group 'X'` | Circular nesting; the loop is broken |
| `duplicate <type> name (later definition wins)` | The same name is defined twice in the same scope |
| `duplicate DIP id (later definition wins)` | The same DIP id is defined twice |
| `policy line too short` | A truncated `set policy` line. The row is kept with `parse_error` set |
| `attribute line without a definition line` | A `set policy id N ...` line refers to a policy that isn't defined in the file |
| `policy block without a definition line` | A `set policy id N` block has no definition line |
| `invalid IPv4 address '...'` | A numeric-looking address that isn't valid (for example `10.0.0.256`) |
| `could not parse (...)` | A line the script recognised as a ScreenOS object or policy command but couldn't interpret |
| `service group shares a name with a service` | A group and a service have the same name |
| `rule expands to N rows; truncated to M` | The expanded output hit `--max-expand` |

| Symptom | Likely cause |
|---|---|
| `ERROR: this looks like Junos 'display set' output` | The file is from an SRX / Junos device. Use `srx_parse.py`, which accepts both `show configuration` and `show configuration \| display set` |
| `ERROR: no ScreenOS 'set address / policy ...' commands found` | The file is not `get config` output, or is empty |
| Many unresolved services | The config uses predefined services missing from the built-in table. Use `--extra-services` |
| Unresolved addresses on policies that work on the device | The policy zones in the file don't match where the address is defined, or the capture is partial |
| `WARNING: block nesting got out of step` | An `exit` didn't match an open block, a vsys started while another block was open, or the file ended inside a block. Check the lines named in `warnings.csv`; truncated captures and unusual block types are the usual causes. Rows after that point may be assigned to the wrong logical system |
| `... is not defined in this vsys; resolved from the root config` | A vsys policy uses a root object (shared zone or service). Informational; the value shown is the root object's |
| Policy count looks low | The capture was cut off, or lines were wrapped by the terminal logger |

---

## 9. Verifying the results

The script does not compare itself with the device, so on first use:

1. **Policy counts.** Compare the console summary with the number of policy definition lines:
   `grep -cE '^set policy id [0-9]+ .* from ' get-config.txt`
2. **Spot-check on the device.** `get policy` lists policies per zone pair and `get policy id N` shows one in detail;
   compare several, including ones with extra block entries and NAT, with the `*_resolved` columns. Confirm the order of
   `rule_number` matches the order the device lists them.
3. **Review `warnings.csv`** and any `unresolved:` values before relying on the output.
4. Use `--strict` in scripted runs so problems fail loudly.

### Loading the output

```python
import csv

rules = list(csv.DictReader(open("output/2026-10-03_09-36-16/rules_security-policy.csv", encoding="utf-8")))
for r in rules:
    print(r["scope"], r["rule_number"], r["policy_id"], r["name"], r["action"], r["source_resolved"], r["service_resolved"])
```

In Excel, import the CSVs as UTF-8.

---

## 10. Comparing runs

Each run is kept in its own folder, so two runs (for example before and after a change window) can be compared directly:

```bash
# Linux / macOS
diff -r output/2026-10-03_09-36-16 output/2026-10-10_09-00-02

# Windows PowerShell (or any platform with git)
git diff --no-index output/2026-10-03_09-36-16 output/2026-10-10_09-00-02
```

- Output files contain no timestamps, so identical configs produce identical CSVs.
- `rule_number` shifts for every policy below an inserted or deleted one, and `source_line` shifts after any edit. To match
  policies between runs, join on `logical_system` plus `policy_id` (stable unless the policy is recreated) or on `logical_system`, `scope` and `name`.
- Compare the `*_resolved` columns if you only care about content changes.

Suggested `.gitignore` entry:

```
output/
```

---

## 11. Limitations

- **Not parsed:** VPN (IKE, tunnels, proxy IDs), routing, interface settings other than DIP / MIP / VIP, authentication,
  zones' attributes, IPv6 objects, and everything outside address books, services, schedulers, policies and the NAT items above.
- **Virtual systems:** supported, but the block structure was derived from one real sample (two vsys with BGP and route-map blocks). A block
  type that is not in the list in section 7 (vrouter, protocol, route-map, policy) could throw the `exit` counting off; the script reports
  this (it never guesses silently) but cannot fix it. Send the lines around the problem if it happens.
- **Shared / root objects** used by a vsys are resolved from the root with a warning; whether ScreenOS allows this for a given object type is
  not checked.
- **Predefined services:** only a subset is built in. Others are reported as unresolved until added with `--extra-services`.
- **Policy order:** file order is assumed to be evaluation order, which is how `get config` presents policies. Confirm this
  against the device on first use (see section 9).
- **Policy comments:** ScreenOS stores only a policy `name`, so there is no separate comment field to extract.
- **Syntax variants:** ScreenOS syntax differs between releases. Lines the script recognises but cannot interpret are listed in
  `warnings.csv`; unrecognised options inside a policy go to `options` or `other_fields` and are not dropped.
- **`referenced_by_rules`** only considers policies, VIP services and policy NAT.
- Written from the ScreenOS syntax as documented and tested only on a sample config, not on a real SSG / NetScreen export.
  Check the first real run carefully.
- No automated test suite beyond `--selftest`, and no formal schema for the CSVs.
