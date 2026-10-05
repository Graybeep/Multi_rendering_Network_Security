# packs/CLAUDE.md

Artifact formats and the canonical field list. Applies to everything under
`packs/` and `schemas/`.

**Packs are data, not code.** Nothing here may require a Python change to take
effect. Every pack is validated against its JSON Schema at load time, and a
rejected pack must fail with a message naming the offending field.

```
packs/vendors/    one per vendor — detection, facts, command mappings
packs/rules/      one per framework — assertions over the canonical model
packs/fixes/      one per vendor — remediation CLI
packs/learned/    written at runtime by the training GUI
```

---

## Canonical field list (v1 — ~45 fields)

Grow only as rules need them. **Renaming breaks every pack and rule already
written; adding is free.** Name carefully, add freely.

```
device.hostname | vendor | os_family | os_version | model | serial

services.ssh.enabled | .version | .timeout | .max_auth_tries
services.telnet.enabled
services.http.enabled | services.https.enabled

auth.aaa.enabled
auth.enable_secret.algorithm
auth.password_min_length
auth.login_banner.present
auth.local_users[].name | .privilege | .password_algorithm

session.idle_timeout

logging.enabled | .level | .buffered_enabled | .servers[]

ntp.authenticate | ntp.servers[]

snmp.version | snmp.traps_enabled
snmp.communities[].string_redacted | .access

interfaces[].name | .shutdown | .description | .proxy_arp | .ip_redirects
             | .unreachables | .switchport_mode | .access_vlan

mgmt.vty_lines[].transport_input | .access_class | .exec_timeout

acl.lists[].name | .entries[].seq | .entries[].action

discovery.cdp_enabled | discovery.lldp_enabled
```

Collections are not optional. Most real CIS and STIG checks quantify over lists —
"no interface has proxy-arp", "every vty line sets access-class". A flat
dictionary of scalars cannot express them.

Every field in `schemas/canonical.schema.json` carries a plain-English
`description`. That text is what the suggestion service ranks against, so write it
as a human would describe the setting, not as a restatement of the field name.

---

## Vendor pack — `packs/vendors/cisco_ios.yaml`

```yaml
id: cisco_ios
version: 1.0.0
reader: indent_blocks
detect:
  - "^Building configuration"
  - "^version 1[2-7]\\."
facts:
  os_version: {pattern: "^version (\\S+)", group: 1}
  serial:     {pattern: "Processor board ID (\\S+)", group: 1}
mappings:
  - id: ios.ssh.version
    canonical: services.ssh.version
    match: "^ip ssh version (\\d+)"
    cast: int
    absent: unknown
    fixture: "ip ssh version 2"

  - id: ios.intf.proxy_arp
    canonical: "interfaces[{name}].proxy_arp"
    scope: "interface {name}"
    match: "^ip proxy-arp$"
    value: true
    absent: default
    default: false
    fixture: "ip proxy-arp"
```

`absent:` is the whole `NOT_DETERMINED` mechanism expressed as data:
`unknown` means we cannot say, `default` means the pack declares what the device
does when the line is missing. A declared default must be scoped to an OS version
range — defaults change between releases.

`{name}` comes from the enclosing block the reader identified. That is the join
between reader and mapper.

`priority:` (optional int) resolves two mappings matching one line. Learned
mappings outrank base packs by default. The loader must reject ambiguous overlaps
rather than picking nondeterministically.

Detection signatures must be anchored and weighted. `^switchname` discriminates;
`^hostname` does not. Two packs tying is an explicit ambiguous state, never
first-match-wins.

---

## Rule pack — `packs/rules/cis.yaml`

```yaml
- id: CIS-NET-1.2.3
  framework: cis
  profile: 1
  title: SSH protocol version 2 is required
  applies_to: {os_family: "*", os_version: ">=12.0"}
  requires: [services.ssh.version]
  assert: "services.ssh.version == `2`"
  severity: high
  fix: fix_ssh_v2
  fixtures:
    pass: "ip ssh version 2"
    fail: "ip ssh version 1"
```

**Rule packs are per-framework and never mention a vendor.** If you find yourself
writing `cis_cisco.yaml`, the canonical model is not doing its job and you have
rebuilt the per-vendor coupling the project exists to avoid.

`requires` is load-bearing: it is what turns an unmapped field into
`NOT_DETERMINED` instead of a false `FAIL`.

Assertions are JMESPath. **Do not invent a DSL.**

Licensing: cite the control ID and write the assertion in your own words. Do not
reproduce benchmark prose — CIS and ISO text is not freely redistributable.

---

## Fix template — `packs/fixes/cisco_ios.yaml`

```yaml
- id: fix_ssh_v2
  vendor: cisco_ios
  os_version: ">=12.0"
  commands: ["configure terminal", "ip ssh version 2", "end", "write memory"]
  reload_required: false
  rollback: ["configure terminal", "ip ssh version 1", "end"]
```

Rendered commands must be idempotent — safe to paste twice — and must flag
anything needing a reload. Per-interface failures render a fix naming that
specific interface, pulled from the canonical model.

---

## Learned mappings — `packs/learned/cisco_ios.yaml`

Identical schema to a vendor pack's `mappings` block, plus
`{source: learned, author, created, cluster_signature}`.

An administrator's labelling session **is** a pack fragment — exportable and
shippable as a first-class vendor pack next release. That equivalence is the point;
do not invent a second format for learned content.

---

## Fixtures are mandatory

Every mapping ships a config snippet that must match. Every rule ships one snippet
that must `PASS` and one that must `FAIL`.

This is the regression suite, and it is also the answer when a judge asks how we
know the CIS translations are correct. A mistranslated rule without fixtures is
silently wrong on every device, forever.
