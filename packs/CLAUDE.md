# packs/CLAUDE.md

Artifact formats and the canonical field list. Applies to everything under
`packs/` and `schemas/`.

**Packs are data, not code.** Nothing here may require a Python change to take
effect. Every pack is validated against `schemas/packs.schema.json` at load time,
and a rejected pack must fail with a message naming the offending field. The
registry also runs every fixture at load: a mapping whose fixture does not match
it, two mappings claiming one line at equal priority, or a rule whose pass/fail
fixtures disagree with it, rejects that pack. Other packs keep working.

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

auth.aaa.enabled | auth.aaa.servers[]
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
    default: true            # IOS enables proxy ARP unless told otherwise
    default_os_version: ">=12.0"
    fixture: |
      interface GigabitEthernet0/1
       ip proxy-arp
    expect: true
```

Collections are declared by a mapping whose `canonical` ends in `[]`. Each match
creates an item; named groups fill item attributes; `empty: mapped|unknown` says
what zero matches means. `map:` translates captured text (per attribute for
collections), `defaults:` fills attributes a line leaves out, `auto_key: true`
numbers keyless items 10, 20, …. A capture not listed in `map:` means the line is
not understood and goes to the learning queue. `scope:` is a template
(`interface {name}`) or, when the template is too loose, an anchored regex with
named groups (`^line (?P<name>vty \d+(?: \d+)?)$`).

`absent:` is the whole `NOT_DETERMINED` mechanism expressed as data:
`unknown` means we cannot say, `default` means the pack declares what the device
does when the line is missing. A declared default must be scoped to an OS version
range — defaults change between releases.

`{name}` comes from the enclosing block the reader identified. That is the join
between reader and mapper.

`priority:` (optional int) resolves two mappings matching one line. Learned
mappings outrank base packs by default. The loader must reject ambiguous overlaps
rather than picking nondeterministically.

`keep: min|max` (scalars only) is for a setting written as a list over several
lines, such as Junos `protocol-version v1` plus `protocol-version v2`. It keeps the
weakest or strongest value instead of the last line. Without it, line order decides
the verdict.

`unresolved_inheritance:` (pack level) lists regexes searched in every effective
statement, e.g. Junos `apply-groups`. A hit means the file inherits configuration
the pack does not resolve. Absent fields then stay `unknown` instead of defaulted,
and every collection is marked unread, because a group can add items the local lines
do not show.

`constants:` (pack level) states facts true of every device on the platform,
whatever the config says. Example: `discovery.cdp_enabled: false` on Junos, which
has no CDP. They are emitted as `defaulted` with `evidence.source:
platform_constant`. They apply with no OS version and under `apply-groups`. A field
cannot be both a constant and a mapping target; the loader rejects that. Never
invent a command so that a fact has something to match.

The operator can supply an OS version (`scan --os-version`). It is used only when
the config states none, and it is recorded with `evidence.source: operator`. The
engine never infers a version from syntax.

Flat-syntax packs (`reader: set_commands` or `brace_tree`) see the whole path in each
statement, so collection keys are named groups in `match`, and `scope` is not used.
Fixtures are written with the `set` verb, as the device prints them. `brace_tree` reads
both the hierarchical and the `display set` encoding to identical statements, and its
`detect` and `facts` patterns are written once, against the `set` display form.

Detection signatures must be anchored and weighted. `^switchname` discriminates;
`^hostname` does not. Two packs tying is an explicit ambiguous state, never
first-match-wins.

---

## Rule pack — `packs/rules/cis.yaml`

```yaml
id: cis
version: 1.0.0
framework: cis
rules:
  - id: cis.ssh.version_2
    title: Only SSH protocol version 2 is accepted
    control: null            # human cites the benchmark control ID; never guessed
    applies_to: {os_family: '*'}
    requires: [services.ssh.version]
    assert: 'services.ssh.version == `2`'
    severity: high
    fix: fix_ssh_v2
    fixtures:                # canonical-model fragments, never vendor syntax
      pass: {services.ssh.version: 2}
      fail: {services.ssh.version: 1}

  - id: cis.interfaces.no_proxy_arp
    for_each: 'interfaces[]' # assertion runs per item; FAIL lists failing items
    requires: ['interfaces[].proxy_arp', 'interfaces[].shutdown']
    assert: 'shutdown == `true` || proxy_arp == `false`'
    ...
```

Rule fixtures are canonical fragments so the rule pack stays vendor-neutral; the
vendor side is proven by mapping fixtures and by the fix round-trip test. Every
field an assertion reads must appear in `requires` — the loader rejects a rule
that reads anything else (a bare `null` in JMESPath is a field; write `` `null` ``).
Quote paths containing `[]` inside YAML flow collections.

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
id: cisco_ios_fixes
version: 1.0.0
vendor_pack: cisco_ios
fixes:
  - id: fix_no_proxy_arp
    os_version: '>=12.0'
    commands: [configure terminal, '{items}', end, write memory]
    item_commands: ['interface {name}', ' no ip proxy-arp', ' exit']
    rollback: [configure terminal, '{items}', end]
    item_rollback: ['interface {name}', ' ip proxy-arp', ' exit']
    reload_required: false
    operator_input: []       # e.g. [<NEW_SECRET>] — placeholders the operator must fill
```

A fix whose `os_version` range excludes the device is withheld, not rendered.

`item_commands_for: {<item name>: [...]}` replaces `item_commands` for one item, for
when a vendor keeps that item somewhere else. Junos `root`, for example, lives at
`system root-authentication`, not under `system login user`.

Rendered commands must be idempotent — safe to paste twice — and must flag
anything needing a reload. Per-interface failures render a fix naming that
specific interface, pulled from the canonical model.

---

## Learned mappings — `packs/learned/cisco_ios.yaml`

```yaml
vendor_pack: cisco_ios
version: 0.1.0
mappings:            # identical schema to a vendor pack's mappings, plus:
  - ...              # source: learned, author, created, cluster_signature
```

Learned mappings get priority 100 (shipped: 0), so they outrank shipped ones.

### Ignore entries — "not a security setting"

A line that carries no security setting (`boot-start-marker`, `end`) is answered with
an ignore entry in the same `mappings:` list. It is a mapping with no target:

```yaml
  - id: cisco_ios.ignore.c1a2b3c4d5e6f7a8
    canonical: null
    ignore: true
    match: "^boot-start-marker$"
    reason: structural marker, carries no security setting   # required, free text
    fixture: boot-start-marker
    source: learned          # plus author, created, cluster_signature as usual
```

An ignore is **"this text carries no setting", never "this setting is fine"**. It only
removes the line from the learning queue. It writes nothing to the canonical model,
so it cannot change a verdict, and a rule whose field is still unmapped stays
`NOT_DETERMINED`. Other rules:

- `reason` is required. An ignore with no stated reason is how a real setting gets
  dropped without anyone noticing.
- No `absent`, `value`, `cast`, `default` or `expect`: there is no field to fill.
- It applies only when no mapping matches the line. A line a mapping matches but
  cannot read (a capture missing from `map:`) stays in the queue. The loader rejects
  an ignore whose fixture a mapping matches: an ignore never hides a mapped line.
- It applies to leaf lines only. A block header is never a question, and ignoring
  one would not hide the lines inside it.
- Scope is the vendor, for good: it lives in the vendor's learned pack. There is no
  per-scan or per-device ignore yet.
- It is removed like any pack entry: delete it and the line returns to the queue.

An administrator's labelling session **is** a pack fragment — exportable and
shippable as a first-class vendor pack next release. That equivalence is the point;
do not invent a second format for learned content.

---

## Fixtures are mandatory

Every mapping ships a config snippet that must match (and `expect:` the value it
must produce). Every rule ships one canonical fragment that must `PASS` and one
that must `FAIL`, and must return `NOT_DETERMINED` on an unread device.

This is the regression suite, and it is also the answer when a judge asks how we
know the CIS translations are correct. A mistranslated rule without fixtures is
silently wrong on every device, forever.
