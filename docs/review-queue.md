# Human sign-off queue

Items an agent decided provisionally and must not self-approve. A human ticks each one, or sends it back.

## Junos defaults — `packs/vendors/junos.yaml` (all scoped `>=12.1`)

- [ ] `services.ssh.enabled` absent → `false`: no management service runs unless configured under `system services`.
- [ ] `services.ssh.version` absent → `2`: v2 only unless `protocol-version v1` is configured.
- [ ] `services.telnet.enabled`, `services.http.enabled`, `services.https.enabled` absent → `false` (same basis as SSH).
- [ ] `auth.aaa.enabled` absent → `false`: without `authentication-order`, only local passwords are checked.
- [ ] `ntp.authenticate` absent → `false`: without `trusted-key`, time from any configured server is accepted.
- [ ] `auth.login_banner.present` absent → `false`; `interfaces[].proxy_arp` absent → `false`; `interfaces[].shutdown` absent → `false`.

Deliberately left `unknown` (default not certain): `tries-before-disconnect` (believed 10), `password minimum-length`.

## Choices made while implementing the 2.2 review

- [ ] `partial: lower_bound` — the review specified the lower-bound behaviour but named only `counterexample_sufficient`;
      a second value was added for whole-list rules such as `length(logging.servers) > 0`.
- [ ] Rule opt-ins in `cis.yaml` 1.1.0: `counterexample_sufficient` on local_users.strong_hash, interfaces.no_proxy_arp,
      vty.ssh_only, vty.access_class; `lower_bound` on logging.remote_host.
- [ ] Operator `--os-version`: a version stated in the config wins over the operator's, with a warning. Recorded as
      `state: defaulted`, `evidence.source: operator` (the schema's `mapped` requires a config line).
- [ ] Junos fixes end in `commit confirmed 5` and roll back with `rollback 1`. `fix_ntp_authenticate` uses `type md5`
      for compatibility with 12.1; newer releases accept `sha256`.

## Learning loop (PLAN 2.3–2.6)

- [ ] Normaliser placeholder classes: `<INT> <IPV4> <PREFIX> <IPV6> <MAC> <STR> <IFACE> <DOMAIN> <NAME>`. `<NAME>` comes only from the
      device's own canonical model (hostname, collection keys), never from spelling. So route-map, prefix-list and zone names stay literal,
      and such lines cluster per name.
- [ ] Block headers (lines with children) are never questions.
- [ ] Confirm refuses rather than guesses: a true/false field needs a stated value, a line with more than one candidate value needs a
      stated value, and an item attribute needs a slot that names an item the device already lists.
- [ ] Learned fixtures are synthetic: documentation addresses (192.0.2.1, 2001:db8::1, 0000.5e00.5300), `example` and `example.com`.
      Integers and interface names are kept from the sample line.
- [ ] Ranking weights: 0.6 × TF-IDF cosine + 0.4 × token overlap, halved when an integer field meets a line with no integer. Field
      path words count twice. Known misses: `ios.logging.trap`, `ios.ssh.auth_retries`, `junos.ssh.version`.
- [ ] A confirmation with no `author` is recorded as `author: unattributed`.

## Ignore entries and the ranking measurement (2026-10-07)

- [ ] Ignore scope is per vendor and permanent (a learned-pack entry). There is no per-scan or per-device ignore.
- [ ] An ignore applies only when no mapping matches the line. A line a mapping matches but cannot read (a capture
      missing from `map:`) is refused with 409, because the mapping needs extending.
- [ ] Ignores apply to leaf lines only, never to a block header.
- [ ] `reason` needs at least 2 non-space characters. Nothing checks what it says.
- [ ] Two descriptions reworded so the config's own words appear: `logging.level` (trap level, informational) and
      `services.ssh.max_auth_tries` (authentication retries). `services.ssh.version` now says "SSH". No field renamed.
- [ ] **Hand labels in `docs/ranking-eval.md`** (30 clusters, labelled by the agent). In particular, #20
      `line con 0 / exec-timeout 0 0` → `session.idle_timeout`, and #7/#9 `privilege level 15` → no v1 field.
- [ ] Catalogue gap, team decision: a field for console/aux `privilege level` (automatic privileged shell).

## Reader divergence — `brace_tree` vs `set_commands` (PLAN 3.1)

- [ ] **Decide: normalise or keep.** A flat file holding both `set a b` and `set a b c` yields two statements; the brace
      form of that configuration (`a { b { c; } }`) yields one, `a b c`. A mapping that matches the prefix alone
      (`services ssh` → `services.ssh.enabled`) then sees different input, and a verdict depends on which encoding the
      operator uploaded.
      **Assumption carried until decided:** Junos `display set` prints only leaves, so device output never holds both
      lines; only a hand-edited or concatenated flat file does. This is a claim about vendor output and has not been
      checked against a captured pair (PLAN 3.1c). Pinned by
      `test_documented_divergence_flat_prefix_statement_has_no_brace_equivalent`; documented in `brace_tree.py`.
      Options: (a) `set_commands` drops a statement that is a strict prefix of another live one, (b) `brace_tree` emits
      every block header as a statement too, (c) keep, and rely on the assumption.

## Redaction findings — one list (2.2 audit, then 3.1)

Two classes. A **wrong-token** finding masks a setting or leaves a secret in clear, and costs one field or one leak. A
**structural** finding eats a delimiter and fails the whole file. Structural is worse; it is now caught as a class by
`tests/test_redaction_structure.py` (every fixture, plus every secret keyword × every brace-form line shape).

- [ ] Wrong token, 2.2 (`cf9c59e`, `be2a6b4`, `4d1b0fa`): password policy words (`minimum-length`, `format`,
      `change-type`) masked as secrets; 10 leaks closed by matching constructs, not keywords.
- [ ] Structural, 3.1: `key 0 {` (a key-chain block in brace-form Junos) masked to `key 0 ****`; any secret keyword
      followed by `{` or `[` had the same fault. Fixed: a value never starts with `{` or `[`.
- [ ] Wrong token, 3.1: a Junos encoding word on its own line under its keyword's block (`ascii-text "X";`) was left
      in clear. Fixed for quoted values after `ascii-text` and `hexadecimal`.
- [ ] Structural and leak, 3.1: `snmp community` took `\S+`. It ate `;` and `{`, and a quoted community with a space
      (`"two words"`) was masked only up to the space, so the rest stayed in clear. Fixed: quoted value is one token;
      a bare value stops at a delimiter.
- [ ] Still not done, for 3.9: `snmp-server host` (IOS/NX-OS) still takes `\S+`; it has no brace form, so no
      structural risk, but a quoted community there leaks the same way (`"two words"` → `**** words"`). Pinned by
      `test_snmp_host_quoted_community_is_masked_whole`, a strict xfail: the fix flips it and must remove the marker.

## STIG rule pack — `packs/rules/stig.yaml` 0.1.0 (PLAN 3.2)

Sign-off means: you read the check text in `docs/sources/stig-ndm-extract.md` and you agree the assertion
captures it, **for the reason written**, or you write a better one. "Looks right" is not a sign-off. The "case"
lines are the agent's argument, not approval.

- [ ] **`control` is the SRG ID**, not a product STIG ID. Case: our rules are vendor-neutral, and the SRG ID is
      the one identifier the Cisco (CISC-ND-…) and Juniper (JUNI-ND-…) STIGs share for each requirement. Both
      product IDs sit in a comment above each rule.
- [ ] `stig.logging.two_servers` · `SRG-APP-000516-NDM-000350` · `length(logging.servers) >= 2`, lower bound.
      Case: the rule titles in both STIGs say "at least two syslog servers". Caveat: the Cisco check's last sentence
      says only "not configured to send log data to the syslog servers"; we follow the title.
- [ ] `stig.vty.idle_timeout` · `SRG-APP-000190-NDM-000267` · every vty line: `0 < exec_timeout <= 300`.
      Case: Cisco check: `exec-timeout 5 0` on vty and console; `exec-timeout 0` means never, so it fails.
      **Narrower than the control:** console and aux are not checked, because the model has no field for them.
      **NOT_DETERMINED on every Junos device**, because Junos sets idle time per login class, and nothing maps that.
      Team decision: model a device-wide idle timeout (`session.idle_timeout`, unmapped today) or per-class items.
      Note that "0 = never" breaks a plain keep-the-weakest rule.
- [ ] `stig.password.min_length` · `SRG-APP-000164-NDM-000252` · `auth.password_min_length >= 15`.
      Case: both checks state 15. The Cisco check reads `aaa common-criteria policy … min-length`, which
      `cisco_ios.yaml` did not map: added as `ios.password_min_length.cc_policy`, weakest policy wins (`keep: min`).
      Without it, a device configured exactly as the STIG says would FAIL.
- [ ] `stig.ntp.two_servers` · `SRG-APP-000373-NDM-000298` · `length(ntp.servers) >= 2`, lower bound.
      Case: the check asks for "redundant authoritative time sources" and shows two `ntp server` lines. Reading
      "redundant" as "at least two configured" is ours. Server reachability is runtime state and out of scope
      (ARCHITECTURE known limits).
- [ ] `stig.aaa.two_servers` · `SRG-APP-000516-NDM-000336` · `length(auth.aaa.servers) >= 2`, lower bound.
      Case: both titles say "at least two authentication servers". Partial: the STIG also requires that the
      servers are the *primary* source in the login method list; we do not check method order.
- [ ] **New canonical field `auth.aaa.servers[]`** (additive). Mapped from IOS `radius-server host` /
      `tacacs-server host`, IOS named `radius|tacacs server NAME` + `address ipv4`, and Junos
      `system radius-server` / `tacplus-server`. No line means a mapped empty list. No fixture configures a server,
      so every device FAILs this rule today. That is a true finding on these configs, not a test of the mapping.
- [ ] Source currency: the Juniper STIG used is V3R2 (Jan 2025); a newer release may exist. See the extract header.
