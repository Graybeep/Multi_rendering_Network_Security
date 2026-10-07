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
