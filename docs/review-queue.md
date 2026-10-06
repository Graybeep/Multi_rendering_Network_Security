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
