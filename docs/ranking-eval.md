# Lexical ranking: measured on real questions

2026-10-07 · ranker `src/learning/rank.py` (lexical tier only) · descriptions as reworded in the same commit.

## Method

- Input: the 13 real IOS configs in `fixtures/configs/batfish_example_live`, audited with the shipped
  packs. They yield **160 clusters** (questions).
- Sample: 30 clusters drawn with `random.Random(26155).sample(clusters, 30)`, then sorted by id.
- Each was labelled by hand against the v1 canonical field list in `packs/CLAUDE.md`: which field (if
  any) the line fills. Labels were written down before scoring the ranker against them.
- Scored: is the labelled field in the ranker's top 3?

**The labels were made by the agent (Claude), not by a network engineer.** They are in the table below
so a human can check them. The sign-off item is in `docs/review-queue.md`.

## Result

| | count |
|---|---|
| Questions with a defensible v1 field | **1 of 30** |
| ... of which the right field is in the top 3 | **0 of 1** |
| Security-relevant, but no v1 field exists | 2 of 30 |
| Routing policy and topology (BGP, route-maps, prefix and community lists, `network`, domain name) | 24 of 30 |
| Structural or hardware lines, no setting at all | 3 of 30 |

**For the slide:** in a random sample of 30 real questions, 29 have no matching field in the v1
catalogue, so the ranker had nothing correct to find. On the one question that did, it missed. Top-3
accuracy on real traffic **cannot be measured from this sample**: n = 1.

The 54/57 (now 56/57) figure is a regression check on the shipped mappings' own fixture lines. Two
descriptions were reworded after missing there. It is not an accuracy figure and should not be shown
as one.

## What this says

1. **The real queue is mostly not security configuration.** These are BGP lab configs, so routing
   dominates. The dominant answers are "not a security setting" and "no field fits". That supports
   building ignore before any better ranker.
2. **The queue is inflated.** BGP community values (`2:1`, `3:2`) are not normalised, and route-map,
   prefix-list and peer-group names stay literal by design (review queue: normaliser placeholder
   classes). So `set community 2:1 additive` and `set community 3:2 additive` are separate
   questions, as are the two `set local-preference 350` lines under different route-maps. Without
   that, 160 would be noticeably fewer. Not counted precisely here.
3. **Ignore has limited reach on named lines.** An ignore is built from the cluster signature, so
   one under `route-map as2_to_as1` does not cover the same line under `route-map as3_to_as1`. Each
   name needs its own answer.
4. **Scores carry some signal, n is tiny.** With no correct field, the top-1 score was at most 0.27,
   except `privilege level 15` → `auth.local_users[].privilege` at 0.41, which is wrong: it is the
   line's privilege, not a user's. The one real question scored 0.66 top-1, but on the wrong field.
   Across all 160 clusters the median top-1 score is 0.11. A "no confident match" threshold looks
   plausible, but do not set one from 30 rows.
5. **Catalogue gap:** `privilege level <INT>` on `line con` and `line aux` is a hardening setting
   (an automatic privileged shell at the console) and has no v1 field. Adding one would be a team
   decision. Adding is free; renaming is not.

## Labels

`—` means no v1 canonical field fits. Top 3 is the ranker's output; ✗ marks a miss.

| # | scope | line | devices | label | top 3 |
|---|---|---|---|---|---|
| 1 | — | `ip community-list expanded as3_community permit _3:` | 6 | — routing | snmp.version, interfaces[].ip_redirects, mgmt.vty_lines[].access_class |
| 2 | — | `ip prefix-list inbound_route_filter seq 10 permit 0.0.0.0/0 le 32` | 6 | — routing | interfaces[].ip_redirects, mgmt.vty_lines[].access_class |
| 3 | `route-map as3_to_as1 permit 100` | `set local-preference 350` | 2 | — routing | auth.local_users[].privilege, auth.local_users[].password_algorithm, auth.aaa.enabled |
| 4 | `route-map as2_to_as1 permit 2` | `set community 2:1 additive` | 2 | — routing | snmp.version |
| 5 | — | `ip domain name lab.local` | 13 | — not security | interfaces[].ip_redirects, device.hostname, device.model |
| 6 | `interface GigabitEthernet0/0` | `media-type gbic` | 13 | — hardware | interfaces[].shutdown, interfaces[].description, interfaces[].unreachables |
| 7 | `line aux 0` | `privilege level 15` | 13 | — security, no v1 field | auth.local_users[].privilege, logging.level, mgmt.vty_lines[].transport_input |
| 8 | `router bgp 1` | `exit-address-family` | 13 | — structural | device.os_family, interfaces[].ip_redirects, interfaces[].proxy_arp |
| 9 | `line con 0` | `privilege level 15` | 13 | — security, no v1 field | auth.local_users[].privilege, logging.level, mgmt.vty_lines[].transport_input |
| 10 | `route-map as3_to_as2 permit 100` | `set community 3:2 additive` | 4 | — routing | snmp.version |
| 11 | `address-family ipv4` | `neighbor as3 route-map filter-bogons in` | 1 | — routing | device.os_family, interfaces[].proxy_arp |
| 12 | `address-family ipv4` | `neighbor as3 route-map as3_to_as2 in` | 2 | — routing | device.os_family, interfaces[].proxy_arp |
| 13 | `router bgp 1` | `neighbor xanadu peer-group` | 1 | — routing | interfaces[].ip_redirects, mgmt.vty_lines[].transport_input, mgmt.vty_lines[].access_class |
| 14 | `route-map as4_to_as1 permit 100` | `match ip address prefix-list as4-prefixes` | 1 | — routing | interfaces[].ip_redirects, interfaces[].proxy_arp, mgmt.vty_lines[].access_class |
| 15 | `route-map as3_to_as2 permit 5` | `match ip address prefix-list default_list` | 1 | — routing | interfaces[].ip_redirects, mgmt.vty_lines[].access_class, interfaces[].proxy_arp |
| 16 | `router bgp 2` | `neighbor dept remote-as 65001` | 2 | — routing | interfaces[].ip_redirects, mgmt.vty_lines[].transport_input, logging.servers[] |
| 17 | `router bgp 1` | `neighbor 3.2.2.2 peer-group bad-ebgp` | 1 | — routing | interfaces[].ip_redirects, mgmt.vty_lines[].transport_input, mgmt.vty_lines[].access_class |
| 18 | `router bgp 1` | `neighbor 5.6.7.8 peer-group xanadu` | 1 | — routing | interfaces[].ip_redirects, mgmt.vty_lines[].transport_input, mgmt.vty_lines[].access_class |
| 19 | — | `ip community-list expanded as4_community permit _4:` | 1 | — routing | snmp.version, interfaces[].ip_redirects, mgmt.vty_lines[].access_class |
| 20 | `line con 0` | `exec-timeout 0 0` | 13 | **session.idle_timeout** (see note) | mgmt.vty_lines[].exec_timeout, services.ssh.timeout, mgmt.vty_lines[].transport_input ✗ |
| 21 | `route-map as2_to_as3 permit 1` | `set community 2:3 additive` | 2 | — routing | snmp.version |
| 22 | `route-map as3_to_as1 permit 2` | `set metric 50` | 2 | — routing | (none) |
| 23 | `router bgp 1` | `neighbor as2 peer-group` | 11 | — routing | interfaces[].ip_redirects, mgmt.vty_lines[].transport_input, mgmt.vty_lines[].access_class |
| 24 | `router bgp 1` | `neighbor as4 remote-as 4` | 1 | — routing | interfaces[].ip_redirects, mgmt.vty_lines[].transport_input, logging.servers[] |
| 25 | `route-map as3_to_as2 permit 1` | `set metric 50` | 2 | — routing | (none) |
| 26 | `address-family ipv4` | `neighbor as3 peer-group` | 1 | — routing | device.os_family, interfaces[].proxy_arp, mgmt.vty_lines[].transport_input |
| 27 | `address-family ipv4` | `neighbor as2 route-map as1_to_as2 out` | 2 | — routing | device.os_family, interfaces[].proxy_arp, session.idle_timeout |
| 28 | `address-family ipv4` | `network 1.0.1.0 mask 255.255.255.0` | 6 | — routing | device.os_family, interfaces[].shutdown, interfaces[].proxy_arp |
| 29 | `route-map as2_to_as1 permit 100` | `set local-preference 350` | 2 | — routing | auth.local_users[].privilege, auth.local_users[].password_algorithm, auth.aaa.enabled |
| 30 | — | `boot-end-marker` | 13 | — structural | (none) |

Note on #20: `session.idle_timeout` is "an idle administrative session", and a console session is one.
`mgmt.vty_lines[].exec_timeout` is remote logins only, and the IOS pack's vty scope does not include
`line con`. So the ranker's top pick is the near-miss field. The line also cannot be learned as asked:
`0 0` is minutes and seconds, and authoring refuses it (see `test_a_line_with_two_numbers_is_refused_rather_than_guessed`).
A human may reasonably label it differently. That is why the labels need sign-off.

## Reproduce

```sh
.venv/Scripts/python - <<'EOF'      # .venv/bin/python on macOS / Linux
import random
from pathlib import Path
from tests.test_learning import _audit_all
from src.mapping.canonical import Catalogue
from src.registry import Registry
from src.learning.cluster import build_clusters
from src.learning.rank import rank
cat = Catalogue.load(); snap = Registry(Path("packs"), cat).snapshot()
clusters = build_clusters(_audit_all(snap, cat), cat)
for c in sorted(random.Random(26155).sample(clusters, 30), key=lambda c: c.cluster_id):
    print(c.scope, "|", c.sample.raw.strip(), "|", [x["canonical_field"] for x in rank(c, cat, 3)])
EOF
```

The sample changes if the shipped packs change which lines are unmatched, so rerun it after pack edits.
