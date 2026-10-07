# Synthetic fixtures

Hand-written configs that exercise a code path no real fixture reaches. They are **not device data**.

Rules:
- Every file starts with a `!` comment block saying it is synthetic, who wrote it and which path it exercises.
- Addresses are documentation ranges only (192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32).
- They never appear in a demo, a report, a screenshot or a slide (CLAUDE.md invariant 4).
  `tests/test_synthetic_fixtures.py` checks that no demo script reads this folder.
- A real config that exercises the same path replaces the synthetic one.
