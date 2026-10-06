# Source

Copied unmodified from https://github.com/batfish/batfish/tree/b5b6b1bc0ee6a7e8ec79aeaf871ad4244e0b56df/tests/parsing-tests/networks/unit-tests/configs
(`nxos/` subfolder plus `nxos_acl`, 7 files). Licence: Apache License 2.0 — https://github.com/batfish/batfish/blob/master/LICENSE

These are Batfish **parser test snippets**, not whole device configs — Batfish has no full
NX-OS device config. NX-OS is indentation-structured, so these exercise the existing
`indent_blocks` reader. A demo-grade NX-OS config must come from elsewhere.

Never edit these files to make a test pass.
