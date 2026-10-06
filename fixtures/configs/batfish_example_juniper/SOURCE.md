# Source

Copied unmodified from https://github.com/batfish/batfish/tree/b5b6b1bc0ee6a7e8ec79aeaf871ad4244e0b56df/tests/parsing-tests/networks/example-juniper/configs
(2 Junos configs). Licence: Apache License 2.0 — https://github.com/batfish/batfish/blob/master/LICENSE

Junos in flat `set` syntax, not hierarchical braces. Same device roles as
`../batfish_example_live/as1border1.cfg` and `as1border2.cfg` (Cisco IOS), so the same
router can be audited in two vendor dialects against the same canonical fields.

The other 12 files in that upstream directory are Cisco IOS despite its name and were not copied.

Never edit these files to make a test pass.
