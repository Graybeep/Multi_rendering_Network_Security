# Source

Copied unmodified from https://github.com/batfish/batfish/tree/b5b6b1bc0ee6a7e8ec79aeaf871ad4244e0b56df/projects/batfish/src/test/resources/org/batfish/grammar/juniper/testconfigs
(10 files). Licence: Apache License 2.0 — https://github.com/batfish/batfish/blob/master/LICENSE

These are Batfish **parser test snippets**, not whole device configs. They are the only
hierarchical (curly-brace) Junos in the Batfish repository, and they exist to exercise
edge cases: line and block comments, `set` lines mixed into a brace file, an
unbalanced quote, `secret` data, and deliberately misbraced input. Use them as
`brace_tree` reader fixtures, not as audit targets.

Never edit these files to make a test pass.
