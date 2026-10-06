# Source

Copied unmodified from https://github.com/batfish/batfish/tree/b5b6b1bc0ee6a7e8ec79aeaf871ad4244e0b56df/tests/parsing-tests/networks/srx-testbed/configs
(3 Junos SRX configs). Licence: Apache License 2.0 — https://github.com/batfish/batfish/blob/master/LICENSE

Junos in flat `set` syntax. Contains md5-crypt (`$1$`) password hashes, a `$9$`
pre-shared key and SSH public keys exactly as published upstream — useful for redaction
and hash-strength tests. Not secrets of ours; still never log raw lines from these files.

Never edit these files to make a test pass.
