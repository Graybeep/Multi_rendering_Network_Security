"""Redaction regression table. One row per construct; each comment names the platform and command.

Two failure modes, both tested: a non-secret masked (destroys a setting a rule reads) and a secret left
in clear (invariant 2). Inputs are syntax examples, not device data.
"""

import pytest

from src.ingest.redact import redact_line

# Lines that carry no secret and must pass through unchanged.
NOT_SECRETS = [
    "set system login password minimum-length 12",          # Junos password policy
    "set system login password minimum-upper-cases 1",      # Junos password policy
    "set system login password maximum-length 64",          # Junos password policy
    "set system login password change-type character-sets",  # Junos password policy
    "set system login password format sha512",              # Junos hash format for new passwords
    "set system authentication-order password",             # Junos: local passwords as a method
    "set system login retry-options tries-before-disconnect 3",  # Junos retry limit
    "set system root-authentication plain-text-password",   # Junos: prompts interactively; no value
    "set security ike proposal p1 authentication-method pre-shared-keys",  # Junos IKE method name
    "service password-encryption",                          # IOS
    "no service password-encryption",                       # IOS
    "security passwords min-length 8",                      # IOS password policy
    "password encryption aes",                              # IOS: enables type 6 encryption
    "password strength-check",                              # NX-OS password policy
    "no password strength-check",                           # NX-OS password policy
    "ip ssh authentication-retries 3",                      # IOS retry limit
    "login block-for 120 attempts 3 within 60",             # IOS login lockout
    "crypto key generate rsa modulus 2048",                 # IOS key generation, no key material
    "key chain OSPF-KEYS",                                  # IOS key chain name
    " key 1",                                               # IOS key id inside a key chain
    "ntp trusted-key 1",                                    # IOS NTP key id
    "ntp server 10.1.2.3 use-vrf management key 12345 minpoll 10 maxpoll 10",  # NX-OS key id
    "snmp-server community public RO",                      # well-known default, kept so a rule can flag it
    "set policy-options community as1_to_as2_community members 1:2",  # Junos BGP community, not SNMP
    "aaa authentication enable default enable",             # IOS method list
    "            key 0 {",                                  # Junos brace form: key-chain key id opens a block
    "        encrypted-password {",                         # a block header; `{` is never a secret
]

# Lines with a secret. Expected output keeps the algorithm or encoding token, masks the secret.
SECRETS = [
    ("enable secret 9 $9$abc$def", "enable secret 9 $9$****"),                        # IOS
    ("enable secret level 15 5 $1$mERr$hx5r", "enable secret level 15 5 $1$****"),   # IOS per-level secret
    ("enable password 7 0822455D0A16", "enable password 7 ****"),                     # IOS
    ("username admin privilege 15 secret 8 $8$xyz", "username admin privilege 15 secret 8 $8$****"),
    (" neighbor 10.0.0.2 password 7 0822455D0A16", " neighbor 10.0.0.2 password 7 ****"),  # IOS BGP
    (" ip ospf message-digest-key 1 md5 s3cret", " ip ospf message-digest-key 1 md5 ****"),  # IOS OSPF
    (" ip ospf message-digest-key 1 md5 7 0822455D", " ip ospf message-digest-key 1 md5 7 ****"),
    (" ip ospf authentication-key s3cret", " ip ospf authentication-key ****"),       # IOS OSPF
    (" key-string 7 0822455D0A16", " key-string 7 ****"),                             # IOS key chain
    ("crypto isakmp key s3cret address 10.0.0.2", "crypto isakmp key **** address 10.0.0.2"),  # IOS IKE
    ("crypto isakmp key 6 s3cret address 10.0.0.2", "crypto isakmp key 6 **** address 10.0.0.2"),
    ("tacacs-server key 7 1234ABCD", "tacacs-server key 7 ****"),                    # IOS
    ("radius-server key s3cret", "radius-server key ****"),                           # IOS
    ("snmp-server community Xy9!secret RO", "snmp-server community **** RO"),          # IOS
    ("snmp-server host 10.0.0.9 version 2c Xy9secret", "snmp-server host 10.0.0.9 version 2c ****"),  # IOS
    ("snmp-server host 10.0.0.9 Xy9secret", "snmp-server host 10.0.0.9 ****"),       # IOS, v1 implied
    ("snmp-server user u1 g1 v3 auth sha AuthPass1 priv aes 128 PrivPass1",          # IOS SNMPv3
     "snmp-server user u1 g1 v3 auth sha **** priv aes 128 ****"),
    ("ntp authentication-key 1 md5 s3cret 7", "ntp authentication-key 1 md5 **** 7"),  # IOS NTP
    ('set system ntp authentication-key 1 type md5 value "$9$abc"',                  # Junos NTP
     "set system ntp authentication-key 1 type md5 value $9$****"),
    ('set protocols bgp group g authentication-key "$9$abc"', "set protocols bgp group g authentication-key $9$****"),
    ('set system radius-server 10.0.0.1 secret "two words"', "set system radius-server 10.0.0.1 secret ****"),
    ('set snmp community s3cr3t authorization read-only', "set snmp community **** authorization read-only"),
    ('set snmp v3 usm local-engine user u1 authentication-sha authentication-password "AuthPass1"',  # Junos
     "set snmp v3 usm local-engine user u1 authentication-sha authentication-password ****"),
    ('set snmp v3 usm local-engine user u1 privacy-aes128 privacy-password "PrivPass1"',  # Junos
     "set snmp v3 usm local-engine user u1 privacy-aes128 privacy-password ****"),
    ('set security ike policy p pre-shared-key ascii-text "$9$abc"', "set security ike policy p pre-shared-key ascii-text $9$****"),
    ('                    ascii-text "$9$abc"; ## SECRET-DATA',  # Junos brace form, under `pre-shared-key {`
     "                    ascii-text $9$****; ## SECRET-DATA"),
    ('    hexadecimal "two words";', "    hexadecimal ****;"),                         # Junos brace form
    ("    set password ENC SH2abc==", "    set password ENC ****"),                   # FortiOS
    ("    set psksecret ENC xyz", "    set psksecret ENC ****"),                       # FortiOS
    ("    set passwd ENC xyz", "    set passwd ENC ****"),                             # FortiOS
]


@pytest.mark.parametrize("line", NOT_SECRETS)
def test_not_a_secret_is_left_alone(line: str) -> None:
    assert redact_line(line) == line


@pytest.mark.parametrize("line, expected", SECRETS)
def test_secret_is_masked_and_keeps_its_algorithm(line: str, expected: str) -> None:
    assert redact_line(line) == expected
