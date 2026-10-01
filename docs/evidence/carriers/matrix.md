| network that does it | blocking | IPv4 | IPv6 |
|---|---|---|---|
| sender | open | ✓ UDP (1 s) | ✓ UDP (1 s) |
| sender | udp_blocked | ✓ TCP (10 s) | ✓ TCP (10 s) |
| sender | udp_cut | ✓ UDP, then TCP (8 s) | ✓ UDP, then TCP (8 s) |
| sender | udp_policed | ✓ UDP, then TCP (held back) (17 s) | ✓ UDP, then TCP (held back) (17 s) |
| sender | tcp443_only | ✓ relay/TLS (5 s) | ✓ relay/TLS (6 s) |
| sender | tls_inspected | ✓ refused: TLS opened on the way (8 s) | ✓ refused: TLS opened on the way (8 s) |
| receiver | open | ✓ UDP (1 s) | ✓ UDP (1 s) |
| receiver | udp_blocked | ✓ relay/UDP, then TCP (9 s) | ✓ TCP (10 s) |
| receiver | udp_cut | ✓ UDP, then TCP (8 s) | ✓ UDP, then TCP (8 s) |
| receiver | udp_policed | ✓ UDP, then TCP (held back) (17 s) | ✓ UDP, then TCP (held back) (17 s) |
| receiver | tcp443_only | ✓ relay/UDP, receiver over TLS (2 s) | ✓ relay/UDP, receiver over TLS (3 s) |
| receiver | tls_inspected | ✓ refused: TLS opened on the way (1 s) | ✓ refused: TLS opened on the way (1 s) |
