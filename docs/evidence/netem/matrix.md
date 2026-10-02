| profile | the network | result |
|---|---|---|
| clean | 20 ms round trip, 50 Mbit/s, a queue of a round trip and more | ✓ 46.4 Mbit/s of 50 (93%), 0.0% sent again, 4.3 s |
| loss_1 | 1 % random loss towards the receiver | ✓ 41.5 Mbit/s of 50 (83%), 0.9% sent again, 4.8 s |
| loss_5 | 5 % random loss | ✓ 27.0 Mbit/s of 50 (54%), 4.9% sent again, 5.0 s |
| loss_10 | 10 % random loss | ✓ 24.1 Mbit/s of 50 (48%), 11.6% sent again, 4.2 s |
| loss_20 | 20 % lost towards the receiver, 5 % of the ACKs | ✓ 7.7 Mbit/s of 50 (15%), 24.8% sent again, 8.7 s |
| loss_30 | 30 % lost towards the receiver, 10 % of the ACKs | ◐ 2.6 Mbit/s of 50 (5%), 45.2% sent again, 19.3 s — below 8% of the bottleneck |
| burst_loss | losses in bursts (Gilbert–Elliott: 1 % into a bad state that loses 70 %) | ◐ 10.4 Mbit/s of 50 (21%), 6.2% sent again, 12.9 s — below 40% of the bottleneck |
| jitter | 80 ms round trip, ±20 ms each way: packets overtake each other | ✓ 40.5 Mbit/s of 50 (81%), 0.0% sent again, 3.3 s |
| reorder | a tenth of the packets 20 ms ahead of the rest, behind a 50 Mbit/s bottleneck | ◐ 35.4 Mbit/s of 50 (71%), 6.6% sent again, 3.8 s — more than 5% sent again |
| duplicate | 5 % of the packets twice, both ways | ✓ 43.9 Mbit/s of 50 (88%), 0.0% sent again, 3.1 s |
| satellite | 600 ms round trip, 20 Mbit/s, 0.5 % loss (geostationary) | ✓ 11.3 Mbit/s of 20 (56%), 0.3% sent again, 11.9 s |
| asymmetric | 50 Mbit/s down, 0.5 Mbit/s back: the ACKs' way is narrow | ✓ 45.2 Mbit/s of 50 (90%), 0.0% sent again, 3.0 s |
| bufferbloat | 20 Mbit/s with 3 s of queue: what the sender fills of it | ◐ 18.7 Mbit/s of 20 (94%), 0.0% sent again, 7.2 s; ping 24 ms idle, median 381 ms and top 383 ms under it — the queue adds 357 ms (at most 150) |
| tcp_fair | 20 Mbit/s shared with a TCP bulk flow | ✓ 15.1 Mbit/s of 20 (76%), 0.1% sent again, 8.9 s; TCP 8.8 Mbit/s alongside: the sender's share 63% |
| mtu_1240 | a path MTU of 1240 bytes: below what IPv6 promises, above what the handshake needs | ✓ 44.4 Mbit/s of 50 (89%), 0.0% sent again, 1.5 s |
| mtu_1000 | a path MTU of 1000 bytes: the handshake's 1200-byte datagrams do not pass (THREAT_MODEL Р7) | ✓ not delivered within 40 s — no handshake, as THREAT_MODEL Р7 says |
