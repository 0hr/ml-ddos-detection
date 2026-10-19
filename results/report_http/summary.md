# Testbed experiment results

Comparison of normal operation, high (benign) load, and controlled suspicious traffic with mitigation disabled vs enabled.

Each scenario was run **3 times**; values are **mean (min–max)** over the runs.

## Service availability

| scenario | runs | attack | mitigation | requests | success overall | success during attack | median latency (ms) |
|---|---|---|---|---|---|---|---|
| normal | 3 | - | off | 445 (403–470) | 100.0% | 100.0% | 39.6 (39.5–39.6) |
| highload | 3 | - | off | 1901 (1873–1918) | 100.0% | 100.0% | 38.6 (38.5–38.7) |
| attack_nomit | 3 | http | off | 448 (406–474) | 100.0% | 100.0% | 36.6 (36.6–36.6) |
| attack_mit | 3 | http | on | 446 (403–471) | 100.0% | 100.0% | 39.3 (39.1–39.5) |

## Detection and mitigation

Detection latency runs from the first attack packet on the server link to the monitor's first block decision. Exposure is how much of the attack actually reached the server. Detect-only scenarios (mitigation off) log the blocks they *would* have requested (dry run), so they have no API or switch latency.

| scenario | detection (s) | API (ms) | switch confirm (ms) | attack exposure | block requests | renewals | false blocks (benign) |
|---|---|---|---|---|---|---|---|
| normal | - | - | - | - | 0 | 0 | none |
| highload | - | - | - | - | 0 | 0 | none |
| attack_nomit | 1.20 (1.08–1.33) | dry run | - | 99.3% (98.8%–100.0%) · 31.7 (31.6–31.9) s | 6 | 0 | none |
| attack_mit | 1.21 (1.08–1.33) | 1.20 (0.91–1.41) | 0.76 (0.52–0.91) | 5.0% (4.9%–5.2%) · 1.6 (1.6–1.7) s | 3 | 3 | none |

## Per-flow detection on testbed traffic

Counts are summed over all runs; rates are computed from the totals.

| scenario | flows | TP | FP | FN | TN | recall | precision | FPR |
|---|---|---|---|---|---|---|---|---|
| normal | 2,223 | - | 5 | - | 2,218 | - | - | 0.0022 |
| highload | 9,188 | - | 102 | - | 9,086 | - | - | 0.0111 |
| attack_nomit | 185,793 | 4,805 | 53 | 178,841 | 2,094 | 0.026 | 0.989 | 0.0247 |
| attack_mit | 9,141 | 121 | 6 | 6,824 | 2,190 | 0.017 | 0.953 | 0.0027 |

Per-flow false positives never became blocks unless listed under *false blocks*: the monitor needs several attack flows from one source before it acts.

## Benign flows flagged as attack

| scenario | flagged (all runs) | zero-payload TCP | fwd-only (no reply) | median duration (ms) |
|---|---|---|---|---|
| normal | 5 | 5 | 0 | 1.9 |
| highload | 102 | 102 | 21 | 1.4 |
| attack_nomit | 53 | 53 | 1 | 1.5 |
| attack_mit | 6 | 6 | 1 | 1.3 |

Zero-payload TCP flows carry no request data: connection tails left over when a flow is closed at FIN (as CICFlowMeter does), and SYN retransmissions from clients whose packets are being dropped by the flooded link. Both look like the SYN-flood class the model learned from CIC-DDoS2019.

## Capture health

The live monitor reads its own copy of the traffic (tap); `capture.pcap` is a separate archive capture. If the monitor cannot keep up, the kernel drops tap packets and its telemetry, detections and blocks are based on partial data.

| scenario | live monitor (tap) dropped | archive capture dropped |
|---|---|---|
| normal | 0 of 20,573 (0.0%) | 0 of 20,573 (0.0%) |
| highload | 0 of 86,087 (0.0%) | 0 of 86,087 (0.0%) |
| attack_nomit | 0 of 1,190,688 (0.0%) | 0 of 1,190,688 (0.0%) |
| attack_mit | 0 of 65,435 (0.0%) | 0 of 65,435 (0.0%) |

![attack traffic](attack_traffic.png)

![availability](availability.png)

![latency](latency_cdf.png)

![confusion](confusion_matrices.png)
