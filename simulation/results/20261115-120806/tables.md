# Simulated data vs CIC-DDoS2019

Simulated dataset: `/home/harun/PycharmProjects/ML-DDoS/simulation/data/20261115-120806/dataset.parquet` — 118,305 finished flows, 18 sessions, plus 21,942 in-progress snapshots used for training only.

Simulated split: by repetition: repetition 3 held out as test (3 repetitions). Train 59,880 · validation 14,970 rows (flows and snapshots) · test 51,024 finished flows.
CIC-DDoS2019 split: the one of ml/train.py (test 62,402 flows).

## Results

| train on | test on | flows | accuracy | precision | recall | F1 | FPR | ROC-AUC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CIC-DDoS2019 | CIC-DDoS2019 | 62,402 | 0.9990 | 0.9998 | 0.9991 | 0.9994 | 0.14% | 1.0000 |
| CIC-DDoS2019 | Simulated | 51,024 | 0.4041 | 0.8787 | 0.1812 | 0.3004 | 6.01% | 0.6345 |
| Simulated | CIC-DDoS2019 | 62,402 | 0.1202 | 0.8912 | 0.0024 | 0.0047 | 0.22% | 0.9112 |
| Simulated | Simulated | 51,024 | 0.7935 | 0.9940 | 0.7118 | 0.8296 | 1.03% | 0.9845 |
| Simulated, finished flows only | CIC-DDoS2019 | 62,402 | 0.1183 | 0.0000 | 0.0000 | 0.0000 | 0.04% | 0.9084 |
| Simulated, finished flows only | Simulated | 51,024 | 0.7940 | 0.9935 | 0.7128 | 0.8301 | 1.11% | 0.9824 |
| CIC + simulated | CIC-DDoS2019 | 62,402 | 0.9985 | 0.9999 | 0.9984 | 0.9991 | 0.07% | 1.0000 |
| CIC + simulated | Simulated | 51,024 | 0.8991 | 0.9850 | 0.8705 | 0.9242 | 3.19% | 0.9863 |

## Simulated test set, per class

| class | test flows | CIC-DDoS2019 | Simulated, finished flows only | Simulated | CIC + simulated |
| --- | ---: | ---: | ---: | ---: | ---: |
| Sim-HTTP-flood | 12,063 | 4.0% | 27.6% | 26.9% | 61.4% |
| Sim-TCP-connect-flood | 22,430 | 20.1% | 99.6% | 99.9% | 99.9% |
| Sim-UDP-flood | 1,536 | 100.0% | 0.0% | 0.4% | 100.0% |
| BENIGN | 14,995 | 6.0% | 1.1% | 1.0% | 3.2% |

For BENIGN the rate is the false-positive rate; for every other class it is recall.

## Detection time in the live monitor

Each held-out capture replayed through traffic/monitor.py (same flow meter, scoring and per-source vote as live; flow-rate rule off so only the model decides). Time from launching the attack to the first block decision for each attacker.

| model | attack | attackers flagged | median time | slowest |
| --- | ---: | ---: | ---: | ---: |
| CIC-DDoS2019 | Sim-HTTP-flood | 0/3 | — | — |
| Simulated, finished flows only | Sim-HTTP-flood | 0/3 | — | — |
| Simulated | Sim-HTTP-flood | 0/3 | — | — |
| CIC + simulated | Sim-HTTP-flood | 0/3 | — | — |
| CIC-DDoS2019 | Sim-TCP-connect-flood | 0/3 | — | — |
| Simulated, finished flows only | Sim-TCP-connect-flood | 3/3 | 0.1 s | 0.1 s |
| Simulated | Sim-TCP-connect-flood | 3/3 | 0.1 s | 0.1 s |
| CIC + simulated | Sim-TCP-connect-flood | 3/3 | 0.1 s | 0.1 s |
| CIC-DDoS2019 | Sim-UDP-flood | 3/3 | 1.0 s | 1.0 s |
| Simulated, finished flows only | Sim-UDP-flood | 0/3 | — | — |
| Simulated | Sim-UDP-flood | 1/3 | 9.0 s | 9.0 s |
| CIC + simulated | Sim-UDP-flood | 3/3 | 1.0 s | 1.1 s |

| model | legitimate hosts flagged | sessions replayed |
| --- | ---: | ---: |
| CIC-DDoS2019 | 0 | 6 |
| Simulated, finished flows only | 0 | 6 |
| Simulated | 0 | 6 |
| CIC + simulated | 0 | 6 |

## How different are the datasets

| flows compared | CIC sample | simulated sample | ROC-AUC (0.5 = indistinguishable) |
| --- | ---: | ---: | ---: |
| all flows | 15,000 | 15,000 | 1.000 |
| benign flows | 15,000 | 15,000 | 1.000 |
| attack flows | 15,000 | 15,000 | 1.000 |

Features that separate them most (all flows): Flow IAT Min (0.180), Init_Win_bytes_forward (0.113), Fwd IAT Min (0.083), Init_Win_bytes_backward (0.073), Fwd Packet Length Min (0.063), Min Packet Length (0.053), Avg Fwd Segment Size (0.051), Fwd Packet Length Max (0.048).

## Datasets

|  | CIC-DDoS2019 | Simulated |
| --- | ---: | ---: |
| flows | 416,011 | 118,305 |
| benign share | 11.8% | 33.9% |
| attack types | 12 | 3 |
| TCP share | 17.8% | 97.7% |
| UDP share of benign flows | 41.9% | 2.4% |
