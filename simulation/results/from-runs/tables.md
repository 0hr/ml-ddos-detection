# Simulated data vs CIC-DDoS2019

Simulated dataset: `simulation/data/from-runs/dataset.parquet` — 13,490 flows, 12 sessions.

Simulated split: by repetition: repetition 3 held out as test (3 repetitions). Train 7,168 · validation 1,792 · test 4,530 flows.
CIC-DDoS2019 split: the one of ml/train.py (test 62,402 flows).

## Results

| train on | test on | flows | accuracy | precision | recall | F1 | FPR | ROC-AUC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CIC-DDoS2019 | CIC-DDoS2019 | 62,402 | 0.9990 | 0.9998 | 0.9991 | 0.9994 | 0.14% | 1.0000 |
| CIC-DDoS2019 | Simulated | 4,530 | 0.9852 | 0.9198 | 1.0000 | 0.9582 | 1.78% | 1.0000 |
| Simulated | CIC-DDoS2019 | 62,402 | 0.8035 | 0.9996 | 0.7774 | 0.8746 | 0.20% | 0.9000 |
| Simulated | Simulated | 4,530 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.00% | 1.0000 |
| CIC + simulated | CIC-DDoS2019 | 62,402 | 0.9988 | 0.9999 | 0.9987 | 0.9993 | 0.09% | 1.0000 |
| CIC + simulated | Simulated | 4,530 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.00% | 1.0000 |

## Simulated test set, per class

| class | test flows | trained on CIC-DDoS2019 | trained on Simulated | trained on CIC + simulated |
| --- | ---: | ---: | ---: | ---: |
| Sim-UDP-flood | 768 | 100.0% | 100.0% | 100.0% |
| BENIGN | 3,762 | 1.8% | 0.0% | 0.0% |

For BENIGN the rate is the false-positive rate; for every other class it is recall.

## How different are the datasets

| flows compared | CIC sample | simulated sample | ROC-AUC (0.5 = indistinguishable) |
| --- | ---: | ---: | ---: |
| all flows | 15,000 | 13,490 | 1.000 |
| benign flows | 15,000 | 11,186 | 1.000 |
| attack flows | 15,000 | 2,304 | 1.000 |

Features that separate them most (all flows): Flow IAT Min (0.250), Fwd IAT Min (0.133), Init_Win_bytes_forward (0.069), Bwd IAT Min (0.052), Init_Win_bytes_backward (0.051), Bwd Packet Length Std (0.051), Bwd Packet Length Max (0.049), Flow Bytes/s (0.027).

## Datasets

|  | CIC-DDoS2019 | Simulated |
| --- | ---: | ---: |
| flows | 416,011 | 13,490 |
| benign share | 11.8% | 82.9% |
| attack types | 12 | 1 |
| TCP share | 17.8% | 82.9% |
| UDP share of benign flows | 41.9% | 0.0% |
