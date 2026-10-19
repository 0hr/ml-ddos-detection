# random_forest_sim

Random Forest (ml/train.py settings) trained on 59,880 flows: 59,880 collected.

Collected data: `/home/harun/PycharmProjects/ML-DDoS/simulation/data/20261115-120806/dataset.parquet`; by repetition: repetition 3 held out as test (3 repetitions).
Threshold 0.93 (validation, max TPR − FPR with FPR ≤ 1 %). Training took 1 s.

## Test results, against the main model

| test set | model | accuracy | precision | recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CIC-DDoS2019 | main model (CIC only) | 0.9990 | 0.9998 | 0.9991 | 0.9994 | 0.14% |
| CIC-DDoS2019 | random_forest_sim | 0.1202 | 0.8912 | 0.0024 | 0.0047 | 0.22% |
| Simulated | main model (CIC only) | 0.4041 | 0.8787 | 0.1812 | 0.3004 | 6.01% |
| Simulated | random_forest_sim | 0.7935 | 0.9940 | 0.7118 | 0.8296 | 1.03% |

## Collected test set, per class

| class | test flows | main model | random_forest_sim |
| --- | ---: | ---: | ---: |
| Sim-HTTP-flood | 12,063 | 4.0% | 26.9% |
| Sim-TCP-connect-flood | 22,430 | 20.1% | 99.9% |
| Sim-UDP-flood | 1,536 | 100.0% | 0.4% |
| BENIGN | 14,995 | 6.0% | 1.0% |

For BENIGN the rate is the false-positive rate; for every other class it is recall.

## Use it

```bash
sudo python3 testbed/live.py --model models/random_forest_sim.joblib
sudo python3 testbed/run_experiment.py --model models/random_forest_sim.joblib
```
