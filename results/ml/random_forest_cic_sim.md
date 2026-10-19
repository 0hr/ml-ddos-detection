# random_forest_cic_sim

Random Forest (ml/train.py settings) trained on 351,087 flows: 291,207 from CIC-DDoS2019 + 59,880 collected.

Collected data: `/home/harun/PycharmProjects/ML-DDoS/simulation/data/20261115-120806/dataset.parquet`; by repetition: repetition 3 held out as test (3 repetitions).
Threshold 0.78 (validation, max TPR − FPR with FPR ≤ 1 %). Training took 4 s.

## Test results, against the main model

| test set | model | accuracy | precision | recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CIC-DDoS2019 | main model (CIC only) | 0.9990 | 0.9998 | 0.9991 | 0.9994 | 0.14% |
| CIC-DDoS2019 | random_forest_cic_sim | 0.9985 | 0.9999 | 0.9984 | 0.9991 | 0.07% |
| Simulated | main model (CIC only) | 0.4041 | 0.8787 | 0.1812 | 0.3004 | 6.01% |
| Simulated | random_forest_cic_sim | 0.8991 | 0.9850 | 0.8705 | 0.9242 | 3.19% |

## Collected test set, per class

| class | test flows | main model | random_forest_cic_sim |
| --- | ---: | ---: | ---: |
| Sim-HTTP-flood | 12,063 | 4.0% | 61.4% |
| Sim-TCP-connect-flood | 22,430 | 20.1% | 99.9% |
| Sim-UDP-flood | 1,536 | 100.0% | 100.0% |
| BENIGN | 14,995 | 6.0% | 3.2% |

For BENIGN the rate is the false-positive rate; for every other class it is recall.

## Use it

```bash
sudo python3 testbed/live.py --model models/random_forest_cic_sim.joblib
sudo python3 testbed/run_experiment.py --model models/random_forest_cic_sim.joblib
```
