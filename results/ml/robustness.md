# Robustness of the Random Forest

All tests use the deployed decision threshold (0.67) and the same hyper-parameters as `ml/train.py`.

## 1. Five-fold cross-validation

| metric | mean | std |
|---|---|---|
| recall | 0.9989 | 0.0001 |
| fpr | 0.0007 | 0.0004 |
| f1 | 0.9994 | 0.0000 |

The main random split is not a lucky draw: fold-to-fold variation is tiny.

## 2. Temporal holdout

Within every label, the earliest 70% of flows train the model and the latest 15% test it, so near-identical neighbouring flows cannot appear on both sides.

Recall **0.9966**, FPR **0.0000**, F1 0.9983 (random 5-fold: recall 0.9989, FPR 0.0007).

| label | share of later flows flagged |
|---|---|
| BENIGN | 0.000 |
| DrDoS_DNS | 0.971 |
| DrDoS_LDAP | 0.988 |
| DrDoS_MSSQL | 1.000 |
| DrDoS_NTP | 1.000 |
| DrDoS_NetBIOS | 0.966 |
| DrDoS_SNMP | 0.989 |
| DrDoS_SSDP | 1.000 |
| DrDoS_UDP | 1.000 |
| Syn | 0.982 |
| TFTP | 1.000 |
| UDP-lag | 0.984 |
| WebDDoS | 0.790 |

## 3. Leave-one-attack-out

Each attack type is removed from training entirely; the model must recognise it as an attack without ever having seen it.

| unseen attack | flows | detected | benign FPR |
|---|---|---|---|
| DrDoS_DNS | 3,925 | 94.6% | 0.0005 |
| DrDoS_LDAP | 1,074 | 99.0% | 0.0007 |
| DrDoS_MSSQL | 3,943 | 99.9% | 0.0007 |
| DrDoS_NTP | 139,389 | 99.6% | 0.0007 |
| DrDoS_NetBIOS | 1,162 | 86.5% | 0.0007 |
| DrDoS_SNMP | 2,351 | 99.4% | 0.0007 |
| DrDoS_SSDP | 56,394 | 100.0% | 0.0007 |
| DrDoS_UDP | 56,599 | 100.0% | 0.0007 |
| Syn | 16,151 | 99.5% | 0.0007 |
| TFTP | 48,649 | 99.9% | 0.0006 |
| UDP-lag | 36,723 | 99.5% | 0.0006 |
| WebDDoS | 412 | 78.4% | 0.0007 |

## Reading

- Leakage from the random split is small: later, unseen traffic of the same attacks is detected at 99.66% with no benign false positives.
- 9 of 12 attack types are detected at ≥ 95% *without being in the training data*: the model learned what a volumetric flood looks like, not a list of known attacks.
- Weakest when unseen: DrDoS_DNS (94.6%), DrDoS_NetBIOS (86.5%), WebDDoS (78.4%). WebDDoS is an application-layer attack (normal-looking HTTP requests) with only 439 flows in the whole dataset; per-flow features see little difference from benign web traffic.
