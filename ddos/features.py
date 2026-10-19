"""Feature list shared by training (CIC-DDoS2019 CSVs) and live traffic (pcap flows).

We keep only features our own flow meter (ddos.flowmeter) can reproduce exactly. Left out:
  * identifiers / setup-specific: Flow ID, IPs, ports, Timestamp, Inbound, SimillarHTTP
  * buggy in CICFlowMeter-V3: flag counts (SYN flood rows show SYN=0, ACK=1), header
    lengths (negative for UDP), act_data_pkt_fwd, min_seg_size_forward
  * constant or duplicate: bulk features, Subflow* (same as totals), Fwd Header Length.1
  * Active/Idle: depend on CICFlowMeter's 5 s timeout, which we do not reproduce
"""

import numpy as np
import pandas as pd

LABEL_COL = "Label"
BENIGN = "BENIGN"

FEATURES = [
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
]

# Kept beside the features for inspection (false positives, duplicates), never fed to the model.
META_COLS = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Timestamp"]

# A zero-duration flow makes CICFlowMeter divide by zero and emit inf/NaN. Training and
# live traffic both treat such a flow as lasting 1 microsecond instead.
MIN_DURATION_US = 1.0
SUPPORTED_PROTOCOLS = (6, 17)


def fix_rates(df: pd.DataFrame) -> pd.DataFrame:
    """Recompute rate features with the MIN_DURATION_US convention (in place)."""
    dur_s = np.maximum(df["Flow Duration"].to_numpy(dtype=float), MIN_DURATION_US) / 1e6
    fwd = df["Total Fwd Packets"].to_numpy(dtype=float)
    bwd = df["Total Backward Packets"].to_numpy(dtype=float)
    nbytes = df["Total Length of Fwd Packets"].to_numpy(dtype=float) + df[
        "Total Length of Bwd Packets"
    ].to_numpy(dtype=float)
    df["Flow Bytes/s"] = nbytes / dur_s
    df["Flow Packets/s"] = (fwd + bwd) / dur_s
    df["Fwd Packets/s"] = fwd / dur_s
    df["Bwd Packets/s"] = bwd / dur_s
    return df


def binary_target(labels: pd.Series) -> np.ndarray:
    """1 = attack, 0 = benign."""
    return (labels.astype(str).str.upper() != BENIGN).to_numpy(dtype=np.int8)
