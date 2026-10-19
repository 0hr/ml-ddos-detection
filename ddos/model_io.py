"""Save and load models together with their exact feature list.

A bundle is a joblib file with the model and its schema. The schema is also written as
JSON next to it so the monitor (or a person) can check it. Loading checks the bundle was
trained on the same ordered features as ``ddos.features.FEATURES``; predicting checks that
every feature is present and finite.
"""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ddos.features import FEATURES, MIN_DURATION_US


def schema_hash(features: list[str]) -> str:
    return hashlib.sha256("\n".join(features).encode()).hexdigest()[:16]


def build_schema(X: pd.DataFrame) -> dict:
    return {
        "features": list(X.columns),
        "schema_hash": schema_hash(list(X.columns)),
        "dtype": "float64",
        "units": {"time": "microseconds", "length": "transport payload bytes", "rates": "per second"},
        "conventions": {
            "flow": "bidirectional 5-tuple, forward = first packet sender, FIN or 120 s ends a flow, >= 2 packets",
            "std": "sample std (ddof=1), 0 with < 2 values",
            "min_duration_us": MIN_DURATION_US,
            "packet_length_overall": "first packet counted twice (CICFlowMeter-V3 behaviour)",
            "init_win_missing": -1,
        },
        "train_ranges": {
            c: {"min": float(X[c].min()), "median": float(X[c].median()), "max": float(X[c].max())}
            for c in X.columns
        },
    }


@dataclass
class Bundle:
    model: object
    name: str
    threshold: float
    schema: dict
    metrics: dict

    @property
    def features(self) -> list[str]:
        return self.schema["features"]

    def _matrix(self, df: pd.DataFrame) -> np.ndarray:
        missing = [c for c in self.features if c not in df.columns]
        if missing:
            raise ValueError(f"input is missing {len(missing)} schema features: {missing[:5]}")
        X = df[self.features].to_numpy(dtype=np.float64)
        if not np.isfinite(X).all():
            raise ValueError("input contains NaN/inf; apply ddos.features.fix_rates first")
        return X

    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        """Probability of the attack class for each row."""
        X = self._matrix(df)
        if len(X) == 0:
            return np.empty(0)
        return self.model.predict_proba(pd.DataFrame(X, columns=self.features))[:, 1]

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        return (self.predict_proba(df) >= self.threshold).astype(np.int8)


def save_bundle(path: Path, model, name: str, threshold: float, schema: dict, metrics: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {"model": model, "name": name, "threshold": threshold, "schema": schema, "metrics": metrics},
        path,
        compress=3,
    )
    path.with_suffix(".schema.json").write_text(json.dumps(schema, indent=2))


def load_bundle(path: str | Path) -> Bundle:
    raw = joblib.load(path)
    schema = raw["schema"]
    if schema["features"] != FEATURES or schema["schema_hash"] != schema_hash(FEATURES):
        raise ValueError(
            f"{path}: feature schema {schema['schema_hash']} does not match "
            f"ddos.features.FEATURES ({schema_hash(FEATURES)}); retrain the model"
        )
    return Bundle(raw["model"], raw["name"], float(raw["threshold"]), schema, raw.get("metrics", {}))
