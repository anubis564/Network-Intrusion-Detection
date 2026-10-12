"""Detection engine: loads the models, scores flows and explains individual predictions.

Two modes:
* model  - the trained binary + specialist pipelines from models/ are used.
* replay - the models are missing or invalid; the app replays the dataset's ground-truth labels so
           the interface still works, and shows a banner explaining why.
"""
import sys
import time
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
import polars as pl
import polars.selectors as cs
import streamlit as st

from core import knowledge as kb
from core.config import DEMO_DATA, IDENTIFIER_COLUMNS, MODELS_DIR, ROOT

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ATTACK_THRESHOLD = 0.5
SUSPICIOUS_THRESHOLD = 0.2


@dataclass
class Engine:
    mode: str
    binary: object = None
    specialist: object = None
    specialist_classes: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    input_columns: list = field(default_factory=list)
    error: str = ""

    @property
    def binary_name(self) -> str:
        return self.metadata.get("binary", {}).get("estimator") or _estimator_name(self.binary)

    @property
    def specialist_name(self) -> str:
        return self.metadata.get("specialist", {}).get("estimator") or _estimator_name(self.specialist)


def _estimator_name(model) -> str:
    if model is None:
        return "-"
    final = model[-1] if hasattr(model, "steps") else model
    return type(final).__name__


@st.cache_resource(show_spinner="Loading detection models...")
def load_engine() -> Engine:
    from src.artifacts import load_artifacts

    try:
        art = load_artifacts(MODELS_DIR)
    except Exception as exc:  # missing file, wrong model, class defined in a notebook, version mismatch...
        return Engine(mode="replay", error=f"{type(exc).__name__}: {exc}")

    columns = art["metadata"].get("input_columns") or list(getattr(art["binary"], "feature_names_in_", []))
    if not columns:
        return Engine(mode="replay", error="model_metadata.json is missing 'input_columns'.")
    return Engine(mode="model", binary=art["binary"], specialist=art["specialist"],
                  specialist_classes=art["specialist_classes"], metadata=art["metadata"], input_columns=columns)


@st.cache_data(show_spinner=False)
def load_demo() -> pl.DataFrame:
    return pl.read_parquet(DEMO_DATA)


def read_uploaded_csv(file) -> pl.DataFrame:
    df = pl.read_csv(file, infer_schema_length=10_000, null_values=["", "NaN", "nan"])
    df = df.rename({c: c.strip() for c in df.columns})
    if "Timestamp" in df.columns and df["Timestamp"].dtype == pl.String:
        df = df.with_columns(pl.col("Timestamp").str.strptime(pl.Datetime, "%d/%m/%Y %I:%M:%S %p", strict=False))
    return df


# ----------------------------------------------------------------------------------------- scoring
def _feature_frame(df: pl.DataFrame, columns: list[str]) -> tuple[pl.DataFrame, np.ndarray]:
    missing = [c for c in columns if c not in df.columns]
    if missing:
        raise ValueError(f"{len(missing)} required columns are missing, e.g. {missing[:5]}")
    X = df.select([pl.col(c).cast(pl.Float64, strict=False) for c in columns])
    valid = X.select(
        pl.all_horizontal(pl.all().is_not_null() & pl.all().is_finite() & (pl.all() >= 0))
    ).to_series().to_numpy()
    X = X.with_columns(cs.float().fill_nan(0).fill_null(0))
    X = X.with_columns(pl.when(pl.all().is_infinite()).then(0).otherwise(pl.all()).name.keep())
    X = X.with_columns(pl.all().cast(pl.Float32))
    if "Protocol" in X.columns:
        X = X.with_columns(pl.col("Protocol").cast(pl.Int32))
    return X, valid


def _decorate(out: pd.DataFrame) -> pd.DataFrame:
    out["family"] = [kb.family_of(lbl) for lbl in out["pred_label"]]
    out["severity"] = [kb.severity_of(lbl) if atk else "-" for lbl, atk in zip(out["pred_label"], out["is_attack"])]
    out["action"] = [kb.SEVERITY_ACTION.get(sev, "-") if atk else "Allowed"
                     for sev, atk in zip(out["severity"], out["is_attack"])]
    status = np.where(out["is_attack"] & out["severity"].isin(["Critical", "High"]), "Malicious",
                      np.where(out["is_attack"] | (out["attack_prob"] >= SUSPICIOUS_THRESHOLD), "Suspicious", "Normal"))
    out["status"] = np.where(out["valid"], status, "Invalid")
    return out


def score(engine: Engine, df: pl.DataFrame) -> pd.DataFrame:
    """Score every row of a raw flow table. Returns one result row per input row, in the same order."""
    n = df.height
    out = pd.DataFrame({"valid": np.ones(n, bool), "attack_prob": np.zeros(n), "is_attack": np.zeros(n, bool),
                        "pred_label": ["BENIGN"] * n, "pred_conf": np.ones(n)})

    if engine.mode == "replay":
        if "Label" not in df.columns:
            raise ValueError("Models are not loaded, and the file has no Label column to replay.")
        labels = [("BENIGN" if str(l).endswith("Attempted") else kb.base_label(l)) for l in df["Label"].to_list()]
        out["pred_label"] = labels
        out["is_attack"] = out["pred_label"] != "BENIGN"
        out["attack_prob"] = out["is_attack"].astype(float)
        return _decorate(out)

    X, valid = _feature_frame(df, engine.input_columns)
    out["valid"] = valid
    idx = np.flatnonzero(valid)
    if len(idx):
        Xv = X[idx]
        proba = engine.binary.predict_proba(Xv)
        pos = list(getattr(engine.binary, "classes_", [0, 1])).index(1)
        out.loc[idx, "attack_prob"] = proba[:, pos]
        out.loc[idx, "pred_conf"] = np.maximum(proba[:, pos], 1 - proba[:, pos])
        atk_idx = idx[proba[:, pos] >= ATTACK_THRESHOLD]
        out.loc[atk_idx, "is_attack"] = True
        if len(atk_idx):
            if engine.specialist is not None:
                sp = engine.specialist.predict_proba(X[atk_idx])
                best = sp.argmax(axis=1)
                out.loc[atk_idx, "pred_label"] = [_class_name(engine, engine.specialist.classes_[b]) for b in best]
                out.loc[atk_idx, "pred_conf"] = sp.max(axis=1)
            else:
                out.loc[atk_idx, "pred_label"] = "Unknown attack"
    return _decorate(out)


def _class_name(engine: Engine, cls) -> str:
    if isinstance(cls, (int, np.integer)) and engine.specialist_classes:
        return str(engine.specialist_classes[int(cls)])
    return str(cls)


def specialist_top(engine: Engine, df_row: pl.DataFrame, k: int = 3) -> list[tuple[str, float]]:
    if engine.mode != "model" or engine.specialist is None:
        return []
    X, _ = _feature_frame(df_row, engine.input_columns)
    p = engine.specialist.predict_proba(X)[0]
    order = np.argsort(p)[::-1][:k]
    return [(_class_name(engine, engine.specialist.classes_[i]), float(p[i])) for i in order]


@st.cache_data(show_spinner="Scoring demo traffic...")
def score_demo(_engine: Engine, cache_key: str) -> pd.DataFrame:
    demo = load_demo()
    t0 = time.perf_counter()
    res = score(_engine, demo)
    elapsed = time.perf_counter() - t0
    keep = [c for c in IDENTIFIER_COLUMNS + ["Protocol", "Flow Duration", "Total Fwd Packet", "Total Bwd packets",
                                             "Total Length of Fwd Packet", "Total Length of Bwd Packet", "Label"]
            if c in demo.columns]
    base = demo.select(keep).to_pandas()
    res = pd.concat([base, res], axis=1)
    res["true_label"] = ["BENIGN" if str(l).endswith("Attempted") else kb.base_label(l) for l in res["Label"]]
    res["true_attack"] = res["true_label"] != "BENIGN"
    res.attrs["latency_ms_per_flow"] = 1000 * elapsed / max(len(res), 1)
    return res


def engine_key(engine: Engine) -> str:
    return f"{engine.mode}-{engine.metadata.get('saved_on', '')}-{len(engine.input_columns)}"


# ------------------------------------------------------------------------------------- explanation
def explain(engine: Engine, df_row: pl.DataFrame, use_specialist: bool = False, class_name: str | None = None):
    """Per-feature contributions to one prediction.

    Uses TreeSHAP values computed by XGBoost when the final estimator is an XGBoost model,
    otherwise falls back to feature importance weighted by how unusual the value is.
    Returns (DataFrame[feature, value, contribution], method description).
    """
    if engine.mode != "model":
        return None, "Models are not loaded."
    model = engine.specialist if use_specialist else engine.binary
    if model is None:
        return None, "Model not available."
    X, _ = _feature_frame(df_row, engine.input_columns)
    if hasattr(model, "steps"):
        Xt, est = model[:-1].transform(X), model[-1]
    else:
        Xt, est = X.to_pandas(), model
    Xt = pd.DataFrame(Xt)
    values = Xt.iloc[0].to_numpy(dtype=float)

    if type(est).__name__.startswith("XGB"):
        import xgboost as xgb

        contribs = est.get_booster().predict(xgb.DMatrix(Xt), pred_contribs=True)
        if contribs.ndim == 3:  # multi-class: (rows, classes, features + bias)
            classes = [_class_name(engine, c) for c in est.classes_]
            ci = classes.index(class_name) if class_name in classes else int(np.argmax(contribs[0, :, :].sum(axis=1)))
            row = contribs[0, ci, :-1]
        else:
            row = contribs[0, :-1]
        method = "TreeSHAP values from XGBoost (contribution to the log-odds of the prediction)"
    elif hasattr(est, "feature_importances_"):
        base = benign_baseline()
        dev = np.array([_deviation(base, f, v) for f, v in zip(Xt.columns, values)])
        row = est.feature_importances_ * dev
        method = "Feature importance x deviation from normal traffic (approximation; the model is not XGBoost)"
    else:
        return None, "This model type cannot be explained."

    out = pd.DataFrame({"feature": Xt.columns, "value": values, "contribution": row})
    out = out.reindex(out["contribution"].abs().sort_values(ascending=False).index)
    return out, method


# ----------------------------------------------------------------------------------- baseline stats
@st.cache_data(show_spinner=False)
def benign_baseline() -> dict:
    demo = load_demo()
    benign = demo.filter(pl.col("Label") == "BENIGN").select(cs.numeric().exclude("Src Port", "Dst Port"))
    return {c: np.sort(benign[c].cast(pl.Float64).to_numpy()) for c in benign.columns}


def _deviation(base: dict, feature: str, value: float) -> float:
    arr = base.get(feature)
    if arr is None or len(arr) == 0:
        return 0.0
    pct = np.searchsorted(arr, value, side="right") / len(arr)
    return float(abs(pct - 0.5) * 2)


def percentile_in_benign(feature: str, value: float) -> float | None:
    arr = benign_baseline().get(feature)
    if arr is None or len(arr) == 0:
        return None
    return float(np.searchsorted(arr, value, side="right") / len(arr) * 100)


def benign_median(feature: str) -> float | None:
    arr = benign_baseline().get(feature)
    return float(np.median(arr)) if arr is not None and len(arr) else None
