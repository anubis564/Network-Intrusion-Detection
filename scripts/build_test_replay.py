"""Rebuild the notebook's held-out TEST set (flows the binary model never saw) with their identifiers.

The notebook cleans the data with clean_dataset(df, make_target_binary=True) and splits it with
train_test_split(X, y, test_size=0.2, random_state=42, stratify=y). The split depends only on the row
order and the labels, so repeating the same cleaning while carrying a row id gives the same test rows,
which can then be joined back to their IP addresses, ports and timestamps.

Usage:  python scripts/build_test_replay.py <folder with the five *-WorkingHours.csv files> [--benign-fraction 0.35]

Writes app/data/test_flows.parquet, the traffic the Live Monitor and the dashboard replay.
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import polars as pl
import polars.selectors as cs
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.preprocessing import IDENTIFIER_COLUMNS  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("raw_dir", nargs="?", default="data/raw")
parser.add_argument("--benign-fraction", type=float, default=0.35,
                    help="share of the benign test flows to keep (all attack flows are kept)")
parser.add_argument("--check-model", default=None, help="models folder: report the binary model's F1 on the test set")
args = parser.parse_args()

# --- the notebook's loading (cells 12-18): same file order, same downcast
frames = []
for file in Path(args.raw_dir).glob("*.csv"):
    df = pl.read_csv(file)
    frames.append(df.rename({c: c.strip() for c in df.columns}))
data = pl.concat(frames)
del frames, df
data = data.with_columns(pl.col(pl.Float64()).cast(pl.Float32()))
data = data.with_columns(pl.col(pl.Int64()).cast(pl.Int32()))
data = data.with_row_index("row_id")

# --- clean_dataset(df, make_target_binary=True), carrying row_id along
ids = data.select(["row_id"] + IDENTIFIER_COLUMNS + ["Label"]).rename({"Label": "Original Label"})
X = data.drop(IDENTIFIER_COLUMNS)
del data
X = X.with_columns(pl.when(cs.numeric().is_infinite()).then(None).otherwise(cs.numeric()).name.keep())
X = X.with_columns(cs.float().fill_nan(None).name.keep()).drop_nulls()
X = X.filter(~pl.any_horizontal(cs.numeric().exclude("row_id") < 0))
X = X.with_columns(pl.when(pl.col("Label").str.ends_with("Attempted")).then(pl.lit("BENIGN"))
                   .otherwise(pl.col("Label")).alias("Label"))
X = X.with_columns(pl.when(pl.col("Label") == "BENIGN").then(0).otherwise(1).alias("Label"))
X = X.unique(subset=[c for c in X.columns if c != "row_id"], keep="first", maintain_order=True)
print(f"cleaned: {X.height:,} flows")

y = X["Label"].to_numpy()
_, test_idx = train_test_split(np.arange(X.height), test_size=0.2, random_state=42, stratify=y)
test = X[np.sort(test_idx)]
del X
print(f"test set: {test.height:,} flows ({int(test['Label'].sum()):,} attacks)")

if args.check_model:
    from sklearn.metrics import f1_score
    from src.artifacts import load_artifacts
    model = load_artifacts(args.check_model)["binary"]
    pred = model.predict(test.drop(["row_id", "Label"]))
    print(f"binary model on the rebuilt test set: attack F1 = {f1_score(test['Label'], pred):.10f}")

# --- keep every attack flow and a share of the benign ones, put identifiers back, sort by time
rng = np.random.default_rng(42)
keep = (test["Label"].to_numpy() == 1) | (rng.random(test.height) < args.benign_fraction)
replay = (
    test.filter(pl.Series(keep)).drop("Label")
    .join(ids, on="row_id", how="left")
    .with_columns(pl.col("Timestamp").str.strptime(pl.Datetime, "%d/%m/%Y %I:%M:%S %p"))
    .rename({"Original Label": "Label"})
    .sort("Timestamp")
    .drop("row_id")
)
out = ROOT / "app" / "data" / "test_flows.parquet"
replay.write_parquet(out, compression="zstd", compression_level=19)
print(f"{replay.height:,} flows -> {out} ({out.stat().st_size / 1e6:.1f} MB)")
print(replay.group_by("Label").len().sort("len", descending=True))
