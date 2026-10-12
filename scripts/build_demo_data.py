"""Build the small demo dataset the Streamlit app replays (app/data/demo_flows.parquet).

Usage:  python scripts/build_demo_data.py <folder with the five *-WorkingHours.csv files>

Keeps the identifier columns (IPs, ports, timestamp) so the dashboard can show realistic alerts,
and samples every attack type so all of them appear in the demo.
"""
import sys
from pathlib import Path

import polars as pl
import polars.selectors as cs

BENIGN_ROWS = 12_000
ATTACK_ROWS_PER_LABEL = 700
ATTEMPTED_ROWS = 400
SEED = 42

raw_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "data/raw")
out_path = Path(__file__).resolve().parents[1] / "app" / "data" / "demo_flows.parquet"

frames = []
for file in sorted(raw_dir.glob("*.csv")):
    df = pl.read_csv(file)
    frames.append(df.rename({c: c.strip() for c in df.columns}))
data = pl.concat(frames, how="vertical")

data = (
    data
    .filter(pl.all_horizontal(cs.float().is_finite()))
    .filter(~pl.any_horizontal(cs.numeric() < 0))
)

benign = data.filter(pl.col("Label") == "BENIGN").sample(BENIGN_ROWS, seed=SEED)
attempted = data.filter(pl.col("Label").str.ends_with("Attempted"))
attempted = attempted.sample(min(ATTEMPTED_ROWS, attempted.height), seed=SEED)
attacks = (
    data.filter((pl.col("Label") != "BENIGN") & ~pl.col("Label").str.ends_with("Attempted"))
    .filter(pl.int_range(pl.len()).shuffle(seed=SEED).over("Label") < ATTACK_ROWS_PER_LABEL)
)

demo = (
    pl.concat([benign, attempted, attacks])
    .with_columns(pl.col("Timestamp").str.strptime(pl.Datetime, "%d/%m/%Y %I:%M:%S %p").alias("Timestamp"))
    .sort("Timestamp")
)
out_path.parent.mkdir(parents=True, exist_ok=True)
demo.write_parquet(out_path, compression="zstd", compression_level=19)
print(f"{demo.height:,} flows -> {out_path} ({out_path.stat().st_size / 1e6:.1f} MB)")
print(demo.group_by("Label").len().sort("len", descending=True))
