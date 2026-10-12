"""Saving and loading the trained models in the format the Streamlit app expects.

Call ``save_artifacts`` at the end of the notebook (section 7) instead of dumping the
models one by one. It writes:

    models/xgb_binary_model.pkl   pipeline that predicts 0 = benign, 1 = attack
    models/specialist_model.pkl   pipeline trained on attack flows only (attack type)
    models/model_metadata.json    input columns, class names, metrics and library versions
"""
import json
import platform
from datetime import date
from pathlib import Path

import joblib

BINARY_FILE = "xgb_binary_model.pkl"
SPECIALIST_FILE = "specialist_model.pkl"
METADATA_FILE = "model_metadata.json"


def _versions() -> dict:
    import numpy
    import polars
    import sklearn

    versions = {"python": platform.python_version(), "scikit-learn": sklearn.__version__,
                "numpy": numpy.__version__, "polars": polars.__version__}
    try:
        import xgboost
        versions["xgboost"] = xgboost.__version__
    except ImportError:
        pass
    return versions


def save_artifacts(binary_model, specialist_model, input_columns, specialist_classes=None,
                   metrics=None, out_dir="../models", notes="") -> Path:
    """Save both models plus metadata.

    binary_model / specialist_model: fitted pipelines (e.g. from ``make_model``), trained on the
        output of ``clean_dataset`` without the Label column.
    input_columns: the columns the pipelines were fitted on, e.g. ``X_train.columns``.
    specialist_classes: attack names in the order of the specialist's predicted indices, e.g.
        ``list(encoder.classes_)`` when the labels were encoded with a LabelEncoder. Leave it as
        None when the specialist was trained on the string labels directly.
    metrics: optional dict of test metrics to show in the app, e.g.
        {"binary": {"f1_attack": 0.9996, ...}, "specialist": {"f1_macro": 0.96, ...}}.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    binary_classes = [int(c) for c in getattr(binary_model, "classes_", [])]
    if binary_classes and sorted(binary_classes) != [0, 1]:
        raise ValueError(f"binary_model must predict 0/1, but its classes are {binary_classes}")

    if specialist_classes is None:
        specialist_classes = [str(c) for c in getattr(specialist_model, "classes_", [])]
    if "BENIGN" in specialist_classes:
        raise ValueError("specialist_model must be trained on attack flows only (no BENIGN class)")

    joblib.dump(binary_model, out / BINARY_FILE, compress=3)
    joblib.dump(specialist_model, out / SPECIALIST_FILE, compress=3)

    metadata = {
        "input_columns": list(input_columns),
        "binary": {"file": BINARY_FILE, "classes": [0, 1], "positive_label": 1,
                   "estimator": type(binary_model[-1] if hasattr(binary_model, "steps") else binary_model).__name__},
        "specialist": {"file": SPECIALIST_FILE, "classes": list(specialist_classes),
                       "estimator": type(specialist_model[-1] if hasattr(specialist_model, "steps") else specialist_model).__name__},
        "metrics": metrics or {},
        "versions": _versions(),
        "saved_on": date.today().isoformat(),
        "notes": notes,
    }
    (out / METADATA_FILE).write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return out


def load_artifacts(models_dir) -> dict:
    """Load models and metadata. Raises a ValueError explaining what is wrong if the files do not fit."""
    models_dir = Path(models_dir)
    meta_path = models_dir / METADATA_FILE
    metadata = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}

    binary_path = models_dir / metadata.get("binary", {}).get("file", BINARY_FILE)
    specialist_path = models_dir / metadata.get("specialist", {}).get("file", SPECIALIST_FILE)
    if not binary_path.exists():
        raise ValueError(f"{binary_path.name} not found in {models_dir}")

    binary = joblib.load(binary_path)
    classes = [int(c) for c in getattr(binary, "classes_", [0, 1])]
    if sorted(classes) != [0, 1]:
        raise ValueError(f"{binary_path.name} is not a binary model: it predicts {len(classes)} classes")

    specialist, specialist_classes = None, []
    if specialist_path.exists():
        specialist = joblib.load(specialist_path)
        specialist_classes = metadata.get("specialist", {}).get("classes") or \
            [str(c) for c in getattr(specialist, "classes_", [])]

    return {"binary": binary, "specialist": specialist, "specialist_classes": specialist_classes,
            "metadata": metadata}
