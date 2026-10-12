# Network Intrusion Detection System (NIDS)

A machine-learning intrusion detection system built on the **improved CICIDS2017** dataset, with a Streamlit
security dashboard and an AI assistant that explains every alert.

## What the app does

| Page | What you can do |
|---|---|
| **Dashboard** | SOC-style overview: flows analysed, alerts, critical alerts, attacking sources, traffic over time (normal / suspicious / malicious), top attack types, recent alerts with severity and simulated response, system status, HTML report export. |
| **Live Monitor** | Replays the capture in time order through the models as if traffic were arriving now, with a live alert feed, critical-alert notifications and a "jump to attack" control. |
| **Alert Investigation** | Verdict, severity and MITRE ATT&CK mapping for one flow; **why the model decided** (TreeSHAP contributions from XGBoost); comparison with normal traffic; attack-type probabilities; response playbook with progress tracking; suggested firewall rule; analyst feedback; incident report download; a what-if lab to change features and re-score. |
| **AI Assistant** | Chat about the selected alert, attacks, response steps or the dataset, in Arabic or English. Retrieval-augmented: answers cite the passages they use. Uses **Gemini** when an API key is configured, and answers from the knowledge base otherwise. |
| **Batch Scan** | Upload a CICFlowMeter CSV, score every flow, download the results. |
| **Attack Library** | Every attack type: how it works, how it shows up in the flows (from our EDA), impact, response and prevention. |
| **Model & Data** | Test metrics, pipeline, confusion matrix on the demo traffic, key dataset findings, and the **RAG evaluation** on the team's 50-question bank (hit rate 98% at TOP_K = 3). |

## Repository layout

```
app/
  app.py                 Streamlit entry point (navigation, sidebar)
  views/                 one file per page
  core/                  engine (models, scoring, explanations), RAG, assistant, knowledge base, UI helpers
  knowledge/             documents indexed by the assistant (dataset notes, question bank, project notes)
  data/demo_flows.parquet  18,928 real flows sampled from the dataset (with IPs/timestamps) for the demo
src/
  preprocessing.py       cleaning + feature-selection classes and make_model()  (used by notebook AND app)
  artifacts.py           save_artifacts() / load_artifacts(): the model format the app expects
models/                  binary_model.pkl, specialist_model.pkl, model_metadata.json
notebooks/cicids2017.ipynb  analysis, EDA and model training
scripts/build_demo_data.py  rebuilds app/data/demo_flows.parquet from the raw CSVs
```

## Run locally

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
streamlit run app/app.py
```

For the AI assistant, copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` and add a Gemini API key
(free key: https://aistudio.google.com/apikey). Without a key the assistant runs in offline mode.

## Data

The CSV files are not in the repository (about 1.1 GB). Download the improved CICIDS2017 dataset from
https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html and place the five
`*-WorkingHours.csv` files in `data/raw/`. The notebook reads them from `../data/raw`.

## Models: how to save them for the app

The app needs **two pipelines** and a metadata file in `models/`:

* `binary_model.pkl`: predicts **0 = benign, 1 = attack**
* `specialist_model.pkl`: trained on **attack flows only**, predicts the attack type
* `model_metadata.json`: input columns, class names, metrics, library versions

Three rules for the notebook:

1. **Import the transformers from `src`** instead of defining them in notebook cells. A pipeline pickled with
   classes defined in a notebook refers to `__main__.ClassName` and cannot be loaded by the app.
   ```python
   import sys; sys.path.append("..")
   from src.preprocessing import clean_dataset, make_model
   from src.artifacts import save_artifacts
   ```
2. **Create a new model object for every task** (`make_model(xgb.XGBClassifier(...))` each time).
   `evaluate_model` refits the object it receives, so reusing `forest_clf` / `xgb_model` for the binary,
   multiclass and specialist runs overwrites the earlier models.
3. **Save with `save_artifacts`** (it checks that the binary model really has two classes and that the
   specialist has no BENIGN class):
   ```python
   save_artifacts(
       binary_model=results_xgb["model"],
       specialist_model=results_xgb_specialist["model"],
       input_columns=X_train.columns,                  # columns from clean_dataset(), without Label
       specialist_classes=list(encoder.classes_),     # if the specialist labels were LabelEncoded
       metrics={"binary": {"f1_attack": ..., "precision_attack": ..., "recall_attack": ...},
                "specialist": {"f1_macro": ...}},
       out_dir="../models",
   )
   ```

If the models are missing or cannot be loaded, the app still starts in **replay mode** (it replays the dataset
labels) and shows the reason in a banner.

## Deploy on Streamlit Community Cloud

1. Push the repository to GitHub.
2. On https://share.streamlit.io choose **New app**, select the repository and branch, main file `app/app.py`.
3. In **Advanced settings** choose **Python 3.13**, and paste the secrets:
   ```toml
   GEMINI_API_KEY = "..."
   GEMINI_MODEL = "gemini-2.5-flash"
   ```

## Dataset citation

G. Engelen, V. Rimmer and W. Joosen, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study",
2021 IEEE Security and Privacy Workshops (SPW), pp. 7-12.
