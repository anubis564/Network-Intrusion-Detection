# Project notes: our NIDS pipeline

How our Network Intrusion Detection System was built, from the raw CSV files to the deployed app.

## Goal and framing
The goal is a data-driven Network Intrusion Detection System (NIDS) that analyses network flow features and separates benign traffic from attacks. It is a supervised classification problem: labels give the target classes the model learns to predict, such as benign traffic or a specific attack class. Benign labels mark non-malicious traffic, while attack labels identify traffic associated with a particular attack category. We solve it on two levels: a binary model (benign = 0, attack = 1) and a specialist model that names the attack type for flows the binary model flags. Because benign traffic vastly outnumbers attacks, accuracy is misleading; we focus on recall (attacks caught), precision (false alarms avoided), F1 and the confusion matrix.

## Data preparation
The five daily CSV files (Monday to Friday, 2,100,814 flows) are merged and stored as Parquet. Cleaning steps, in order: drop identifier columns (Flow ID, Src IP, Src Port, Dst IP, Dst Port, Timestamp) so the model learns behaviour instead of the lab's addresses; drop rows with infinite or NaN values (fewer than 0.05% of rows); drop rows with impossible negative values (for example a negative Flow IAT Min caused by timestamp errors); relabel "Attempted" flows as BENIGN; remove duplicate rows. Data cleaning matters because invalid or corrupted rows and NaN values interfere with training, evaluation and reproducibility, and documenting each preprocessing step makes the results reproducible and explains how cleaning and labelling change the data. Features that are almost always zero (Fwd URG Flags, Bwd URG Flags, URG Flag Count, Subflow Bwd Packets) are removed, and one of every pair of features with correlation above 0.95 is dropped. Protocol is one-hot encoded.

## Why Attempted flows are relabelled as benign
In every family that has Attempted labels, 100% of Attempted flows have zero forward payload, while 0% of the real attack flows do (8.3% of benign flows have no payload). Without a payload the attack cannot have any effect, so from a detection point of view these flows behave like ordinary empty connections.

## Key findings from the exploratory analysis
- Monday contains only benign traffic. Each attack family appears on exactly one day: Brute Force on Tuesday; DoS and Heartbleed on Wednesday; Web Attack and Infiltration on Thursday; Bot, PortScan and DDoS on Friday.
- Every family except PortScan targets one service: DoS, DDoS and web attacks hit port 80, FTP-Patator port 21, SSH-Patator port 22, Bot port 8080, Infiltration and Heartbleed port 444. PortScan touches 1,001 different ports.
- All attack flows use TCP, while about 60% of benign flows are UDP.
- PortScan probes are 99% duplicates once identifiers are removed (159,023 flows shrink to about 1,670).
- The recorded timestamps are 5 hours ahead of the lab's local time.
- Initial TCP window sizes (FWD Init Win Bytes, Bwd Init Win Bytes) are very predictive but partly describe the lab machines, so they are a possible shortcut feature.
- Low-volume families that look like normal traffic (Bot, Web Attack, Infiltration) are the hardest to detect.

## Models
We compared Random Forest and XGBoost inside a scikit-learn pipeline (low non-zero feature remover, correlation selector, one-hot encoder, classifier), evaluated with stratified 5-fold cross-validation and a held-out test set. A labelled flow-based dataset like this can be used to train and evaluate classifiers, provided the data is prepared and split appropriately. Tree-based models handle the extreme, zero-inflated feature values without scaling, which is why outliers were kept: in security data extreme values are often the attack signature itself.

## The application
The Streamlit app is the user interface of the project: it shows a SOC-style dashboard, a simulated live traffic monitor, an alert investigation page that explains each prediction, batch scanning of CSV files, an attack library, and an AI assistant. Streamlit provides the interface for entering questions, displaying answers and inspecting the retrieved context.
