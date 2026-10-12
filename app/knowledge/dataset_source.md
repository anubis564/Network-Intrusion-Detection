# Improved CICIDS2017 dataset (source notes)

Notes summarised from the dataset's official page, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study - Tools & Datasets" (https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html), by the Distrinet group at KU Leuven.

## Purpose of the improved dataset
The improved CICIDS2017 is a flow-based dataset for research and evaluation of network intrusion detection. It is a regenerated version of the original CICIDS2017: the same packet captures were processed again with a fixed version of the CICFlowMeter tool and labelled again with improved logic. A flow-based intrusion detection dataset describes network activity with flow-level features (one row per network flow) instead of analysing every packet on its own. A network flow is a group of packets that belong to the same connection (same source and destination IP, ports and protocol) and is summarised by statistics such as duration, packet counts, byte counts, inter-arrival times and TCP flag counts.

## CICFlowMeter and the fixed version
CICFlowMeter is the tool that turns raw network traffic (packet captures) into flows and extracts the flow-based features used for analysis and machine learning. The authors published a fixed version of CICFlowMeter on GitHub at https://github.com/GintsEngelen/CICFlowMeter because they found problems in how the original tool constructed and terminated TCP flows.

Important changes in the fixed CICFlowMeter:
- FIN handling: a TCP flow is no longer terminated after a single FIN packet. It now terminates only after FIN packets have been mutually exchanged, which matches the TCP specification.
- RST handling: an RST packet is no longer ignored. An RST packet now also terminates the TCP flow.
- Timeout: a flow can still terminate by timing out when its total duration exceeds the timeout. This timeout-based termination behaviour was left unchanged.

## Dataset updates
- 20/10/2021: dataset files re-uploaded to fix an error in the Idle Time features. The fixed CICFlowMeter tool itself was not affected.
- 22/10/2021: CICFlowMeter fixed following a GitHub pull request affecting the Fwd and Bwd Bulk features; the dataset CSV files were regenerated and re-uploaded.
- 24/11/2021: CICFlowMeter fixed following further pull requests (Down/Up ratio fixed and several features related to flow length affected); the CSV files were regenerated and re-uploaded.
- 18/11/2022: the authors point to their newer work for the most recent CICIDS2017 version (improved ground-truth labelling and additional features) and a fixed CSE-CIC-IDS2018.

## The "X - Attempted" label
Most attack classes in CICIDS2017 need to transmit a payload to be effective. For any flow that belongs to a payload-reliant attack class X but does not contain a payload, the dataset uses the label "X - Attempted", where X is the original attack class. This separates effective attack flows (the attack payload was delivered) from flows that match an attack class but lack the payload the attack needs. Classes that do not depend on a payload, such as Portscan, have no Attempted category (shown as N/A in the composition table). The Benign label identifies traffic classified as non-malicious.

## Dataset composition (flow counts)
Counts of effective flows and "Attempted" flows per label, as reported on the page:

| Label | Effective flows | "Attempted" flows |
|---|---|---|
| Benign | 1,657,069 | N/A |
| FTP-Patator | 3,973 | 11 |
| SSH-Patator | 2,980 | 8 |
| DoS GoldenEye | 7,567 | 80 |
| DoS Hulk | 158,469 | 579 |
| DoS SlowHttpTest | 1,742 | 3,367 |
| DoS Slowloris | 4,001 | 1,706 |
| Heartbleed | 11 | 0 |
| Web Attack - Brute Force | 151 | 1,214 |
| Web Attack - XSS | 27 | 652 |
| Web Attack - SQL Injection | 12 | 0 |
| Infiltration | 32 | 16 |
| Bot | 738 | 1,470 |
| Portscan | 159,023 | N/A |
| DDoS | 95,123 | 0 |

In words: 1,657,069 effective Benign flows; 95,123 effective DDoS flows and zero DDoS Attempted flows; 158,469 effective DoS Hulk flows and 579 DoS Hulk Attempted flows; 159,023 effective Portscan flows, where an Attempted count is not applicable; 27 effective Web Attack - XSS flows and 652 Web Attack - XSS Attempted flows. The web attack categories are Web Attack - Brute Force, Web Attack - XSS and Web Attack - SQL Injection.

## How the counts were computed
The flow counts (and the numbers in the paper) were obtained after removing all corrupted entries and all entries whose numerical features contained NaN values. NaN means "Not a Number": a value used to represent an invalid or missing number. The page notes that the table in the paper has an error: the correct total number of Attempted labels is 9,103, and the correct number of Benign flows for both the intermediate and final dataset versions is 1,657,069.

## Labelling and benchmarking code
The labelling logic is described in the Extended Documentation and the machine-learning experiments in the paper. The labelling and benchmarking code is available in the authors' GitHub repository. Reading the web page does not download the dataset itself: the CSV files must be downloaded separately from the link on the page.

## Citation requested by the authors
When using the fixed CICFlowMeter, the improved regenerated CICIDS2017 dataset, or the labelling and benchmarking code, the authors ask to cite: Gints Engelen, Vera Rimmer and Wouter Joosen, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study", 2021 IEEE Security and Privacy Workshops (SPW), pages 7-12, IEEE, 2021. The authors are Gints Engelen, Vera Rimmer and Wouter Joosen; the work was presented at the 2021 IEEE Security and Privacy Workshops (SPW); the page range is 7-12.
