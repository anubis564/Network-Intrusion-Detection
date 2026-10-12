# Question bank

Questions and answers about the improved CICIDS2017 dataset and the RAG assistant, prepared by the team.
Source page: https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html

### Q1. What is the main purpose of the improved CICIDS2017 dataset?
It is a flow-based dataset intended to support research and evaluation in network intrusion detection.

### Q2. What is CICFlowMeter used for?
CICFlowMeter extracts flow-based features from network traffic so flows can be used for analysis and machine-learning tasks.

### Q3. Why did the authors provide a fixed version of CICFlowMeter?
The fixed version addresses identified issues in how TCP flows are constructed and terminated.

### Q4. How did the fixed version change TCP FIN handling?
A TCP flow is not terminated after just one FIN packet; it is terminated after FIN packets have been mutually exchanged.

### Q5. How does the fixed version treat an RST packet?
An RST packet terminates the TCP flow rather than being ignored.

### Q6. Was the timeout-based flow termination behavior changed?
No. The page states that the existing timeout behavior was left unchanged.

### Q7. Where does the page link to the fixed CICFlowMeter code?
It links to the GitHub repository https://github.com/GintsEngelen/CICFlowMeter.

### Q8. What is a network flow in the context of this dataset?
A network flow is a collection of traffic packets grouped for flow-level feature extraction and analysis.

### Q9. What is meant by a flow-based intrusion detection dataset?
It represents network activity through flow-level features rather than requiring every packet to be analyzed independently.

### Q10. What does the label 'X - Attempted' mean?
For a payload-dependent attack class X, the label indicates that the flow is associated with the attack class but lacks the payload required for the attack to be effective.

### Q11. Why distinguish effective attacks from attempted attacks?
The distinction separates flows where the attack was effective from flows that match an attack class but lack the required payload.

### Q12. What does the label Benign represent?
It identifies traffic classified as non-malicious in the dataset.

### Q13. How many effective Benign flows are listed?
The page lists 1,657,069 effective Benign flows.

### Q14. How many effective DDoS flows are listed?
The page lists 95,123 effective DDoS flows.

### Q15. How many DDoS 'Attempted' flows are listed?
The page lists zero DDoS 'Attempted' flows.

### Q16. How many effective DoS Hulk flows are listed?
The page lists 158,469 effective DoS Hulk flows.

### Q17. How many DoS Hulk 'Attempted' flows are listed?
The page lists 579 DoS Hulk 'Attempted' flows.

### Q18. How many effective Portscan flows are listed?
The page lists 159,023 effective Portscan flows.

### Q19. Is an 'Attempted' count applicable to Portscan in the table?
The table shows the 'Attempted' count as not applicable for Portscan.

### Q20. Which web attack categories appear in the dataset composition table?
The table includes Web Attack - Brute Force, Web Attack - XSS, and Web Attack - SQL Injection.

### Q21. How many effective Web Attack - XSS flows are listed?
The page lists 27 effective Web Attack - XSS flows.

### Q22. How many Web Attack - XSS 'Attempted' flows are listed?
The page lists 652 Web Attack - XSS 'Attempted' flows.

### Q23. Why were some dataset entries excluded from the reported counts?
The counts were calculated after removing corrupted entries and entries with NaN values in numerical features.

### Q24. What does NaN mean in a numerical dataset?
NaN means 'Not a Number' and is commonly used to represent an invalid or missing numerical value.

### Q25. What is the corrected total number of 'Attempted' labels mentioned on the page?
The page states that the correct total amount of 'Attempted' labels is 9,103.

### Q26. Why is data cleaning important before training an intrusion detection model?
Invalid or corrupted rows and NaN numerical features can interfere with model training, evaluation, and reproducibility.

### Q27. What role do labels play in supervised intrusion detection?
Labels provide the target classes a supervised model learns to predict, such as benign traffic or a specific attack class.

### Q28. What is the difference between benign and malicious traffic labels?
Benign labels indicate non-malicious traffic, while attack labels identify traffic associated with a particular attack category.

### Q29. Can the dataset be used to evaluate a machine-learning classifier?
Yes. A labelled flow-based intrusion detection dataset can be used to train and evaluate classifiers, provided the data is prepared and split appropriately.

### Q30. Why should researchers document dataset preprocessing?
Documenting preprocessing makes results easier to reproduce and helps explain how cleaning and labeling affect the dataset.

### Q31. Why should the retrieved context be checked before accepting an answer?
Checking retrieved passages verifies that the answer is supported by the source and reduces the risk of unsupported model-generated claims.

### Q32. What is retrieval in a RAG system?
Retrieval searches a knowledge source and selects passages relevant to a user's question before answer generation.

### Q33. What is the role of embeddings in semantic retrieval?
Embeddings represent text as numeric vectors so semantically related questions and passages can be compared.

### Q34. What does cosine similarity measure in vector search?
Cosine similarity compares the orientation of two vectors and is commonly used to rank text passages by semantic similarity.

### Q35. Why split a webpage into chunks for RAG?
Chunking creates smaller passages that can be embedded and retrieved individually instead of searching one large block of text.

### Q36. What is the purpose of overlap between adjacent chunks?
Overlap helps preserve context when a relevant passage crosses a chunk boundary.

### Q37. What does the retriever return to the language model?
It returns the top-ranked text passages that are most relevant to the question.

### Q38. What should a RAG chatbot do when the source does not contain the answer?
It should clearly state that the answer was not found in the retrieved source rather than inventing details.

### Q39. Why should answers cite retrieved passages?
Citations help users verify which source passages support the generated answer.

### Q40. What is the role of Gemini in this RAG application?
Gemini can generate a natural-language answer using the question and the retrieved passages supplied in the prompt.

### Q41. What is the role of Streamlit in the project?
Streamlit provides the user interface for entering questions, displaying answers, and inspecting retrieved context.

### Q42. What does TOP_K control in a simple retrieval pipeline?
TOP_K determines how many of the highest-ranked passages are selected for the answer-generation step.

### Q43. Why can a high similarity score still lead to a wrong answer?
Similarity is a ranking signal, not proof of factual correctness; the passage may be related but still fail to answer the question.

### Q44. Why should a RAG system avoid making up citations?
Invented citations cannot be verified and may incorrectly attribute claims to the source.

### Q45. What should be done if the webpage cannot be retrieved?
Check the URL and network access, handle HTTP errors, and consider saving an authorized copy of the source text for indexing.

### Q46. Does this webpage retrieval code automatically download the full dataset files?
No. Retrieving the webpage text does not download the dataset itself; dataset files must be downloaded separately from the links provided on the page.

### Q47. What citation does the webpage request for the fixed tool or improved dataset?
The page requests citation of Engelen, Rimmer, and Joosen, 'Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study,' presented at the 2021 IEEE Security and Privacy Workshops (SPW), pages 7–12.

### Q48. Who are the authors named in the requested citation?
The requested citation names Gints Engelen, Vera Rimmer, and Wouter Joosen.

### Q49. At which event was the cited CICIDS2017 case study presented?
The cited work was presented at the 2021 IEEE Security and Privacy Workshops (SPW).

### Q50. What page range is given for the cited paper?
The page range listed is 7–12.
