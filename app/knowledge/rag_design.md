# How the assistant's RAG works

Design notes for the retrieval-augmented generation (RAG) assistant in the NIDS app.

## Retrieval
Retrieval searches a knowledge source and selects the passages most relevant to the user's question before an answer is generated. Our knowledge source is a set of documents: notes on the improved CICIDS2017 dataset page, the attack library (description, MITRE ATT&CK technique, indicators and response steps for every attack), our project notes, and these design notes. The retriever returns the top-ranked text passages that are most relevant to the question, and only those passages are given to the language model.

## Chunking and overlap
The source text is split into chunks because smaller passages can be indexed and retrieved individually, instead of searching one large block of text. Long sections are cut into chunks of about 900 characters. Adjacent chunks overlap by about 150 characters so that a relevant passage that crosses a chunk boundary still keeps its context.

## Vectors, embeddings and cosine similarity
Each chunk and each question is turned into a numeric vector. Embeddings represent text as numeric vectors so that semantically related questions and passages can be compared. Our app uses TF-IDF vectors (computed locally, no external API) and ranks chunks by cosine similarity. Cosine similarity compares the orientation (angle) of two vectors and is commonly used to rank passages by similarity, independent of their length.

## TOP_K
TOP_K is the number of highest-ranked passages passed to the answer-generation step. Our default is 4 and it can be changed in the assistant settings. A small TOP_K keeps the prompt focused; a larger one gives more context but may add noise.

## Answer generation with Gemini
Gemini, Google's large language model, generates a natural-language answer from the user's question, the retrieved passages and the context of the selected alert (prediction, confidence and the features that drove it), all supplied in the prompt. If no Gemini API key is configured, the assistant still answers from the retrieved passages and the alert context directly, without a language model.

## Citations and verification
Answers cite the retrieved passages as [S1], [S2] and so on, and every answer lists its sources so the user can verify which passages support it. Checking the retrieved context before accepting an answer reduces the risk of unsupported, invented claims. A high similarity score is only a ranking signal, not proof of factual correctness: a passage can be related to the question and still fail to answer it. The system must never make up citations, because invented citations cannot be verified and wrongly attribute claims to the source. When the sources do not contain the answer, the assistant must clearly say that the answer was not found in the retrieved sources rather than inventing details.

## When the source page cannot be retrieved
If the dataset web page cannot be fetched, check the URL and network access and handle HTTP errors; keeping an authorised local copy of the source text for indexing avoids the problem. Our app indexes local notes, so it does not depend on the page being online. Retrieving the page text does not download the dataset itself; the dataset files must be downloaded separately.

## Evaluating retrieval
The team's question bank (50 questions with expected answers) is used as a test set: for each question we check whether the retriever finds a passage that supports the expected answer before any answer is generated. The question bank itself is left out of the index during this test. The result (hit rate at TOP_K) is shown in the app's Model & Data page.
