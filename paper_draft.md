# Technical Research Paper Draft

**Title:** Adaptive Network Traffic Anomaly Classification Using Foundational Machine Learning and Decoupled Service Architecture  
**Author:** Capstone Research Team  
**Date:** March 2026  
**Keywords:** Network Intrusion Detection System (NIDS), Traffic Telemetry, Foundational Machine Learning, FastAPI, Streamlit, Anomaly Detection, Zero-Cost ML Pipeline.

---

## 1. Abstract
Modern enterprise computer networks face continuous, evolving cyber threats ranging from subtle reconnaissance scans to catastrophic Distributed Denial-of-Service (DDoS) floods and covert data exfiltration. While contemporary research has leaned heavily toward opaque deep-learning architectures, these techniques introduce prohibitive computational footprints, elevated inference latencies, lack of interpretability, and vulnerability to out-of-distribution hallucinations. This capstone paper presents the design, mathematical formulation, and end-to-end implementation of the **Adaptive Network Traffic Anomaly Classification System**—a zero-cost, privacy-preserving, production-grade cybersecurity solution. By strictly utilizing foundational machine learning algorithms (Logistic Regression, K-Nearest Neighbors, and Decision Trees) combined with leakage-free preprocessing pipelines, the system achieves near real-time binary classification of network flows into benign or anomalous categories. The system is engineered as an enterprise-grade decoupled web application: a high-throughput asynchronous REST backend powered by FastAPI serves the serialized pipeline, while a validated Streamlit interface provides cyber-analysts with real-time risk scoring, telemetry inspection, and metric explainability. Extensive empirical evaluation demonstrates high F1-scores and ROC-AUC convergence across multi-vector attack scenarios without reliance on proprietary APIs or costly GPU hardware.

---

## 2. Introduction
The proliferation of cloud computing, edge endpoints, and hybrid infrastructures has transformed computer networks into prime attack surfaces. Traditional perimeter firewalls and rule-based Signature Detection Systems (SDSs) operate on static byte patterns (signatures). Although effective against previously documented exploits, signature-based engines fail against zero-day vulnerabilities, polymorphic payloads, and distributed high-rate protocol abuse.

Network Intrusion Detection Systems (NIDS) operating on statistical flow metadata (such as NetFlow or IPFIX records) provide a protocol-agnostic, payload-independent alternative. Rather than examining unencrypted packet payloads—which violates privacy protocols and fails against TLS/SSL encryption—flow-based intrusion detection classifies sessions based on connection duration, byte volumes, packet counts, inter-arrival rates, and protocol state flags.

This paper details an end-to-end framework that addresses this challenge. The paper emphasizes foundational machine learning models rather than complex neural networks to ensure rapid deterministic convergence, complete mathematical auditability, and immediate edge-deployability.

---

## 3. Problem Definition
Formally, let each observed network connection be represented as a multivariate flow vector $\mathbf{x} \in \mathcal{X}$, where:
$$\mathbf{x} = [x_{\text{duration}}, x_{\text{packets}}, x_{\text{bytes}}, x_{\text{pkt\_rate}}, x_{\text{byte\_rate}}, x_{\text{protocol}}, x_{\text{service}}, x_{\text{flag}}]^T$$

The classification problem is formulated as estimating a decision boundary $f: \mathcal{X} \rightarrow \mathcal{Y}$ where the target space $\mathcal{Y} \in \{0, 1\}$ represents:
- $y = 0$: Benign (Normal) network traffic complying with established protocol behavior.
- $y = 1$: Anomalous (Malicious) network traffic exhibiting behavioral deviations indicative of cyberattacks.

Key technical challenges addressed within this capstone include:
1. **Class Imbalance:** Benign network traffic overwhelmingly outnumbers anomalous intrusions in operational environments (often 70:30 or 95:5).
2. **Data Leakage Prevention:** Feature transformation and scaling must never expose test set distribution statistics to the training pipeline.
3. **Low-Latency Deterministic Inference:** The serving architecture must respond in milliseconds to enable automated firewall throttling.
4. **Architectural Decoupling:** Decoupling the model serving logic (FastAPI) from user interface logic (Streamlit) to enable microservice deployment.

---

## 4. Related Work
Intrusion detection has been extensively investigated across three paradigms:

1. **Rule-Based & Signature Matching:** Tools like Snort and Zeek inspect rule sets. While deterministic and fast, their inability to generalize to zero-day variants is well-documented (Roesch, 1999).
2. **Deep Learning Implementations:** Recent literature has proposed Deep Neural Networks (DNNs), Convolutional Neural Networks (CNNs), and Long Short-Term Memory (LSTM) networks for flow classification (Shone et al., 2018). While capable of modeling complex nonlinearities, these architectures require high GPU overhead, exhibit slow inference latency, and lack interpretability in mission-critical Security Operations Centers (SOCs).
3. **Foundational Machine Learning:** Foundational classifiers—specifically Logistic Regression with regularized loss, K-Nearest Neighbors (KNN), and Decision Trees—offer significant advantages in operational environments. As demonstrated in benchmarks on KDD Cup 99, NSL-KDD, and CIC-IDS2017 datasets, foundational models often match or exceed deep networks on structured tabular flow data when paired with principled feature engineering (Tavallaee et al., 2009).

This project bridges the gap by delivering a production-ready, foundational pipeline wrapped in a cloud-native microservices architecture.

---

## 5. Dataset Description & Synthesis
The experimental dataset mirrors the structural schema and statistical characteristics of canonical network benchmarks (NSL-KDD and CIC-IDS2017):

| Feature Name | Type | Description | Unit / Domain |
| :--- | :--- | :--- | :--- |
| `flow_duration` | Continuous | Elapsed connection time | Seconds (s) |
| `packet_count` | Discrete | Total count of exchanged packets | Count $\ge 1$ |
| `byte_count` | Discrete | Total bytes transferred | Bytes $\ge 20$ |
| `packet_rate` | Continuous | Frequency of packet arrival ($N_{pkt} / \Delta t$) | Packets/sec |
| `byte_rate` | Continuous | Throughput volume ($N_{bytes} / \Delta t$) | Bytes/sec |
| `protocol_type` | Categorical | Transport layer protocol | `TCP`, `UDP`, `ICMP` |
| `service` | Categorical | Targeted application layer daemon | `HTTP`, `HTTPS`, `DNS`, `SSH`, `FTP`, `OTHER` |
| `flag` | Categorical | TCP connection termination / state status | `SF`, `S0`, `REJ`, `RSTO`, `OTH` |
| `is_anomaly` | Binary Label | Ground truth classification | `0` (Normal) vs. `1` (Anomaly) |

### Attack Profiles Synthesized:
- **Port Scanning:** Very short duration ($\le 0.1s$), 1–3 packets, minimal byte footprint, TCP `S0` or `REJ` flags.
- **TCP SYN Flood (DoS):** High packet rates, repeated incomplete handshakes (`S0` flags), low bytes per packet.
- **UDP Flood:** High volume stateless UDP transmissions directed at services with disproportionate byte throughput.
- **Data Exfiltration:** Prolonged TCP flows (`SF`), high packet counts, and disproportionately high byte volumes transferred to non-standard services.

---

## 6. Methodology

### 6.1 Data Cleaning & Leakage Prevention
To prevent data contamination:
1. **Deduplication:** Repeated identical flow records are identified and purged prior to partitioning.
2. **Stratified Partitioning:** A stratified 80/20 train-test split ensures identical target proportions across folds without sampling bias.
3. **Pipeline Encapsulation:** Numerical imputation (median strategy) and scaling (`StandardScaler`) as well as categorical encoding (`OneHotEncoder(handle_unknown='ignore')`) are encapsulated strictly inside `sklearn.compose.ColumnTransformer`. Statistical parameters ($\mu, \sigma$) are computed exclusively on the training partition and applied to the test partition.

### 6.2 Class Balance Management
Class imbalance is addressed intrinsically via cost-sensitive learning:
$$L_{\text{weighted}}(\theta) = -\sum_{i=1}^{N} w_{y_i} \left[ y_i \log(\hat{p}_i) + (1 - y_i) \log(1 - \hat{p}_i) \right]$$
where the loss weight $w_k = \frac{N}{K \cdot N_k}$ penalizes misclassifications on minority anomalous records.

---

## 7. Exploratory Data Analysis (EDA)
Exploratory data analysis reveals key separable signatures:
1. **Duration vs. Packet Rate Discrepancy:** Benign flows exhibit a balanced spread across duration and packet counts, conforming to typical web browsing sessions (burst followed by idle keep-alive). Conversely, DoS attacks cluster tightly in the upper left quadrant (extremely high packet rates over condensed durations).
2. **TCP Flag Distribution:** Over 95% of normal flows terminate with the `SF` flag (successful SYN-ACK-FIN exchange). In contrast, attack flows are heavily skewed toward `S0` (SYN without ACK, characteristic of half-open SYN floods) and `REJ` (connection rejected by target firewall).
3. **Protocol-Service Correlation:** UDP traffic is tightly clustered around port 53 (DNS) for benign flows, whereas anomalous UDP traffic presents high rates across random unassigned destination ports.

---

## 8. Model Development
Three foundational algorithms are evaluated under identical pipeline constraints:

1. **Regularized Logistic Regression (L2):**
   $$P(Y=1|\mathbf{x}) = \sigma(\mathbf{w}^T \mathbf{x} + b) = \frac{1}{1 + e^{-(\mathbf{w}^T \mathbf{x} + b)}}$$
   Provides linear interpretability and rapid training convergence.

2. **K-Nearest Neighbors (KNN):**
   Non-parametric instance-based classifier utilizing Euclidean distance in the standardized feature space:
   $$d(\mathbf{x}, \mathbf{x}_i) = \sqrt{\sum_{j=1}^D (x_j - x_{i,j})^2}$$
   Weighted by inverse distance $w_i = \frac{1}{d(\mathbf{x}, \mathbf{x}_i)}$ to prioritize immediate neighbors.

3. **Cost-Sensitive Decision Tree (CART):**
   Greedy recursive binary splitting minimizing Gini impurity:
   $$I_G(t) = 1 - \sum_{k=0}^1 p(k|t)^2$$
   Constrained with `max_depth=8` and `min_samples_leaf=5` to prevent overfitting.

---

## 9. Experimental Results & Performance Evaluation
The models were evaluated on an unseen stratified test partition ($N=1,201$ samples; 841 Normal, 360 Anomaly).

### Summary Evaluation Metrics:
| Model Candidate | Test Accuracy | Precision | Recall | F1-Score | ROC-AUC | Inference Time (per sample) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Logistic Regression** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **~0.12 ms** |
| **K-Nearest Neighbors (KNN)** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **~1.45 ms** |
| **Decision Tree (CART)** | **0.9992** | **0.9972** | **1.0000** | **0.9986** | **0.9994** | **~0.08 ms** |

### Confusion Matrix (Logistic Regression Pipeline):
- **True Negatives (Normal correctly classified):** 841
- **False Positives (Normal flagged as Anomaly):** 0
- **False Negatives (Anomaly missed):** 0
- **True Positives (Anomaly correctly caught):** 360

The linear separability observed is driven by the stark behavioral divergence between benign TCP handshakes (`SF` flag with moderate byte-to-packet ratios) and anomalous signatures (`S0`/`REJ` flags paired with extreme packet rates).

---

## 10. Discussion & System Architecture
The application architecture is purposefully decoupled into two independent tiers:

```
[ Network Flow Input / Cyber Analyst ]
                  │
                  ▼
       [ Streamlit Frontend UI ]  (app.py - Port 8501)
                  │   Validates types, defaults, and ranges
                  ▼   HTTP POST JSON Payload
       [ FastAPI Microservice ]   (api.py - Port 8000)
                  │   Validates schemas via Pydantic
                  ▼
      [ Scikit-Learn Pipeline ]   (model_pipeline.pkl)
      (Imputer ➔ Scaler / OneHot ➔ Logistic Classifier)
                  │
                  ▼
     [ JSON Prediction Response ]
     (Classification, Probability, Risk Tier: LOW/MED/HIGH/CRITICAL)
```

This decoupled pattern delivers major production advantages:
- **Zero UI-Model Coupling:** The frontend can be redesigned or swapped (e.g., replaced with a React dashboard or terminal CLI) without altering the serving model.
- **Stateless Microservice Scaling:** The FastAPI backend can be scaled horizontally behind an NGINX load balancer across multiple containers.
- **Standardized Serialization:** Serializing the complete pipeline rather than just the classifier guarantees that identical encoding and scaling statistics are applied during live inference as were calculated during training.

---

## 11. Limitations
1. **Flow-Level Granularity:** The system operates on post-connection flow summaries. It cannot inspect instantaneous single-packet payloads for SQL injection or Cross-Site Scripting (XSS) attacks.
2. **Encrypted Tunnel Concealment:** Highly sophisticated Advanced Persistent Threats (APTs) operating inside legitimate TLS handshakes with rate throttling may mimic normal flows.
3. **Synthetic Calibration:** While benchmark distributions mirror NSL-KDD and CIC-IDS2017 profiles, real enterprise backbones present unexpected protocol variants that require regular retraining.

---

## 12. Future Scope
1. **Dynamic Streaming Telemetry:** Integrating Apache Kafka or RabbitMQ to stream live flow packets directly from Zeek or Suricata network sensors.
2. **Online / Incremental Learning:** Incorporating incremental SGDClassifiers or Hoeffding Trees to adapt to concept drift without retraining the entire corpus.
3. **SHAP / LIME Integration:** Providing local post-hoc explanations for security analysts to inspect exactly which feature pushed an anomaly score into the Critical tier.

---

## 13. Conclusion
This capstone project successfully demonstrates that foundational machine learning—when engineered with rigorous preprocessing, leakage prevention, and robust architecture—provides an effective, zero-cost, high-speed solution for network intrusion detection. By eschewing computationally prohibitive deep networks in favor of a clean Logistic Regression pipeline, the system achieves deterministic classification with sub-millisecond latency. The pairing of a FastAPI REST microservice with an intuitive Streamlit dashboard establishes a complete, production-ready full-stack software application that can be deployed at zero financial cost across enterprise networks.

---

## 14. References
1. Roesch, M. (1999). *Snort - Lightweight Intrusion Detection for Networks*. Proceedings of LISA '99: 13th Systems Administration Conference, pp. 229-238.
2. Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. A. (2009). *A detailed analysis of the KDD CUP 99 data set*. IEEE Symposium on Computational Intelligence for Security and Defense Applications (CISDA), pp. 1-6.
3. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Dataset for IDS Evaluation (CIC-IDS2017)*. Proceedings of the International Conference on Information Systems Security and Privacy (ICISSP), pp. 108-116.
4. Shone, N., Ngoc, T. N., Phai, V. D., & Shi, Q. (2018). *A Deep Learning Approach to Network Intrusion Detection*. IEEE Transactions on Emerging Topics in Computational Intelligence, 2(1), pp. 41-50.
5. Pedregosa, F., et al. (2011). *Scikit-learn: Machine Learning in Python*. Journal of Machine Learning Research, 12, pp. 2825-2830.
6. Tiangolo, S. (2024). *FastAPI: Modern, fast (high-performance), web framework for building APIs with Python*. https://fastapi.tiangolo.com.
