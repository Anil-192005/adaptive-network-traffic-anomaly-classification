# Adaptive Network Traffic Anomaly Classification
## Capstone Project & Technical Evaluation Report

- **Author:** Anil M
- **GitHub Repository:** [Anil-192005/adaptive-network-traffic-anomaly-classification](https://github.com/Anil-192005/adaptive-network-traffic-anomaly-classification)
- **Live Web App:** [https://nikon-module-literacy-weather.trycloudflare.com](https://nikon-module-literacy-weather.trycloudflare.com)
- **Live API Docs:** [https://stands-eligible-incentive-cells.trycloudflare.com/docs](https://stands-eligible-incentive-cells.trycloudflare.com/docs)
- **Technology Stack:** Python 3.12, Scikit-Learn, FastAPI, Streamlit, Pydantic, Cloudflare Tunnel

---

## 1. Executive Summary
This capstone project presents an end-to-end, zero-cost machine learning software application designed to classify computer network traffic flows as either **Benign (Normal)** or **Anomalous (Malicious)** in real time. Rather than relying on computationally heavy, black-box deep learning architectures, the system harnesses foundational machine learning algorithms (Logistic Regression, K-Nearest Neighbors, and Decision Trees) combined with leakage-free preprocessing pipelines. The resulting solution is deployed as a fully decoupled web application featuring an asynchronous REST API backend built on **FastAPI** and an interactive cyber threat dashboard built on **Streamlit**.

---

## 2. Problem Statement & Objectives
Modern computer networks face continuous multi-vector threats including port scanning, Distributed Denial-of-Service (DDoS) floods, and covert data exfiltration. Conventional signature-based intrusion detection engines fail when confronted with polymorphic payloads and novel zero-day attacks. Furthermore, full packet inspection violates user privacy and is computationally intractable over high-speed encrypted channels.

### Key Objectives:
1. **Zero-Cost, Payload-Agnostic Detection:** Classify network sessions strictly using connection duration, packet counts, byte volumes, and flags.
2. **Leakage-Free Preprocessing:** Standard scaling and One-Hot encoding strictly fit on training splits within an end-to-end `Pipeline`.
3. **Decoupled Architecture:** Asynchronous FastAPI backend serving serialized models (`model_pipeline.pkl`) via RESTful JSON endpoints.
4. **Interactive Cyber Dashboard:** Streamlit frontend supporting manual telemetry input, rate computations, and scenario libraries.
5. **Cross-Device Availability:** Accessible on any phone, tablet, or PC browser worldwide.

---

## 3. System Architecture
```
┌────────────────────────────────────────────────────────┐
│             External User / Security Analyst           │
│         (Any device: Mobile, Tablet, Laptop)           │
└───────────────────────────┬────────────────────────────┘
                            │ HTTPS Request
                            ▼
┌────────────────────────────────────────────────────────┐
│        Streamlit Frontend User Interface (app.py)      │
│  - Input validation (Ranges, Protocols, Services)      │
│  - Automatic rate derivation (Packet & Byte Rates)     │
│  - Preset cyber-attack scenario library                │
└───────────────────────────┬────────────────────────────┘
                            │ HTTP POST (JSON Payload)
                            ▼
┌────────────────────────────────────────────────────────┐
│          FastAPI Microservice Backend (api.py)         │
│  - Strict schema enforcement via Pydantic              │
│  - Asynchronous non-blocking endpoints (/predict)     │
│  - CORS middleware for multi-device cross-origin calls │
└───────────────────────────┬────────────────────────────┘
                            │ Pipeline Inference
                            ▼
┌────────────────────────────────────────────────────────┐
│      Serialized ML Pipeline (model_pipeline.pkl)       │
│  - ColumnTransformer (StandardScaler + OneHotEncoder)  │
│  - Champion Classifier (Regularized Logistic Reg)      │
│  - Risk Tier Engine: LOW | MEDIUM | HIGH | CRITICAL    │
└────────────────────────────────────────────────────────┘
```

---

## 4. Dataset Specifications & Feature Schema
The model evaluates 8 core network flow telemetry features modeled after canonical intrusion datasets (CIC-IDS2017 & NSL-KDD):

| Feature Name | Type | Description | Typical Benign Range | Attack Signature Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `flow_duration` | Float | Connection lifespan (seconds) | 1.0s – 60.0s | < 0.1s (Port scan) or high (Exfil) |
| `packet_count` | Integer | Total packets in conversation | 10 – 300 | 1–3 (Scans) or > 1,000 (SYN Flood) |
| `byte_count` | Integer | Total bytes exchanged | 1,000 – 250,000 | < 100 bytes (Scans) or > 5MB (Exfil) |
| `packet_rate` | Float | Packets per second | 5 – 50 pkts/s | > 500 pkts/s (DoS/Flood) |
| `byte_rate` | Float | Bytes per second | 1 KB/s – 100 KB/s | Massive throughput or micro-bursts |
| `protocol_type` | Categorical | Transport protocol | TCP, UDP, ICMP | UDP floods, ICMP echo attacks |
| `service` | Categorical | Application layer service | HTTPS, HTTP, DNS | Unassigned port attempts, SSH probes |
| `flag` | Categorical | Connection state flag | `SF` (Normal Finish) | `S0` (SYN no ACK), `REJ` (Rejected) |

---

## 5. Model Development & Experimental Evaluation
Three foundational machine learning models were trained and benchmarked against an unseen, stratified test split of 1,201 flows (841 Benign, 360 Anomalous):

| Candidate Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Logistic Regression (Balanced)** | **100.0%** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **Selected Champion** |
| **K-Nearest Neighbors (k=5, Distance)** | 100.0% | 1.0000 | 1.0000 | 1.0000 | 1.0000 | Candidate |
| **Decision Tree (Max Depth=8)** | 99.92% | 0.9972 | 1.0000 | 0.9986 | 0.9994 | Candidate |

### Confusion Matrix (Champion Model - Test Set):
- **True Negatives (Normal correctly classified):** 841
- **False Positives (Normal flagged as Anomaly):** 0
- **False Negatives (Anomaly missed):** 0
- **True Positives (Anomaly correctly caught):** 360

---

## 6. Live Deployment & Verification
- **Frontend Dashboard:** [https://nikon-module-literacy-weather.trycloudflare.com](https://nikon-module-literacy-weather.trycloudflare.com)
- **FastAPI REST Service:** [https://stands-eligible-incentive-cells.trycloudflare.com/docs](https://stands-eligible-incentive-cells.trycloudflare.com/docs)
- **GitHub Repository:** [https://github.com/Anil-192005/adaptive-network-traffic-anomaly-classification](https://github.com/Anil-192005/adaptive-network-traffic-anomaly-classification)

---

## 7. Conclusion
The Adaptive Network Traffic Anomaly Classification project successfully illustrates that robust, low-latency, interpretable intrusion detection does not require heavy deep-learning frameworks or paid commercial APIs. By pairing leakage-free preprocessing with foundational models and an asynchronous microservices architecture, the project provides a deterministic, zero-cost cyber defense capability suitable for production network telemetry.
