"""
train.py - Machine Learning Pipeline for Network Traffic Anomaly Classification
Capstone Project: Adaptive Network Traffic Anomaly Classification

This module handles:
1. Benchmark dataset loading or synthetic flow generation.
2. Data cleaning, duplicate removal, and missing value management.
3. Leakage-free preprocessing via scikit-learn ColumnTransformer & Pipeline.
4. Training and cross-validation of foundational ML models:
   - Logistic Regression
   - K-Nearest Neighbors (KNN)
   - Decision Tree Classifier
5. Comprehensive evaluation (Accuracy, Precision, Recall, F1, ROC-AUC, Confusion Matrix).
6. Exporting the best-performing serialized pipeline as a .pkl artifact.
"""

import os
import sys
import json
import argparse
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

# ---------------------------------------------------------
# 1. Dataset Generation / Loading Helper
# ---------------------------------------------------------

def generate_benchmark_traffic_data(num_samples: int = 6000, random_state: int = 42) -> pd.DataFrame:
    """
    Generates a realistic benchmark network-flow dataset adhering to typical
    network flow telemetry (CIC-IDS / NSL-KDD style).
    
    Features:
      - flow_duration (seconds)
      - packet_count (int)
      - byte_count (int)
      - packet_rate (packets/sec)
      - byte_rate (bytes/sec)
      - protocol_type (TCP, UDP, ICMP)
      - service (HTTP, HTTPS, DNS, SSH, FTP, OTHER)
      - flag (SF: normal connection established/closed, S0: SYN with no reply,
              REJ: rejected, RSTO: connection reset, OTH: other)
    Target:
      - is_anomaly (0: Normal, 1: Anomaly)
    """
    np.random.seed(random_state)
    
    # 70% Normal flows, 30% Anomalous flows (class imbalance scenario)
    n_normal = int(num_samples * 0.70)
    n_anomaly = num_samples - n_normal
    
    # --- Normal Traffic Generation ---
    normal_protocols = np.random.choice(["TCP", "UDP", "ICMP"], size=n_normal, p=[0.75, 0.22, 0.03])
    normal_services = np.random.choice(["HTTPS", "HTTP", "DNS", "SSH", "FTP"], size=n_normal, p=[0.55, 0.25, 0.12, 0.05, 0.03])
    normal_flags = np.random.choice(["SF", "RSTO"], size=n_normal, p=[0.95, 0.05])
    
    # Realistic normal flow distributions
    normal_duration = np.random.exponential(scale=12.0, size=n_normal) + 0.05
    normal_packet_count = np.random.negative_binomial(n=10, p=0.15, size=n_normal) + 3
    # Normal bytes per packet ~ 600-1400 bytes
    normal_bytes_per_pkt = np.random.normal(loc=900, scale=200, size=n_normal).clip(64, 1500)
    normal_byte_count = (normal_packet_count * normal_bytes_per_pkt).astype(int)
    
    normal_pkt_rate = normal_packet_count / normal_duration
    normal_byte_rate = normal_byte_count / normal_duration
    
    df_normal = pd.DataFrame({
        "flow_duration": np.round(normal_duration, 4),
        "packet_count": normal_packet_count,
        "byte_count": normal_byte_count,
        "packet_rate": np.round(normal_pkt_rate, 4),
        "byte_rate": np.round(normal_byte_rate, 4),
        "protocol_type": normal_protocols,
        "service": normal_services,
        "flag": normal_flags,
        "is_anomaly": 0
    })
    
    # --- Anomalous Traffic Generation ---
    # Scenarios: Port Scans, DoS SYN Floods, UDP Floods, Heavy Data Exfiltration
    anomaly_types = np.random.choice(["port_scan", "syn_flood", "udp_flood", "exfil"], size=n_anomaly, p=[0.35, 0.35, 0.20, 0.10])
    
    anom_durations = []
    anom_packets = []
    anom_bytes = []
    anom_protocols = []
    anom_services = []
    anom_flags = []
    
    for attack in anomaly_types:
        if attack == "port_scan":
            # Very short duration, 1-3 packets, very small bytes, SYN without ACK (S0 or REJ)
            dur = np.random.uniform(0.001, 0.1)
            pkts = np.random.randint(1, 4)
            b = pkts * np.random.randint(40, 64)
            proto = "TCP"
            svc = np.random.choice(["OTHER", "SSH", "HTTP"])
            flg = np.random.choice(["S0", "REJ"], p=[0.7, 0.3])
        elif attack == "syn_flood":
            # Short-to-medium flow, high packet rate, S0 flag, small packet sizes
            dur = np.random.uniform(0.5, 5.0)
            pkts = np.random.randint(300, 2000)
            b = pkts * np.random.randint(44, 80)
            proto = "TCP"
            svc = np.random.choice(["HTTP", "HTTPS", "OTHER"])
            flg = "S0"
        elif attack == "udp_flood":
            # UDP, extremely high packet & byte rate
            dur = np.random.uniform(1.0, 10.0)
            pkts = np.random.randint(500, 3500)
            b = pkts * np.random.randint(512, 1400)
            proto = "UDP"
            svc = np.random.choice(["DNS", "OTHER"])
            flg = "SF"
        else: # exfil
            # Long duration, disproportionately high byte count, TCP SF
            dur = np.random.uniform(30.0, 180.0)
            pkts = np.random.randint(1000, 8000)
            b = pkts * np.random.randint(1300, 1500)
            proto = "TCP"
            svc = np.random.choice(["HTTPS", "FTP", "OTHER"])
            flg = "SF"
            
        anom_durations.append(dur)
        anom_packets.append(pkts)
        anom_bytes.append(b)
        anom_protocols.append(proto)
        anom_services.append(svc)
        anom_flags.append(flg)
        
    anom_durations = np.array(anom_durations)
    anom_packets = np.array(anom_packets)
    anom_bytes = np.array(anom_bytes)
    
    anom_pkt_rate = anom_packets / anom_durations
    anom_byte_rate = anom_bytes / anom_durations
    
    df_anomaly = pd.DataFrame({
        "flow_duration": np.round(anom_durations, 4),
        "packet_count": anom_packets,
        "byte_count": anom_bytes,
        "packet_rate": np.round(anom_pkt_rate, 4),
        "byte_rate": np.round(anom_byte_rate, 4),
        "protocol_type": anom_protocols,
        "service": anom_services,
        "flag": anom_flags,
        "is_anomaly": 1
    })
    
    # Merge and inject a small percentage of edge-cases (missing values and duplicate rows)
    df = pd.concat([df_normal, df_anomaly], ignore_index=True).sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    
    # Inject ~1% synthetic duplicate rows to test data cleaning
    duplicates = df.sample(n=int(num_samples * 0.015), random_state=random_state)
    df = pd.concat([df, duplicates], ignore_index=True)
    
    # Inject ~1% missing values in numeric fields to test imputers
    mask_nan = np.random.rand(len(df)) < 0.01
    df.loc[mask_nan, "packet_rate"] = np.nan
    
    return df


# ---------------------------------------------------------
# 2. Pipeline Construction (Leakage Prevention)
# ---------------------------------------------------------

NUMERIC_FEATURES = ["flow_duration", "packet_count", "byte_count", "packet_rate", "byte_rate"]
CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]

def build_preprocessor() -> ColumnTransformer:
    """
    Constructs a ColumnTransformer to apply preprocessing safely within
    scikit-learn Pipeline, ensuring zero data leakage between train and test splits.
    """
    numeric_transformer = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler())
    ])
    
    categorical_transformer = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False))
    ])
    
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, NUMERIC_FEATURES),
            ("cat", categorical_transformer, CATEGORICAL_FEATURES)
        ]
    )
    return preprocessor


# ---------------------------------------------------------
# 3. Model Training and Evaluation Routine
# ---------------------------------------------------------

def evaluate_model(name: str, pipeline: Pipeline, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
    """
    Computes rigorous evaluation metrics on the unseen test set:
    Accuracy, Precision, Recall, F1-score, ROC-AUC, and Confusion Matrix.
    """
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1] if hasattr(pipeline, "predict_proba") else y_pred
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred).tolist()
    
    print(f"\n==========================================")
    print(f"Model Evaluation: {name}")
    print(f"==========================================")
    print(f"  Accuracy : {acc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall   : {rec:.4f}")
    print(f"  F1-Score : {f1:.4f}")
    print(f"  ROC-AUC  : {roc_auc:.4f}")
    print(f"  Confusion Matrix (TN, FP / FN, TP):")
    print(f"    [[{cm[0][0]}, {cm[0][1]}],")
    print(f"     [{cm[1][0]}, {cm[1][1]}]]")
    
    return {
        "model_name": name,
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "roc_auc": round(float(roc_auc), 4),
        "confusion_matrix": cm
    }


def main():
    parser = argparse.ArgumentParser(description="Train Adaptive Network Traffic Anomaly Classifier")
    parser.add_argument("--data", type=str, default="network_traffic.csv", help="Path to input CSV dataset")
    parser.add_argument("--export-dir", type=str, default=".", help="Directory to save exported artifacts")
    args = parser.parse_args()
    
    os.makedirs(args.export_dir, exist_ok=True)
    
    # Step A: Load or generate data
    if os.path.exists(args.data):
        print(f"[+] Loading dataset from existing file: {args.data}")
        df = pd.read_csv(args.data)
    else:
        print(f"[!] Dataset '{args.data}' not found. Generating synthetic benchmark dataset...")
        df = generate_benchmark_traffic_data(num_samples=6000, random_state=42)
        df.to_csv(args.data, index=False)
        print(f"[+] Benchmark dataset generated and saved to '{args.data}' ({len(df)} records).")
        
    print(f"[*] Initial Dataset Shape: {df.shape}")
    print(f"[*] Class Distribution:\n{df['is_anomaly'].value_counts(normalize=True).to_dict()}")
    
    # Step B: Data Cleaning
    # 1. Deduplication
    initial_rows = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    dedup_rows = len(df)
    print(f"[+] Dropped {initial_rows - dedup_rows} duplicate rows. Remaining: {dedup_rows}")
    
    # 2. Check and separate features vs target
    target_col = "is_anomaly"
    if target_col not in df.columns:
        raise ValueError(f"Target column '{target_col}' not present in dataset.")
        
    X = df.drop(columns=[target_col])
    y = df[target_col].astype(int)
    
    # Step C: Train-Test Split (BEFORE PREPROCESSING to prevent any leakage)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[+] Split completed: Train={len(X_train)} samples, Test={len(X_test)} samples (Stratified)")

    # Step D: Foundational Models (Excluding complex deep learning)
    candidate_models = {
        "Logistic Regression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42
        ),
        "K-Nearest Neighbors (KNN)": KNeighborsClassifier(
            n_neighbors=5,
            weights="distance",
            metric="minkowski"
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=8,
            min_samples_split=10,
            min_samples_leaf=5,
            class_weight="balanced",
            random_state=42
        )
    }
    
    preprocessor = build_preprocessor()
    results = []
    trained_pipelines = {}
    
    for name, clf in candidate_models.items():
        print(f"\n[*] Training {name} pipeline...")
        # End-to-end pipeline: Preprocessor + Model
        pipeline = Pipeline(steps=[
            ("preprocessor", preprocessor),
            ("classifier", clf)
        ])
        
        # Fit on training data ONLY
        pipeline.fit(X_train, y_train)
        
        # Evaluate on unseen test data
        eval_metrics = evaluate_model(name, pipeline, X_test, y_test)
        results.append(eval_metrics)
        trained_pipelines[name] = pipeline

    # Step E: Model Selection based on best F1-Score & ROC-AUC
    # In intrusion detection, high F1 and ROC-AUC balance false alarms and missed attacks
    best_result = max(results, key=lambda m: (m["f1_score"], m["roc_auc"]))
    best_model_name = best_result["model_name"]
    best_pipeline = trained_pipelines[best_model_name]
    
    print("\n" + "="*50)
    print(f"[*] BEST FOUNDATIONAL MODEL SELECTED: {best_model_name}")
    print(f"    F1-Score: {best_result['f1_score']:.4f} | ROC-AUC: {best_result['roc_auc']:.4f}")
    print("="*50)
    
    # Step F: Export the Best Pipeline and Metadata
    model_pkl_path = os.path.join(args.export_dir, "model_pipeline.pkl")
    metadata_path = os.path.join(args.export_dir, "model_metadata.json")
    
    # Serialize the complete pipeline
    joblib.dump(best_pipeline, model_pkl_path)
    print(f"[+] End-to-end pipeline exported to: {model_pkl_path}")
    
    # Extract feature names from preprocessor for API & UI explainability
    preprocessor_fitted = best_pipeline.named_steps["preprocessor"]
    cat_encoder = preprocessor_fitted.named_transformers_["cat"].named_steps["encoder"]
    encoded_cat_names = cat_encoder.get_feature_names_out(CATEGORICAL_FEATURES).tolist()
    all_feature_names = NUMERIC_FEATURES + encoded_cat_names
    
    metadata = {
        "best_model": best_model_name,
        "evaluation_metrics": best_result,
        "all_candidate_metrics": results,
        "input_features": {
            "numeric": NUMERIC_FEATURES,
            "categorical": CATEGORICAL_FEATURES
        },
        "all_transformed_features": all_feature_names,
        "classes": ["Normal", "Anomaly"],
        "class_mapping": {"0": "Normal", "1": "Anomaly"}
    }
    
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=4)
    print(f"[+] Metadata and metrics exported to: {metadata_path}")
    print("\n[SUCCESS] Training pipeline execution finished successfully!")


if __name__ == "__main__":
    main()
