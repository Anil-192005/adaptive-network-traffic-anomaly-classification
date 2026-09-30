"""
api.py - FastAPI Backend Service for Network Traffic Anomaly Classification
Capstone Project: Adaptive Network Traffic Anomaly Classification

Serves the serialized scikit-learn pipeline (.pkl) via high-performance REST APIs.
Provides input validation via Pydantic, risk probability calibration,
and real-time classification endpoints.
"""

import os
import json
from datetime import datetime, timezone
from typing import List, Optional, Literal

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Load artifacts
    load_artifacts()
    yield

# ---------------------------------------------------------
# App Initialization & CORS
# ---------------------------------------------------------

app = FastAPI(
    title="Adaptive Network Traffic Anomaly Classification API",
    description="High-throughput REST API serving foundational ML models for real-time intrusion and flow anomaly detection.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# Model & Metadata Loading
# ---------------------------------------------------------

MODEL_PATH = os.getenv("MODEL_PATH", "model_pipeline.pkl")
METADATA_PATH = os.getenv("METADATA_PATH", "model_metadata.json")

pipeline = None
metadata = {}

def load_artifacts():
    global pipeline, metadata
    if os.path.exists(MODEL_PATH):
        try:
            pipeline = joblib.load(MODEL_PATH)
            print(f"[+] Loaded ML pipeline from {MODEL_PATH}")
        except Exception as e:
            print(f"[!] Error loading model pipeline: {e}")
            pipeline = None
    else:
        print(f"[!] Model file '{MODEL_PATH}' not found. Please run train.py first.")

    if os.path.exists(METADATA_PATH):
        try:
            with open(METADATA_PATH, "r") as f:
                metadata = json.load(f)
            print(f"[+] Loaded metadata from {METADATA_PATH}")
        except Exception as e:
            print(f"[!] Error loading metadata: {e}")
            metadata = {}

# Immediate initialization
load_artifacts()


# ---------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------

class NetworkFlowInput(BaseModel):
    flow_duration: float = Field(
        ..., ge=0.0, description="Duration of the connection in seconds (e.g. 0.05, 12.4)"
    )
    packet_count: int = Field(
        ..., ge=1, description="Total number of packets observed in the flow"
    )
    byte_count: int = Field(
        ..., ge=20, description="Total number of bytes transferred in the flow"
    )
    packet_rate: Optional[float] = Field(
        None, ge=0.0, description="Rate of packets per second. Automatically calculated if omitted."
    )
    byte_rate: Optional[float] = Field(
        None, ge=0.0, description="Rate of bytes per second. Automatically calculated if omitted."
    )
    protocol_type: Literal["TCP", "UDP", "ICMP"] = Field(
        ..., description="Transport layer protocol: TCP, UDP, or ICMP"
    )
    service: str = Field(
        ..., description="Application layer service (e.g. HTTP, HTTPS, DNS, SSH, FTP, OTHER)"
    )
    flag: str = Field(
        ..., description="Connection status flag (e.g. SF, S0, REJ, RSTO, OTH)"
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "flow_duration": 0.045,
                "packet_count": 2,
                "byte_count": 88,
                "packet_rate": 44.44,
                "byte_rate": 1955.5,
                "protocol_type": "TCP",
                "service": "HTTP",
                "flag": "S0"
            }
        }
    }


class AnomalyPrediction(BaseModel):
    prediction: str = Field(..., description="'Normal' or 'Anomaly'")
    is_anomaly: bool = Field(..., description="Boolean flag: True if anomalous, False otherwise")
    anomaly_probability: float = Field(..., description="Probability of flow being an anomaly [0.0 - 1.0]")
    risk_level: str = Field(..., description="Categorical risk: LOW, MEDIUM, HIGH, CRITICAL")
    confidence_score: float = Field(..., description="Model certainty in the assigned classification [0.0 - 1.0]")
    model_name: str = Field(..., description="Active foundational model serving predictions")
    processed_at: str = Field(..., description="Timestamp of inference (ISO 8601)")


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    active_model: Optional[str] = None
    timestamp: str


# ---------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------

def compute_risk_level(prob: float) -> str:
    """Categorizes anomaly probability into standard cybersecurity risk tiers."""
    if prob >= 0.85:
        return "CRITICAL"
    elif prob >= 0.60:
        return "HIGH"
    elif prob >= 0.40:
        return "MEDIUM"
    return "LOW"


def prepare_dataframe(inputs: List[NetworkFlowInput]) -> pd.DataFrame:
    """Converts validated Pydantic items into a normalized Pandas DataFrame."""
    records = []
    for item in inputs:
        d = item.dict()
        dur = max(d["flow_duration"], 0.0001)
        # Compute rates dynamically if not explicitly provided
        if d.get("packet_rate") is None:
            d["packet_rate"] = round(d["packet_count"] / dur, 4)
        if d.get("byte_rate") is None:
            d["byte_rate"] = round(d["byte_count"] / dur, 4)
        records.append(d)
    return pd.DataFrame(records)


# ---------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------

@app.get("/", tags=["General"])
def read_root():
    return {
        "service": "Adaptive Network Traffic Anomaly Classification API",
        "version": "1.0.0",
        "documentation": "/docs",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse, tags=["General"])
def health_check():
    return HealthResponse(
        status="healthy" if pipeline is not None else "degraded (model not loaded)",
        model_loaded=pipeline is not None,
        active_model=metadata.get("best_model", "Unknown") if pipeline else None,
        timestamp=datetime.now(timezone.utc).isoformat()
    )


@app.get("/metrics", tags=["Model Analytics"])
def get_model_metrics():
    """Returns training evaluation metrics and baseline comparisons."""
    if not metadata:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model metadata not found. Train the model using train.py."
        )
    return metadata


@app.post("/predict", response_model=AnomalyPrediction, tags=["Inference"])
def predict_flow(flow: NetworkFlowInput):
    """
    Accepts network-flow metrics, applies the serialized preprocessor pipeline,
    and returns binary classification (Normal / Anomaly) with calibrated risk score.
    """
    global pipeline
    if pipeline is None:
        load_artifacts()
        if pipeline is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Model pipeline is not loaded on server. Please run train.py to generate model_pipeline.pkl."
            )

    try:
        df = prepare_dataframe([flow])
        
        # Binary prediction (0 or 1)
        pred_label_idx = int(pipeline.predict(df)[0])
        
        # Probabilities
        if hasattr(pipeline, "predict_proba"):
            probs = pipeline.predict_proba(df)[0]
            anomaly_prob = float(probs[1])
            confidence = float(max(probs))
        else:
            anomaly_prob = 1.0 if pred_label_idx == 1 else 0.0
            confidence = 1.0

        label_name = "Anomaly" if pred_label_idx == 1 else "Normal"
        is_anom = (pred_label_idx == 1)
        risk = compute_risk_level(anomaly_prob)
        
        return AnomalyPrediction(
            prediction=label_name,
            is_anomaly=is_anom,
            anomaly_probability=round(anomaly_prob, 4),
            risk_level=risk,
            confidence_score=round(confidence, 4),
            model_name=metadata.get("best_model", "Foundational ML Pipeline"),
            processed_at=datetime.now(timezone.utc).isoformat()
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error: {str(e)}"
        )


@app.post("/batch-predict", response_model=List[AnomalyPrediction], tags=["Inference"])
def batch_predict_flows(flows: List[NetworkFlowInput]):
    """Accepts multiple network flows in bulk and returns array of predictions."""
    global pipeline
    if pipeline is None:
        load_artifacts()
        if pipeline is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Model pipeline is not loaded. Train model using train.py."
            )

    try:
        df = prepare_dataframe(flows)
        preds = pipeline.predict(df)
        
        if hasattr(pipeline, "predict_proba"):
            all_probs = pipeline.predict_proba(df)
        else:
            all_probs = [[1.0 - p, float(p)] for p in preds]

        results = []
        now_iso = datetime.now(timezone.utc).isoformat()
        model_name = metadata.get("best_model", "Foundational ML Pipeline")

        for idx, pred_idx in enumerate(preds):
            p_idx = int(pred_idx)
            prob_anom = float(all_probs[idx][1])
            results.append(AnomalyPrediction(
                prediction="Anomaly" if p_idx == 1 else "Normal",
                is_anomaly=(p_idx == 1),
                anomaly_probability=round(prob_anom, 4),
                risk_level=compute_risk_level(prob_anom),
                confidence_score=round(float(max(all_probs[idx])), 4),
                model_name=model_name,
                processed_at=now_iso
            ))
        return results
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch inference error: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
