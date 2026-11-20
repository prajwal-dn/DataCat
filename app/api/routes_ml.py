"""FastAPI routes for DATACAT Logistic Regression ML Service.

Endpoints:
  - POST /api/v1/ml/predict: Live binary anomaly classification on verified telemetry.
  - GET /api/v1/ml/model-info: Returns model architecture, features, weights, and threshold.
  - GET /api/v1/ml/evaluation: Detailed training, validation, and testing metrics.
  - POST /api/v1/ml/reload: Reloads saved JSON model from disk without service restart.
"""

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
import aiosqlite

from app.db.database import get_db_connection
from app.ml.inference import get_model, predict_telemetry_event, reload_model

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ml", tags=["Machine Learning Inference"])


async def get_db():
    db = await get_db_connection()
    try:
        yield db
    finally:
        await db.close()


@router.get("/model-info")
async def model_info():
    """Returns current Logistic Regression model metadata, features, weights, and threshold."""
    try:
        model = get_model()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load model: {e}")

    return {
        "model_type": "LogisticRegressionBinaryClassifier",
        "model_version": model.model_version,
        "feature_count": len(model.feature_names),
        "feature_names": model.feature_names,
        "classification_threshold": model.threshold,
        "intercept": model.intercept,
        "weights": {
            model.feature_names[j]: model.weights[j]
            for j in range(len(model.feature_names))
        },
        "standardization": {
            "means": model.standardizer.means,
            "stds": model.standardizer.stds,
        },
        "training_configuration": model.training_configuration,
    }


@router.get("/evaluation")
async def model_evaluation():
    """Returns evaluation metrics across Training (70%), Validation (15%), and Test (15%) splits."""
    try:
        model = get_model()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load model: {e}")

    metadata = model.training_metadata
    if not metadata:
        return {"status": "NO_EVALUATION_METADATA"}

    return {
        "model_version": model.model_version,
        "dataset_total_samples": metadata.get("dataset_total_samples", 900),
        "split_counts": metadata.get("split_counts", {}),
        "evaluation_metrics": metadata.get("evaluation_metrics", {}),
    }


@router.post("/reload")
async def reload_ml_model():
    """Reloads the saved model from disk into the inference cache."""
    try:
        model = reload_model()
        return {
            "status": "OK",
            "message": f"Successfully reloaded Logistic Regression model v{model.model_version}",
            "threshold": model.threshold,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reload model: {e}")


@router.post("/predict")
async def predict_event(
    event: dict[str, Any],
    db: aiosqlite.Connection = Depends(get_db),
):
    """Computes anomaly probability and binary classification on a telemetry event."""
    if "event_id" not in event or "server_id" not in event or "metrics" not in event:
        raise HTTPException(
            status_code=400,
            detail="Payload must include 'event_id', 'server_id', and 'metrics'.",
        )

    try:
        result = await predict_telemetry_event(db, event)
        return result
    except Exception as e:
        logger.error("Error during ML prediction: %s", e)
        raise HTTPException(status_code=500, detail=f"Inference error: {e}")
