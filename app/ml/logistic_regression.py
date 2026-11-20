"""Pure-Python Logistic Regression Binary Classifier with L2 Regularization.

Implemented strictly using Python's standard library (math, json, statistics, random).
No external dependencies (no NumPy, Pandas, Scikit-learn, PyTorch).

Features:
  - Feature Standardization (mean=0, variance=1) fitted strictly on training data.
  - Numerically stable sigmoid function (prevents overflow/underflow).
  - Binary Cross-Entropy Loss with L2 weight regularization.
  - Class-weighted Batch Gradient Descent with Momentum for imbalanced datasets.
  - Configurable decision threshold tuning on validation split (maximizing F1-score).
  - Complete evaluation suite: Accuracy, Precision, Recall, F1, Confusion Matrix.
  - Transparent JSON model serialization and deserialization.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Optional


class Standardizer:
    """Standardizes feature vectors using mean and standard deviation: z = (x - mean) / std.

    Handles zero-variance features safely.
    """

    def __init__(
        self,
        feature_names: list[str],
        means: Optional[list[float]] = None,
        stds: Optional[list[float]] = None,
    ) -> None:
        self.feature_names = feature_names
        self.means = means or [0.0] * len(feature_names)
        self.stds = stds or [1.0] * len(feature_names)

    def fit(self, X: list[list[float]]) -> "Standardizer":
        """Calculates sample means and standard deviations from training data."""
        if not X:
            raise ValueError("Cannot fit Standardizer on empty dataset")

        n_samples = len(X)
        n_features = len(self.feature_names)

        # 1. Means
        means = [0.0] * n_features
        for row in X:
            for j in range(n_features):
                means[j] += row[j]
        means = [s / n_samples for s in means]

        # 2. Standard deviations
        stds = [0.0] * n_features
        for row in X:
            for j in range(n_features):
                diff = row[j] - means[j]
                stds[j] += diff * diff

        # Use sample variance (n - 1) if n > 1
        denom = n_samples - 1 if n_samples > 1 else 1
        stds = [math.sqrt(s / denom) for s in stds]

        # Regularize zero or tiny variance
        for j in range(n_features):
            if stds[j] < 1e-8:
                stds[j] = 1.0

        self.means = [round(m, 6) for m in means]
        self.stds = [round(s, 6) for s in stds]
        return self

    def transform_one(self, x: list[float]) -> list[float]:
        """Scales a single feature vector."""
        return [
            round((x[j] - self.means[j]) / self.stds[j], 6)
            for j in range(len(self.feature_names))
        ]

    def transform(self, X: list[list[float]]) -> list[list[float]]:
        """Scales a list of feature vectors."""
        return [self.transform_one(row) for row in X]

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature_names": self.feature_names,
            "means": self.means,
            "stds": self.stds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Standardizer":
        return cls(
            feature_names=data["feature_names"],
            means=data["means"],
            stds=data["stds"],
        )


def stable_sigmoid(z: float) -> float:
    """Numerically stable logistic sigmoid function.

    Avoids math.exp overflow for large positive or negative z values:
      - For z >= 0: 1 / (1 + exp(-z))
      - For z < 0:  exp(z) / (1 + exp(z))
    """
    if z >= 0:
        ez = math.exp(-z)
        return 1.0 / (1.0 + ez)
    else:
        ez = math.exp(z)
        return ez / (1.0 + ez)


class LogisticRegressionBinaryClassifier:
    """Pure-Python binary Logistic Regression model."""

    def __init__(
        self,
        feature_names: list[str],
        weights: Optional[list[float]] = None,
        intercept: float = 0.0,
        threshold: float = 0.5,
        standardizer: Optional[Standardizer] = None,
        model_version: str = "1.0.0",
        training_configuration: Optional[dict[str, Any]] = None,
        training_metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        self.feature_names = feature_names
        self.model_version = model_version
        self.weights = weights or [0.0] * len(feature_names)
        self.intercept = float(intercept)
        self.threshold = float(threshold)
        self.standardizer = standardizer or Standardizer(feature_names)
        self.training_configuration = training_configuration or {}
        self.training_metadata = training_metadata or {}

    def _linear_combination(self, x: list[float]) -> float:
        """Computes dot product z = bias + sum(w_j * x_j)."""
        z = self.intercept
        for j, w in enumerate(self.weights):
            z += w * x[j]
        return z

    def predict_proba_one_standardized(self, x_std: list[float]) -> float:
        """Returns P(is_anomaly = 1 | x_std) for an already standardized vector."""
        z = self._linear_combination(x_std)
        # Clamp z to safe numeric range (-50, 50) to prevent precision loss
        z_clamped = max(-50.0, min(50.0, z))
        return round(stable_sigmoid(z_clamped), 6)

    def predict_one_standardized(
        self, x_std: list[float], threshold: Optional[float] = None
    ) -> tuple[float, int]:
        """Returns (probability, predicted_class) for an already standardized vector."""
        t = self.threshold if threshold is None else threshold
        prob = self.predict_proba_one_standardized(x_std)
        pred = 1 if prob >= t else 0
        return prob, pred

    def predict_one(
        self, x_raw: list[float], threshold: Optional[float] = None
    ) -> tuple[float, int]:
        """End-to-end inference on raw (unscaled) feature vector: scales and predicts."""
        x_std = self.standardizer.transform_one(x_raw)
        return self.predict_one_standardized(x_std, threshold)

    def predict_proba(self, X_std: list[list[float]]) -> list[float]:
        """Computes anomaly probabilities for a list of standardized vectors."""
        return [self.predict_proba_one_standardized(row) for row in X_std]

    def predict(
        self, X_std: list[list[float]], threshold: Optional[float] = None
    ) -> list[int]:
        """Predicts binary classes (0 or 1) for a list of standardized vectors."""
        t = self.threshold if threshold is None else threshold
        probs = self.predict_proba(X_std)
        return [1 if p >= t else 0 for p in probs]

    def compute_loss(
        self,
        X_std: list[list[float]],
        y: list[int],
        l2_lambda: float = 0.0,
        pos_weight: float = 1.0,
    ) -> float:
        """Computes weighted Binary Cross-Entropy loss with L2 regularization."""
        n = len(X_std)
        if n == 0:
            return 0.0

        eps = 1e-15
        total_loss = 0.0

        for i in range(n):
            p = self.predict_proba_one_standardized(X_std[i])
            p_safe = max(eps, min(1.0 - eps, p))
            yi = y[i]

            if yi == 1:
                total_loss += -pos_weight * math.log(p_safe)
            else:
                total_loss += -math.log(1.0 - p_safe)

        bce = total_loss / n

        # L2 weight regularization (do NOT regularize intercept!)
        l2_reg = 0.0
        if l2_lambda > 0.0:
            l2_reg = (l2_lambda / (2.0 * n)) * sum(w * w for w in self.weights)

        return round(bce + l2_reg, 6)

    def fit(
        self,
        X_train_raw: list[list[float]],
        y_train: list[int],
        learning_rate: float = 0.05,
        iterations: int = 1500,
        l2_lambda: float = 0.01,
        momentum: float = 0.9,
        class_weight: Optional[str] = "balanced",
    ) -> dict[str, Any]:
        """Trains Logistic Regression via Batch Gradient Descent with Momentum.

        Args:
            X_train_raw: raw feature matrix (fitted and transformed internally).
            y_train: binary target labels (0 or 1).
            learning_rate: gradient descent step size.
            iterations: number of full training epochs.
            l2_lambda: L2 regularization strength.
            momentum: momentum coefficient for gradient descent.
            class_weight: 'balanced' to scale positive class loss, or None.

        Returns:
            dict containing training history (loss per 100 epochs, final loss).
        """
        n_samples = len(X_train_raw)
        n_features = len(self.feature_names)

        # 1. Fit Standardizer exclusively on training split
        self.standardizer.fit(X_train_raw)
        X_std = self.standardizer.transform(X_train_raw)

        # 2. Class imbalance weight calculation
        pos_count = sum(y_train)
        neg_count = n_samples - pos_count
        if class_weight == "balanced" and pos_count > 0:
            # Positive samples are rarer, scale positive error gradients
            pos_weight = neg_count / pos_count
        else:
            pos_weight = 1.0

        # 3. Parameter initialisation: Xavier-like small initial weights
        self.weights = [0.0] * n_features
        self.intercept = 0.0

        v_weights = [0.0] * n_features
        v_intercept = 0.0

        loss_history: list[dict[str, Any]] = []

        # 4. Batch Gradient Descent with Momentum
        for epoch in range(1, iterations + 1):
            grad_weights = [0.0] * n_features
            grad_intercept = 0.0

            # Forward pass & gradient accumulation
            for i in range(n_samples):
                xi = X_std[i]
                yi = y_train[i]
                pi = self.predict_proba_one_standardized(xi)

                # Error with class weighting
                if yi == 1:
                    error = (pi - 1.0) * pos_weight
                else:
                    error = (pi - 0.0)

                grad_intercept += error
                for j in range(n_features):
                    grad_weights[j] += error * xi[j]

            # Average gradients
            grad_intercept = grad_intercept / n_samples
            for j in range(n_features):
                # L2 regularization gradient: + (l2_lambda / n) * w_j
                grad_weights[j] = (grad_weights[j] / n_samples) + (l2_lambda / n_samples) * self.weights[j]

            # Momentum updates
            v_intercept = momentum * v_intercept + learning_rate * grad_intercept
            self.intercept -= v_intercept

            for j in range(n_features):
                v_weights[j] = momentum * v_weights[j] + learning_rate * grad_weights[j]
                self.weights[j] -= v_weights[j]

            # Record loss tracking
            if epoch % 200 == 0 or epoch == iterations or epoch == 1:
                cur_loss = self.compute_loss(X_std, y_train, l2_lambda, pos_weight)
                loss_history.append({"epoch": epoch, "loss": cur_loss})

        self.intercept = round(self.intercept, 6)
        self.weights = [round(w, 6) for w in self.weights]

        self.training_configuration = {
            "learning_rate": learning_rate,
            "iterations": iterations,
            "l2_lambda": l2_lambda,
            "momentum": momentum,
            "class_weight": class_weight,
            "pos_weight": round(pos_weight, 4),
        }

        return {
            "final_loss": loss_history[-1]["loss"] if loss_history else 0.0,
            "loss_history": loss_history,
            "samples": n_samples,
            "positive_samples": pos_count,
            "negative_samples": neg_count,
        }

    def select_threshold_on_validation(
        self,
        X_val_raw: list[list[float]],
        y_val: list[int],
        metric: str = "f1",
    ) -> float:
        """Finds optimal decision threshold on validation set (maximizing F1-score).

        Does NOT touch the test set. Tests thresholds from 0.05 to 0.90.
        """
        X_val_std = self.standardizer.transform(X_val_raw)
        best_threshold = 0.5
        best_score = -1.0

        for t_int in range(5, 91, 1):
            t = t_int / 100.0
            eval_res = self.evaluate(X_val_std, y_val, threshold=t)
            score = eval_res["f1_score"]

            if score > best_score:
                best_score = score
                best_threshold = t
            elif abs(score - best_score) < 1e-4:
                # Tie-breaker: prefer higher recall on operational anomaly detection
                if eval_res["recall"] > 0.8:
                    best_threshold = t

        self.threshold = round(best_threshold, 2)
        return self.threshold

    @staticmethod
    def evaluate(
        X_std: list[list[float]],
        y: list[int],
        threshold: float,
        model: Optional["LogisticRegressionBinaryClassifier"] = None,
    ) -> dict[str, Any]:
        """Calculates comprehensive classification performance metrics."""
        n = len(y)
        if n == 0:
            return {"samples": 0}

        # Predict
        tp = 0
        fp = 0
        tn = 0
        fn = 0

        for i in range(n):
            if model is not None:
                prob = model.predict_proba_one_standardized(X_std[i])
            else:
                prob = 0.5
            pred = 1 if prob >= threshold else 0
            actual = y[i]

            if actual == 1 and pred == 1:
                tp += 1
            elif actual == 0 and pred == 1:
                fp += 1
            elif actual == 0 and pred == 0:
                tn += 1
            elif actual == 1 and pred == 0:
                fn += 1

        accuracy = round((tp + tn) / n, 4)
        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        f1_score = (
            round(2.0 * precision * recall / (precision + recall), 4)
            if (precision + recall) > 0
            else 0.0
        )

        return {
            "samples": n,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "confusion_matrix": {
                "predicted_normal": {"actual_normal": tn, "actual_anomaly": fn},
                "predicted_anomaly": {"actual_normal": fp, "actual_anomaly": tp},
            },
        }

    def evaluate_dataset(
        self, X_raw: list[list[float]], y: list[int], threshold: Optional[float] = None
    ) -> dict[str, Any]:
        """Evaluates raw dataset by applying stored standardizer and prediction threshold."""
        t = self.threshold if threshold is None else threshold
        X_std = self.standardizer.transform(X_raw)
        return self.evaluate(X_std, y, threshold=t, model=self)

    def to_dict(self) -> dict[str, Any]:
        """Serializes model parameters to a structured dictionary."""
        weights_dict = {
            self.feature_names[j]: self.weights[j]
            for j in range(len(self.feature_names))
        }
        return {
            "model_type": "LogisticRegressionBinaryClassifier",
            "model_version": self.model_version,
            "feature_names": self.feature_names,
            "classification_threshold": self.threshold,
            "intercept": self.intercept,
            "weights": weights_dict,
            "standardization": self.standardizer.to_dict(),
            "training_configuration": self.training_configuration,
            "training_metadata": self.training_metadata,
        }

    def save(self, filepath: str | Path) -> None:
        """Persists model to JSON on disk."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LogisticRegressionBinaryClassifier":
        """Reconstructs classifier instance from stored dictionary."""
        feature_names = data["feature_names"]
        weights_map = data.get("weights", {})

        if isinstance(weights_map, dict):
            weights_list = [float(weights_map.get(fn, 0.0)) for fn in feature_names]
        else:
            weights_list = [float(w) for w in weights_map]

        standardizer_data = data.get("standardization", {})
        if standardizer_data:
            standardizer = Standardizer.from_dict(standardizer_data)
        else:
            standardizer = Standardizer(feature_names)

        return cls(
            feature_names=feature_names,
            weights=weights_list,
            intercept=float(data.get("intercept", 0.0)),
            threshold=float(data.get("classification_threshold", 0.5)),
            standardizer=standardizer,
            model_version=data.get("model_version", "1.0.0"),
            training_configuration=data.get("training_configuration", {}),
            training_metadata=data.get("training_metadata", {}),
        )

    @classmethod
    def load(cls, filepath: str | Path) -> "LogisticRegressionBinaryClassifier":
        """Loads and constructs classifier instance from JSON on disk."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found at {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)
