import os
import json
import numpy as np
import pandas as pd
from typing import Tuple, Optional, Dict, List, Callable
from collections import Counter

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import (
    train_test_split, cross_val_score, GridSearchCV, learning_curve,
)
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    precision_recall_fscore_support, roc_auc_score,
)
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.inspection import permutation_importance
import joblib

from .config import MODEL_FILE, PCA_MIN_SAMPLES
from .nist_suite import CryptoScientificLibrary


FEATURE_NAMES = [
    "shannon_entropy", "sac_avalanche", "byte_uniformity",
    "monobit_stat", "monobit_p",
    "block_freq_stat", "block_freq_p",
    "runs_stat", "runs_p",
    "fft_stat", "fft_p",
    "diffusion",
    "cumulative_sums_p",
    "serial_p1", "serial_p2",
    "approx_entropy_p",
    "chi_square",
    "autocorrelation",
    "compression_ratio",
]

CIPHER_CLASSES = [
    "Fernet (AES-128-CBC + HMAC)", "AES-256-GCM",
    "ChaCha20-Poly1305", "AES-256-CBC + HMAC-SHA256",
    "AES-128-GCM", "AES-128-CBC + HMAC-SHA256",
    "TripleDES (educational)", "Blowfish (educational)",
    "XOR + HMAC (educational)", "Vigenere (educational)",
]


class CipherMLClassifier:
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.rf_model = RandomForestClassifier(
            n_estimators=100, random_state=random_state
        )
        self.mlp_model = MLPClassifier(
            hidden_layer_sizes=(64, 32), max_iter=300,
            random_state=random_state, early_stopping=True,
            validation_fraction=0.2, n_iter_no_change=5, tol=1e-3,
        )
        self.anomaly_detector = IsolationForest(
            contamination=0.1, random_state=random_state
        )
        self._is_trained = False
        self._cv_score = None
        self._test_accuracy = None
        self._test_report = None
        self._confusion_matrix = None
        self._feature_importances = None
        self._permutation_importance = None
        self._class_names = CIPHER_CLASSES
        self._training_samples = []  # for active learning / drift
        self._feature_importance_history = []  # for drift tracking
        self._hpo_best_params = None
        self._anomaly_threshold = None
        self._learning_curve = None
        self._best_model = None

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    @property
    def test_accuracy(self) -> Optional[float]:
        return self._test_accuracy

    @property
    def cv_score(self) -> Optional[float]:
        return self._cv_score

    @property
    def feature_importances(self) -> Optional[list]:
        return self._feature_importances

    @property
    def feature_importance_history(self) -> list:
        return self._feature_importance_history

    @property
    def n_features(self) -> int:
        return len(FEATURE_NAMES)

    @property
    def n_classes(self) -> int:
        return len(self._class_names)

    def extract_features(self, data: bytes, msg: str, key: bytes,
                         encrypt_fn: Optional[Callable] = None) -> np.ndarray:
        return CryptoScientificLibrary.extract_full_features(data, msg, key, encrypt_fn)

    def _generate_benchmark_data(self, n_per_class: int = 30,
                                  real_X: Optional[np.ndarray] = None,
                                  real_y: Optional[np.ndarray] = None) -> Tuple[np.ndarray, np.ndarray]:
        """Generate realistic synthetic benchmark data for 10 cipher classes."""
        np.random.seed(self.random_state)
        X_list, y_list = [], []

        class_params = [
            # [entropy, sac, uniformity, monobit_stat, monobit_p, blk_stat, blk_p,
            #  runs_stat, runs_p, fft_stat, fft_p, diffusion,
            #  cum_p, ser_p1, ser_p2, ap_p, chi2, autocorr, compress]
            # Strong ciphers: high entropy, good p-values, ~50% diffusion
            [7.8, 50, 0.92, 0.50, 0.50, 8, 0.50, 1.0, 0.50, 1000, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50, 250, 0.0, 0.95],  # Fernet
            [7.9, 52, 0.95, 0.50, 0.55, 8, 0.52, 1.0, 0.52, 1000, 0.52, 0.52, 0.52, 0.52, 0.52, 0.52, 260, 0.0, 0.95],  # AES-256-GCM
            [7.8, 51, 0.93, 0.50, 0.53, 8, 0.51, 1.0, 0.51, 1000, 0.51, 0.51, 0.51, 0.51, 0.51, 0.51, 255, 0.0, 0.95],  # ChaCha20
            [7.7, 49, 0.91, 0.50, 0.48, 8, 0.49, 1.0, 0.49, 1000, 0.49, 0.49, 0.49, 0.49, 0.49, 0.49, 245, 0.0, 0.94],  # AES-256-CBC+HMAC
            [7.8, 50, 0.92, 0.50, 0.50, 8, 0.50, 1.0, 0.50, 1000, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50, 250, 0.0, 0.95],  # AES-128-GCM
            [7.7, 48, 0.90, 0.50, 0.47, 8, 0.48, 1.0, 0.48, 1000, 0.48, 0.48, 0.48, 0.48, 0.48, 0.48, 240, 0.0, 0.94],  # AES-128-CBC+HMAC
            # Legacy/weak ciphers: lower entropy, structure detectable
            [6.0, 30, 0.60, 0.35, 0.10, 15, 0.12, 1.2, 0.08, 800, 0.10, 0.30, 0.10, 0.08, 0.08, 0.10, 500, 0.2, 1.10],  # 3DES
            [5.5, 25, 0.55, 0.30, 0.05, 18, 0.08, 1.3, 0.05, 700, 0.06, 0.25, 0.06, 0.05, 0.05, 0.06, 600, 0.3, 1.15],  # Blowfish
            [4.0, 15, 0.40, 0.20, 0.01, 25, 0.02, 1.5, 0.01, 500, 0.02, 0.15, 0.01, 0.01, 0.01, 0.01, 900, 0.5, 1.30],  # XOR+HMAC
            [3.0, 5, 0.25, 0.10, 0.001, 40, 0.001, 2.0, 0.001, 300, 0.001, 0.05, 0.001, 0.001, 0.001, 0.001, 1500, 0.7, 1.50],  # Vigenere
        ]

        for idx, params in enumerate(class_params):
            base = np.array(params)
            noise = np.random.normal(0, [0.1, 2, 0.02, 0.02, 0.05, 0.5, 0.05, 0.02, 0.05, 5, 0.05, 0.02, 0.05, 0.05, 0.05, 0.05, 10, 0.02, 0.01],
                                     size=(n_per_class, len(params)))
            X_class = base + noise
            X_class[:, 0] = np.clip(X_class[:, 0], 0, 8)
            X_class[:, 1] = np.clip(X_class[:, 1], 0, 100)
            X_class[:, 2] = np.clip(X_class[:, 2], 0, 1)
            X_class[:, 3] = np.clip(X_class[:, 3], 0, 1)
            X_class[:, 18] = np.clip(X_class[:, 18], 0.5, 2.0)
            X_list.append(X_class)
            y_list.append(np.full(n_per_class, idx))

        X_syn = np.vstack(X_list)
        y_syn = np.concatenate(y_list)
        if real_X is not None and real_y is not None and len(real_X) > 0:
            X_syn = np.vstack([X_syn, real_X])
            y_syn = np.concatenate([y_syn, real_y])
        return X_syn, y_syn

    def train(self, X: np.ndarray = None, y: np.ndarray = None,
              do_hpo: bool = False, do_learning_curve: bool = False) -> Dict:
        if X is None or y is None:
            X, y = self._generate_benchmark_data(n_per_class=20)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=self.random_state, stratify=y
        )

        # --- Random Forest ---
        self.rf_model.fit(X_train, y_train)
        cv_scores = cross_val_score(self.rf_model, X_train, y_train, cv=3)
        self._cv_score = float(cv_scores.mean())

        y_pred = self.rf_model.predict(X_test)
        self._test_accuracy = float(accuracy_score(y_test, y_pred))
        self._test_report = classification_report(
            y_test, y_pred, target_names=self._class_names,
            output_dict=True, zero_division=0,
        )
        self._confusion_matrix = confusion_matrix(y_test, y_pred).tolist()
        self._feature_importances = self.rf_model.feature_importances_.tolist()

        # --- Permutation Importance ---
        try:
            perm = permutation_importance(
                self.rf_model, X_test, y_test, n_repeats=5,
                random_state=self.random_state, n_jobs=1,
            )
            self._permutation_importance = perm.importances_mean.tolist()
        except Exception:
            self._permutation_importance = self._feature_importances.copy()

        # --- MLP Classifier ---
        try:
            self.mlp_model.fit(X_train, y_train)
            mlp_acc = accuracy_score(y_test, self.mlp_model.predict(X_test))
        except Exception:
            mlp_acc = 0.0

        # --- Anomaly Detection ---
        self.anomaly_detector.fit(X_train)

        # --- Hyperparameter Optimization ---
        if do_hpo and len(np.unique(y_train)) > 1:
            try:
                param_grid = {
                    "n_estimators": [50, 100, 200],
                    "max_depth": [None, 10, 20],
                    "min_samples_split": [2, 5],
                }
                gs = GridSearchCV(
                    RandomForestClassifier(random_state=self.random_state),
                    param_grid, cv=3, scoring="accuracy", n_jobs=1,
                )
                gs.fit(X_train[:500], y_train[:500])
                self._hpo_best_params = gs.best_params_
            except Exception:
                self._hpo_best_params = None

        # --- Learning Curve ---
        self._learning_curve = None
        if do_learning_curve:
            try:
                lc_result = learning_curve(
                    self.rf_model, X, y, cv=3, n_jobs=1,
                    train_sizes=np.linspace(0.1, 1.0, 5),
                )
                self._learning_curve = {
                    "train_sizes": lc_result[0].tolist(),
                    "train_mean": lc_result[1].mean(axis=1).tolist(),
                    "test_mean": lc_result[2].mean(axis=1).tolist(),
                }
            except Exception:
                self._learning_curve = None

        self._best_model = "rf"
        self._is_trained = True
        self._feature_importance_history.append({
            "timestamp": pd.Timestamp.now().isoformat(),
            "n_train_samples": len(y_train),
            "test_accuracy": self._test_accuracy,
            "feature_importances": self._feature_importances,
        })

        return {
            "cv_mean_accuracy": self._cv_score,
            "test_accuracy": self._test_accuracy,
            "mlp_accuracy": float(mlp_acc),
            "feature_importances": self._feature_importances,
            "feature_names": FEATURE_NAMES,
            "n_classes": self.n_classes,
            "n_samples": len(y),
            "n_features": len(FEATURE_NAMES),
            "confusion_matrix": self._confusion_matrix,
            "hpo_best_params": self._hpo_best_params,
            "learning_curve": self._learning_curve,
            "classification_report": self._test_report,
        }

    def predict(self, sample_vector: np.ndarray) -> Tuple[int, float]:
        if not self._is_trained:
            raise RuntimeError("Model not trained.")
        pred = int(self.rf_model.predict(sample_vector)[0])
        probas = self.rf_model.predict_proba(sample_vector)[0]
        return pred, float(probas[pred])

    def predict_all_probas(self, sample_vector: np.ndarray) -> np.ndarray:
        """Return probability array for all classes."""
        if not self._is_trained:
            raise RuntimeError("Model not trained.")
        return self.rf_model.predict_proba(sample_vector)[0]

    def get_class_label(self, pred: int) -> str:
        return self._class_names[pred] if 0 <= pred < len(self._class_names) else f"Unknown ({pred})"

    def compute_learning_curve(self, X: np.ndarray = None, y: np.ndarray = None) -> Optional[Dict]:
        if X is None or y is None:
            X, y = self._generate_benchmark_data(n_per_class=20)
        try:
            lc_result = learning_curve(
                self.rf_model, X, y, cv=3, n_jobs=1,
                train_sizes=np.linspace(0.1, 1.0, 5),
            )
            self._learning_curve = {
                "train_sizes": lc_result[0].tolist(),
                "train_mean": lc_result[1].mean(axis=1).tolist(),
                "test_mean": lc_result[2].mean(axis=1).tolist(),
            }
        except Exception:
            self._learning_curve = None
        return self._learning_curve

    def detect_anomaly(self, sample_vector: np.ndarray) -> Tuple[bool, float]:
        """Returns (is_anomaly, anomaly_score). Lower scores = more anomalous."""
        score = float(self.anomaly_detector.score_samples(sample_vector)[0])
        pred = int(self.anomaly_detector.predict(sample_vector)[0])
        return pred == -1, score

    def get_top_features(self, n: int = 5) -> List[Tuple[str, float]]:
        """Return top-n (feature_name, importance) pairs."""
        if not self._feature_importances:
            return []
        pairs = list(zip(FEATURE_NAMES, self._feature_importances))
        pairs.sort(key=lambda x: -x[1])
        return pairs[:n]

    def get_confusion_matrix(self) -> Optional[pd.DataFrame]:
        if not self._confusion_matrix:
            return None
        return pd.DataFrame(
            self._confusion_matrix,
            index=self._class_names,
            columns=self._class_names,
        )

    @staticmethod
    def compute_pca(df: pd.DataFrame, feature_cols: list) -> Optional[pd.DataFrame]:
        if len(df) < PCA_MIN_SAMPLES:
            return None
        X = df[feature_cols].fillna(0).values
        pca = PCA(n_components=2)
        coords = pca.fit_transform(X)
        result = pd.DataFrame(coords, columns=["PC1", "PC2"])
        result["SecurityIndex"] = df.get("SecurityIndex", 0)
        result["explained_variance_ratio"] = pca.explained_variance_ratio_.sum()
        return result

    @staticmethod
    def compute_tsne(df: pd.DataFrame, feature_cols: list,
                     perplexity: int = 5) -> Optional[pd.DataFrame]:
        if len(df) < 3:
            return None
        X = df[feature_cols].fillna(0).values
        pp = min(perplexity, len(df) - 1)
        try:
            tsne = TSNE(n_components=2, perplexity=pp, random_state=42)
            coords = tsne.fit_transform(X)
            result = pd.DataFrame(coords, columns=["tSNE1", "tSNE2"])
            result["SecurityIndex"] = df.get("SecurityIndex", 0)
            return result
        except Exception:
            return None

    def add_training_sample(self, features: list, label: str):
        self._training_samples.append({
            "features": features,
            "label": label,
        })

    def get_training_data_from_history(self, history: List[Dict]) -> Tuple[Optional[np.ndarray], Optional[np.ndarray]]:
        """Extract features and labels from encryption history for active learning."""
        if not history:
            return None, None
        X_list, y_list = [], []
        for entry in history:
            feats = [
                entry.get("Entropy", 0),
                entry.get("SAC", 0),
                entry.get("Uniformity", 0),
                entry.get("Monobit", 0),
                entry.get("Monobit_PValue", 0),
                0, 0,  # block freq (not in history yet)
                entry.get("Runs", 0),
                entry.get("Runs_PValue", 0),
                0,  # FFT stat
                entry.get("FFT_PValue", 0),
                entry.get("Diffusion", 0),
                0.5, 0.5, 0.5, 0.5, 0, 0, 0.95,  # new feature defaults
            ]
            X_list.append(feats)
            mode = entry.get("CipherMode", CIPHER_CLASSES[0])
            if mode in CIPHER_CLASSES:
                y_list.append(CIPHER_CLASSES.index(mode))
            else:
                y_list.append(0)
        if not X_list:
            return None, None
        return np.array(X_list, dtype=np.float64), np.array(y_list)

    def retrain_with_history(self, history: List[Dict], do_hpo: bool = False,
                              n_per_class: int = 20) -> Optional[Dict]:
        X_real, y_real = self.get_training_data_from_history(history)
        if X_real is None or len(X_real) < 2:
            return None
        X_comb, y_comb = self._generate_benchmark_data(
            n_per_class=n_per_class, real_X=X_real, real_y=y_real
        )
        return self.train(X_comb, y_comb, do_hpo=do_hpo)

    def get_feature_importance_df(self) -> pd.DataFrame:
        if not self._feature_importances:
            return pd.DataFrame({"feature": FEATURE_NAMES, "importance": [0] * len(FEATURE_NAMES)})
        return pd.DataFrame({
            "feature": FEATURE_NAMES,
            "importance": self._feature_importances,
            "permutation": self._permutation_importance if self._permutation_importance else self._feature_importances,
        }).sort_values("importance", ascending=False)

    def get_drift_df(self) -> pd.DataFrame:
        if not self._feature_importance_history:
            return pd.DataFrame()
        rows = []
        for entry in self._feature_importance_history:
            for fi_idx, fi_val in enumerate(entry["feature_importances"]):
                if fi_idx < len(FEATURE_NAMES):
                    rows.append({
                        "timestamp": entry["timestamp"],
                        "feature": FEATURE_NAMES[fi_idx],
                        "importance": fi_val,
                    })
        return pd.DataFrame(rows)

    def save(self, path: str = MODEL_FILE):
        if self._is_trained:
            joblib.dump(self, path)

    @staticmethod
    def load(path: str = MODEL_FILE) -> Optional["CipherMLClassifier"]:
        if os.path.exists(path):
            return joblib.load(path)
        return None
