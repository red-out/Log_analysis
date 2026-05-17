"""
Движок ML: Isolation Forest для обнаружения аномалий.
Обучение на исторических признаках, предсказание с объяснением (explanation).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError

from django.conf import settings

logger = logging.getLogger(__name__)

# Порядок признаков для вектора (числовые)
FEATURE_ORDER = [
    "uri_length",
    "uri_entropy",
    "special_char_count",
    "ip_request_count",
    "user_agent_len",
]


@dataclass
class AnomalyPrediction:
    """Результат предсказания по одной записи."""

    is_anomaly: bool
    confidence_score: float  # 0–1, выше = более аномально
    raw_score: float
    explanation: str


class IsolationForestEngine:
    """
    Обёртка над Isolation Forest: обучение, сохранение на диск,
    предсказание с человекочитаемым объяснением.
    """

    def __init__(
        self,
        model_path: Path | None = None,
        contamination: float = 0.05,
        random_state: int = 42,
    ) -> None:
        if model_path is None:
            models_dir = Path(
                getattr(settings, "ML_MODELS_DIR", settings.MEDIA_ROOT / "models")
            )
            models_dir.mkdir(parents=True, exist_ok=True)
            model_path = models_dir / "isolation_forest.pkl"
        self.model_path: Path = Path(model_path)
        self.contamination = contamination
        self.random_state = random_state
        self._model: IsolationForest | None = None

    @property
    def model(self) -> IsolationForest:
        """Ленивая загрузка или создание модели."""
        if self._model is None:
            if self.model_path.exists():
                try:
                    self._model = joblib.load(self.model_path)
                except Exception as e:
                    logger.error("Failed to load model %s: %s", self.model_path, e)
            if self._model is None:
                self._model = IsolationForest(
                    contamination=self.contamination,
                    random_state=self.random_state,
                    n_estimators=100,
                    n_jobs=-1,
                )
        return self._model

    def _to_vector(self, features: Dict[str, Any]) -> np.ndarray:
        """Словарь признаков -> вектор в фиксированном порядке."""
        return np.array(
            [[float(features.get(name, 0.0)) for name in FEATURE_ORDER]],
            dtype=np.float64,
        )

    def fit(self, feature_dicts: Iterable[Dict[str, Any]]) -> None:
        """
        Обучить Isolation Forest на наборе признаков (unsupervised).

        :param feature_dicts: Итерация словарей с ключами из FEATURE_ORDER.
        """
        vectors: List[List[float]] = []
        for fd in feature_dicts:
            vectors.append([float(fd.get(name, 0.0)) for name in FEATURE_ORDER])
        if not vectors:
            raise ValueError("No feature vectors for training.")
        X = np.array(vectors)
        model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100,
            n_jobs=-1,
        )
        model.fit(X)
        self._model = model
        try:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(model, self.model_path)
        except Exception as e:
            logger.error("Failed to save model %s: %s", self.model_path, e)

    def predict(self, features: Dict[str, Any]) -> AnomalyPrediction:
        """
        Предсказание по одному объекту с объяснением.

        :param features: Словарь признаков (как в LogEntry.features).
        :return: AnomalyPrediction с explanation.
        """
        X = self._to_vector(features)
        model = self.model

        try:
            score = float(model.score_samples(X)[0])
            decision = float(model.decision_function(X)[0])
            is_anomaly = decision < 0.0
            # Нормируем в [0, 1]: чем меньше decision, тем выше confidence
            confidence_score = 1.0 / (1.0 + np.exp(5.0 * decision))
            explanation = self._build_explanation(
                features, score, confidence_score, is_anomaly
            )
        except NotFittedError:
            # Модель ещё не обучена: не считаем это ошибкой, просто даём
            # нулевую уверенность и объяснение, что используется только сигнатурный анализ.
            score = 0.0
            confidence_score = 0.0
            is_anomaly = False
            base = (
                "Модель Isolation Forest ещё не обучена на данных этой системы. "
                "Сейчас решение по аномалиям основывается только на сигнатурах и простых признаках."
            )
            explanation = (
                base
                + " "
                + self._build_explanation(
                    features, score, confidence_score, is_anomaly
                )
            )

        return AnomalyPrediction(
            is_anomaly=is_anomaly,
            confidence_score=float(confidence_score),
            raw_score=score,
            explanation=explanation,
        )

    def _build_explanation(
        self,
        features: Dict[str, Any],
        raw_score: float,
        confidence_score: float,
        is_anomaly: bool,
    ) -> str:
        """
        Текстовое объяснение для пользователя (прозрачность по НИР).
        """
        parts: List[str] = []
        if is_anomaly:
            parts.append(
                "Запрос классифицирован как аномальный моделью Isolation Forest."
            )
        else:
            parts.append(
                "Запрос не классифицирован как аномальный по модели Isolation Forest."
            )
        parts.append(f"Сырой score: {raw_score:.4f}, уверенность в аномальности: {confidence_score:.2f}.")

        uri_len = float(features.get("uri_length", 0))
        uri_entropy = float(features.get("uri_entropy", 0))
        special = float(features.get("special_char_count", 0))
        ip_freq = float(features.get("ip_request_count", 0))
        has_sqli = int(features.get("has_sqli_signature", 0))
        has_xss = int(features.get("has_xss_signature", 0))
        has_path_traversal = int(features.get("has_path_traversal_signature", 0))
        has_cmd = int(features.get("has_cmd_injection_signature", 0))
        has_ssrf = int(features.get("has_ssrf_signature", 0))
        has_ldap = int(features.get("has_ldap_injection_signature", 0))
        has_xxe = int(features.get("has_xxe_signature", 0))
        has_sensitive_file_scan = int(features.get("has_sensitive_file_scan_signature", 0))
        has_invalid_method = int(features.get("has_invalid_method", 0))
        has_open_redirect = int(features.get("has_open_redirect_signature", 0))

        highlight: List[str] = []
        if uri_len > 200:
            highlight.append("очень длинный URI")
        elif uri_len > 100:
            highlight.append("длинный URI")
        if uri_entropy > 4.5:
            highlight.append("высокая энтропия URI (возможная обфускация)")
        elif uri_entropy > 3.5:
            highlight.append("повышенная энтропия URI")
        if special > 15:
            highlight.append("много спецсимволов в URI")
        elif special > 8:
            highlight.append("повышенное число спецсимволов")
        if ip_freq > 500:
            highlight.append("очень частые запросы с одного IP")
        elif ip_freq > 100:
            highlight.append("частые запросы с одного IP")
        if has_sqli:
            highlight.append("совпадение с сигнатурой SQL-инъекции")
        if has_xss:
            highlight.append("совпадение с сигнатурой XSS")
        if has_xxe:
            highlight.append("признаки XXE в запросе")
        if has_cmd:
            highlight.append("признаки command injection / RCE")
        if has_path_traversal:
            highlight.append("попытка Path Traversal / LFI/RFI")
        if has_ldap:
            highlight.append("признаки LDAP-инъекции")
        if has_ssrf:
            highlight.append("признаки SSRF (внутренние хосты, metadata)")
        if has_open_redirect:
            highlight.append("подозрительный open redirect")
        if has_sensitive_file_scan:
            highlight.append("сканирование чувствительных файлов и админок (.env, .git, /wp-admin и т.п.)")
        if has_invalid_method:
            highlight.append("использование нетипичного HTTP-метода (TRACE/TRACK/DEBUG и т.п.)")

        if highlight:
            parts.append("Ключевые факторы: " + ", ".join(highlight) + ".")
        else:
            parts.append(
                "Аномалия обусловлена совокупностью признаков, без явных экстремумов."
            )
        return " ".join(parts)
