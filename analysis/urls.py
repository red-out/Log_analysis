"""
URL маршруты API приложения analysis.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    LogUploadView,
    DetectedAnomalyViewSet,
    AlertViewSet,
    AnalysisSessionViewSet,
    LogEntryViewSet,
)

router = DefaultRouter()
router.register(r"anomalies", DetectedAnomalyViewSet, basename="anomaly")
router.register(r"alerts", AlertViewSet, basename="alert")
router.register(r"sessions", AnalysisSessionViewSet, basename="session")
router.register(r"log-entries", LogEntryViewSet, basename="logentry")

urlpatterns = [
    path("logs/upload/", LogUploadView.as_view(), name="log-upload"),
    path("", include(router.urls)),
]
