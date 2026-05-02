from django.contrib.auth.views import LoginView, LogoutView
from django.urls import path

from .views import (
    dashboard,
    upload_logs,
    import_from_fs,
    alerts,
    sessions,
    web_servers,
    stats,
    log_entries,
    anomalies,
    new_alerts,
    alert_set_status,
)


app_name = "ui"

urlpatterns = [
    path(
        "login/",
        LoginView.as_view(
            template_name="ui/login.html",
            redirect_authenticated_user=True,
        ),
        name="login",
    ),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("", dashboard, name="dashboard"),
    path("stats/", stats, name="stats"),
    path("sessions/", sessions, name="sessions"),
    path("web-servers/", web_servers, name="web_servers"),
    path("log-entries/", log_entries, name="log_entries"),
    path("anomalies/", anomalies, name="anomalies"),
    path("alerts/<int:pk>/status/", alert_set_status, name="alert_set_status"),
    path("alerts/new/", new_alerts, name="new_alerts"),
    path("upload/", upload_logs, name="upload"),
    path("import/", import_from_fs, name="import"),
    path("alerts/", alerts, name="alerts"),
]

