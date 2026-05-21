from __future__ import annotations

from datetime import date, datetime, time, timedelta
from pathlib import Path

from django.contrib import messages
from functools import wraps

from django.contrib.auth.decorators import login_required
from django.db import DatabaseError
from django.db.models import Count, Exists, OuterRef, Q
from django.utils import timezone
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.dateparse import parse_date
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from analysis.models import Alert, AnalysisSession, DetectedAnomaly, LogEntry, WebServer
from analysis.serializers import AlertSerializer, DetectedAnomalySerializer, LogEntrySerializer
from analysis.services.ingest import ingest_text
from .forms import UploadLogForm, ImportFromFsForm


def _anomaly_ui_json_dict(anomaly: DetectedAnomaly) -> dict:
    """Те же поля, что в API, плюс полный log_entry (включая raw_line и features)."""
    data = dict(DetectedAnomalySerializer(anomaly).data)
    if anomaly.log_entry_id:
        data["log_entry"] = LogEntrySerializer(anomaly.log_entry).data
    return data


def _alert_ui_json_dict(alert: Alert) -> dict:
    """Полный алерт для UI: вложенная аномалия с полным log_entry."""
    data = dict(AlertSerializer(alert).data)
    if alert.anomaly_id:
        anom = alert.anomaly
        ann = dict(DetectedAnomalySerializer(anom).data)
        if anom.log_entry_id:
            ann["log_entry"] = LogEntrySerializer(anom.log_entry).data
        data["anomaly"] = ann
    return data


STAFF_ONLY_MESSAGE = (
    "Недостаточно прав. Загрузка и импорт логов доступны только администраторам."
)


def staff_required(view_func):
    """Требует is_staff; иначе сообщение и редирект на дашборд (не 404/пустой 403)."""

    @login_required
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_staff:
            messages.error(request, STAFF_ONLY_MESSAGE)
            return redirect("ui:dashboard")
        return view_func(request, *args, **kwargs)

    return _wrapped


def _parse_date_param(raw: str):
    if not (raw or "").strip():
        return None
    return parse_date(raw.strip())


def _alerts_queryset_for_user(user):
    qs = Alert.objects.select_related(
        "anomaly",
        "anomaly__log_entry",
        "anomaly__anomaly_type",
        "recipient",
    )
    if not user.is_staff:
        qs = qs.filter(recipient=user)
    return qs


def _safe_redirect_after_alert_edit(request):
    next_path = (request.POST.get("next") or "").strip()
    if next_path.startswith("/") and not next_path.startswith("//"):
        return redirect(next_path)
    referer = request.META.get("HTTP_REFERER") or ""
    if referer and url_has_allowed_host_and_scheme(
        referer,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return redirect(referer)
    return redirect("ui:alerts")


def _can_edit_alert(user, alert: Alert) -> bool:
    if user.is_staff:
        return True
    return alert.recipient_id == user.id


@login_required
@require_POST
def alert_set_status(request, pk: int):
    alert = get_object_or_404(Alert, pk=pk)
    if not _can_edit_alert(request.user, alert):
        return HttpResponseForbidden("Нет доступа к этому алерту.")

    raw = (request.POST.get("status") or "").strip()
    valid = {s for s, _ in Alert.Status.choices}
    if raw not in valid:
        messages.error(request, "Некорректный статус.")
        return _safe_redirect_after_alert_edit(request)

    if alert.status != raw:
        alert.status = raw
        alert.save(update_fields=["status"])
        messages.success(request, f"Статус алерта #{alert.id} обновлён.")

    return _safe_redirect_after_alert_edit(request)


@login_required
def dashboard(request):
    ctx = {
        "sessions_count": AnalysisSession.objects.count(),
        "log_entries_count": LogEntry.objects.count(),
        "anomalies_count": DetectedAnomaly.objects.count(),
        "new_alerts_count": Alert.objects.filter(status="new").count(),
        "web_servers_count": WebServer.objects.count(),
    }
    return render(request, "ui/dashboard.html", ctx)


@login_required
def sessions(request):
    qs = AnalysisSession.objects.select_related("created_by")

    df = _parse_date_param(request.GET.get("date_from") or "")
    dt = _parse_date_param(request.GET.get("date_to") or "")
    if df:
        qs = qs.filter(start_time__date__gte=df)
    if dt:
        qs = qs.filter(start_time__date__lte=dt)

    user_q = (request.GET.get("created_by") or "").strip()
    if user_q:
        qs = qs.filter(created_by__username__icontains=user_q)

    mv = (request.GET.get("model_version") or "").strip()
    if mv:
        qs = qs.filter(model_version__icontains=mv)

    qs = qs.order_by("-start_time")[:100]
    return render(
        request,
        "ui/sessions.html",
        {
            "sessions": qs,
            "filter_date_from": request.GET.get("date_from") or "",
            "filter_date_to": request.GET.get("date_to") or "",
            "filter_created_by": user_q,
            "filter_model_version": mv,
        },
    )


@login_required
def web_servers(request):
    qs = WebServer.objects.all()

    df = _parse_date_param(request.GET.get("date_from") or "")
    dt = _parse_date_param(request.GET.get("date_to") or "")
    if df:
        qs = qs.filter(created_at__date__gte=df)
    if dt:
        qs = qs.filter(created_at__date__lte=dt)

    name_q = (request.GET.get("q") or "").strip()
    if name_q:
        qs = qs.filter(name__icontains=name_q)

    qs = qs.order_by("name")[:100]
    return render(
        request,
        "ui/web_servers.html",
        {
            "web_servers": qs,
            "filter_date_from": request.GET.get("date_from") or "",
            "filter_date_to": request.GET.get("date_to") or "",
            "filter_q": name_q,
        },
    )


_RISK_LABELS_RU = {
    "low": "Низкий",
    "medium": "Средний",
    "high": "Высокий",
    "critical": "Критический",
}

_METHOD_LABELS_RU = {
    "ml": "ML",
    "signature": "Сигнатурный",
    "hybrid": "Гибрид",
}


@login_required
def stats(request):
    """
    Статистика по алертам и аномалиям за выбранный период (графики в шаблоне).
    """
    today = timezone.localdate()
    default_from = today - timedelta(days=29)

    df = _parse_date_param(request.GET.get("date_from") or "") or default_from
    dt_to = _parse_date_param(request.GET.get("date_to") or "") or today
    if isinstance(df, date) and isinstance(dt_to, date) and df > dt_to:
        df, dt_to = dt_to, df

    start = timezone.make_aware(datetime.combine(df, time.min))
    end = timezone.make_aware(datetime.combine(dt_to, time.max))

    alerts_qs = _alerts_queryset_for_user(request.user).filter(
        created_at__gte=start,
        created_at__lte=end,
    )

    num_days = (dt_to - df).days + 1
    prev_dt_to = df - timedelta(days=1)
    prev_dt_from = prev_dt_to - timedelta(days=num_days - 1)
    prev_start = timezone.make_aware(datetime.combine(prev_dt_from, time.min))
    prev_end = timezone.make_aware(datetime.combine(prev_dt_to, time.max))

    prev_alerts_qs = _alerts_queryset_for_user(request.user).filter(
        created_at__gte=prev_start,
        created_at__lte=prev_end,
    )

    current_alerts_count = alerts_qs.count()
    previous_alerts_count = prev_alerts_qs.count()

    anomalies_qs = DetectedAnomaly.objects.filter(detected_at__gte=start, detected_at__lte=end)
    if not request.user.is_staff:
        anomalies_qs = anomalies_qs.filter(
            Q(analysis_session__created_by=request.user)
            | Q(log_entry__analysis_session__created_by=request.user)
        ).distinct()

    risk_order = ["low", "medium", "high", "critical"]
    risk_map = {
        r["risk_level"]: r["c"] for r in anomalies_qs.values("risk_level").annotate(c=Count("id"))
    }
    risk_labels = []
    risk_values = []
    for k in risk_order:
        v = risk_map.get(k, 0)
        if v > 0:
            risk_labels.append(_RISK_LABELS_RU[k])
            risk_values.append(v)
    if not risk_labels:
        risk_labels = ["Нет данных"]
        risk_values = [0]

    status_order = [s for s, _ in Alert.Status.choices]
    status_label_map = dict(Alert.Status.choices)
    status_map = {r["status"]: r["c"] for r in alerts_qs.values("status").annotate(c=Count("id"))}
    status_labels = []
    status_values = []
    for s in status_order:
        v = status_map.get(s, 0)
        if v > 0:
            status_labels.append(status_label_map[s])
            status_values.append(v)
    if not status_labels:
        status_labels = ["Нет данных"]
        status_values = [0]

    factors_rows = list(
        alerts_qs.values("anomaly__anomaly_type__code")
        .annotate(c=Count("id"))
        .order_by("-c")[:10]
    )
    factor_labels = [(r["anomaly__anomaly_type__code"] or "Без типа") for r in factors_rows]
    factor_values = [r["c"] for r in factors_rows]
    if not factor_labels:
        factor_labels = ["Нет данных"]
        factor_values = [0]

    method_order = ["signature", "ml", "hybrid"]
    method_map = {
        r["detection_method"]: r["c"]
        for r in anomalies_qs.values("detection_method").annotate(c=Count("id"))
    }
    method_labels = []
    method_values = []
    for m in method_order:
        v = method_map.get(m, 0)
        if v > 0:
            method_labels.append(_METHOD_LABELS_RU[m])
            method_values.append(v)
    if not method_labels:
        method_labels = ["Нет данных"]
        method_values = [0]

    chart_data = {
        "risk": {"labels": risk_labels, "values": risk_values},
        "status": {"labels": status_labels, "values": status_values},
        "factors": {"labels": factor_labels, "values": factor_values},
        "methods": {"labels": method_labels, "values": method_values},
        "period_compare": {
            "current": current_alerts_count,
            "previous": previous_alerts_count,
            "current_range": f"{df.strftime('%d.%m.%Y')} — {dt_to.strftime('%d.%m.%Y')}",
            "previous_range": f"{prev_dt_from.strftime('%d.%m.%Y')} — {prev_dt_to.strftime('%d.%m.%Y')}",
        },
    }

    ctx = {
        "filter_date_from": df.isoformat(),
        "filter_date_to": dt_to.isoformat(),
        "chart_data": chart_data,
        "period_days": num_days,
        "prev_period_label": f"{prev_dt_from.strftime('%d.%m.%Y')} — {prev_dt_to.strftime('%d.%m.%Y')}",
    }
    return render(request, "ui/stats.html", ctx)


@login_required
def log_entries(request):
    alert_exists = Alert.objects.filter(anomaly__log_entry_id=OuterRef("pk"))
    qs = LogEntry.objects.select_related("web_server", "analysis_session").annotate(
        has_alert=Exists(alert_exists),
    )

    df = _parse_date_param(request.GET.get("date_from") or "")
    dt = _parse_date_param(request.GET.get("date_to") or "")
    if df:
        qs = qs.filter(timestamp__date__gte=df)
    if dt:
        qs = qs.filter(timestamp__date__lte=dt)

    filter_ip = (request.GET.get("client_ip") or "").strip()
    if filter_ip:
        qs = qs.filter(client_ip=filter_ip)

    filter_status = (request.GET.get("status_code") or "").strip()
    if filter_status.isdigit():
        qs = qs.filter(status_code=int(filter_status))

    filter_method = (request.GET.get("method") or "").strip().upper()
    if filter_method:
        qs = qs.filter(method=filter_method)

    filter_session = (request.GET.get("analysis_session") or "").strip()
    if filter_session.isdigit():
        qs = qs.filter(analysis_session_id=int(filter_session))

    filter_web_server = (request.GET.get("web_server") or "").strip()
    if filter_web_server.isdigit():
        qs = qs.filter(web_server_id=int(filter_web_server))

    has_alert = (request.GET.get("has_alert") or "").strip()
    if has_alert == "yes":
        qs = qs.filter(has_alert=True)
    elif has_alert == "no":
        qs = qs.filter(has_alert=False)

    qs = qs.order_by("-timestamp")[:100]

    return render(
        request,
        "ui/log_entries.html",
        {
            "log_entries": qs,
            "web_servers_list": WebServer.objects.order_by("name"),
            "filter_date_from": request.GET.get("date_from") or "",
            "filter_date_to": request.GET.get("date_to") or "",
            "filter_client_ip": filter_ip,
            "filter_status_code": filter_status,
            "filter_method": filter_method,
            "filter_analysis_session": filter_session,
            "filter_web_server": filter_web_server,
            "filter_has_alert": has_alert,
        },
    )


@login_required
def anomalies(request):
    qs = DetectedAnomaly.objects.select_related(
        "log_entry",
        "log_entry__web_server",
        "anomaly_type",
        "analysis_session",
    )

    df = _parse_date_param(request.GET.get("date_from") or "")
    dt = _parse_date_param(request.GET.get("date_to") or "")
    if df:
        qs = qs.filter(detected_at__date__gte=df)
    if dt:
        qs = qs.filter(detected_at__date__lte=dt)

    risk = (request.GET.get("risk_level") or "").strip()
    if risk in {"low", "medium", "high", "critical"}:
        qs = qs.filter(risk_level=risk)

    q = (request.GET.get("q") or "").strip()
    if q:
        qs = qs.filter(Q(explanation__icontains=q) | Q(log_entry__uri__icontains=q))

    qs = qs.order_by("-detected_at")[:100]
    anomalies_list = list(qs)
    anomaly_details_by_id = {str(a.id): _anomaly_ui_json_dict(a) for a in anomalies_list}

    ctx = {
        "anomalies": anomalies_list,
        "anomaly_details_by_id": anomaly_details_by_id,
        "filter_date_from": request.GET.get("date_from") or "",
        "filter_date_to": request.GET.get("date_to") or "",
        "filter_risk_level": risk,
        "filter_q": q,
        "risk_level_choices": DetectedAnomaly.RiskLevel.choices,
    }
    return render(request, "ui/anomalies.html", ctx)


def _filtered_alerts(request, *, default_status: str):
    qs = _alerts_queryset_for_user(request.user)

    allowed_status = {s for s, _ in Alert.Status.choices} | {"all"}
    status_param = (request.GET.get("status") or "").strip()
    effective = status_param if status_param else default_status
    if effective not in allowed_status:
        effective = default_status

    if effective != "all":
        qs = qs.filter(status=effective)

    df = _parse_date_param(request.GET.get("date_from") or "")
    dt_to = _parse_date_param(request.GET.get("date_to") or "")
    if df:
        qs = qs.filter(created_at__date__gte=df)
    if dt_to:
        qs = qs.filter(created_at__date__lte=dt_to)

    risk = (request.GET.get("risk_level") or "").strip()
    if risk in {"low", "medium", "high", "critical"}:
        qs = qs.filter(risk_level=risk)

    q = (request.GET.get("q") or "").strip()
    if q:
        qs = qs.filter(Q(message__icontains=q) | Q(anomaly__log_entry__uri__icontains=q))

    qs = qs.order_by("-created_at")[:100]

    return qs, {
        "filter_date_from": request.GET.get("date_from") or "",
        "filter_date_to": request.GET.get("date_to") or "",
        "filter_risk_level": risk,
        "filter_q": q,
        "filter_status": effective,
        "risk_level_choices": Alert.RiskLevel.choices,
        "alert_status_choices": Alert.Status.choices,
    }


@login_required
def new_alerts(request):
    alerts_qs, filter_ctx = _filtered_alerts(request, default_status="new")
    alerts_list = list(alerts_qs)
    alert_details_by_id = {str(a.id): _alert_ui_json_dict(a) for a in alerts_list}
    ctx = {"alerts": alerts_list, "alert_details_by_id": alert_details_by_id, **filter_ctx}
    return render(request, "ui/new_alerts.html", ctx)


@staff_required
def upload_logs(request):
    if request.method == "POST":
        form = UploadLogForm(request.POST, request.FILES)
        if form.is_valid():
            f = form.cleaned_data["file"]
            web_server = form.cleaned_data.get("web_server")
            try:
                content = f.read()
                try:
                    text = content.decode("utf-8", errors="ignore")
                except Exception:
                    text = content.decode("cp1251", errors="ignore")

                result = ingest_text(text=text, created_by=request.user, web_server=web_server)
            except DatabaseError:
                messages.error(request, "База данных временно недоступна. Попробуйте позже.")
                return render(request, "ui/upload.html", {"form": form})

            messages.success(
                request,
                f"Найдено аномалий: {result.anomalies_detected}",
            )
            return redirect("ui:dashboard")
    else:
        form = UploadLogForm()

    return render(request, "ui/upload.html", {"form": form})


@staff_required
def import_from_fs(request):
    if request.method == "POST":
        form = ImportFromFsForm(request.POST)
        if form.is_valid():
            path_str = form.cleaned_data["path"]
            recursive = bool(form.cleaned_data.get("recursive"))
            skip_analysis = bool(form.cleaned_data.get("skip_analysis"))
            web_server = form.cleaned_data.get("web_server")

            path = Path(path_str)
            if not path.exists():
                messages.error(request, f"Путь не существует: {path}")
                return render(request, "ui/import.html", {"form": form})

            files = []
            if path.is_file():
                files = [path]
            else:
                if recursive:
                    files = [p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in {".log", ".txt"}]
                else:
                    files = [p for p in path.iterdir() if p.is_file() and p.suffix.lower() in {".log", ".txt"}]

            if not files:
                messages.error(request, "Не найдено файлов .log/.txt по указанному пути.")
                return render(request, "ui/import.html", {"form": form})

            total_anomalies = 0

            for fp in sorted(files):
                try:
                    try:
                        text = fp.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        text = fp.read_text(encoding="cp1251", errors="ignore")
                    result = ingest_text(
                        text=text,
                        created_by=request.user,
                        web_server=web_server,
                        skip_analysis=skip_analysis,
                    )
                except DatabaseError:
                    messages.error(request, "База данных временно недоступна. Импорт прерван.")
                    return render(request, "ui/import.html", {"form": form})

                total_anomalies += result.anomalies_detected

            messages.success(
                request,
                f"Найдено аномалий: {total_anomalies}",
            )
            return redirect("ui:dashboard")
    else:
        form = ImportFromFsForm()

    return render(request, "ui/import.html", {"form": form})


@login_required
def alerts(request):
    alerts_qs, filter_ctx = _filtered_alerts(request, default_status="all")
    ctx = {"alerts": alerts_qs, **filter_ctx}
    return render(request, "ui/alerts.html", ctx)

