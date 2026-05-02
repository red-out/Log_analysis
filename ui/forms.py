from __future__ import annotations

from django import forms

from analysis.models import WebServer


class UploadLogForm(forms.Form):
    file = forms.FileField(
        label="Файл логов (.log/.txt)",
        widget=forms.ClearableFileInput(attrs={"class": "form-control"}),
    )
    web_server = forms.ModelChoiceField(
        label="Веб-сервер (опционально)",
        queryset=WebServer.objects.all(),
        required=False,
        empty_label="— не задано —",
        widget=forms.Select(attrs={"class": "form-select"}),
    )


class ImportFromFsForm(forms.Form):
    path = forms.CharField(
        label="Путь на сервере/в контейнере",
        help_text='Пример (Docker): "/app/sample_access.log" или "/app/logs/"',
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "/var/log/nginx/access.log",
            }
        ),
    )
    recursive = forms.BooleanField(
        label="Рекурсивно (для директории)",
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )
    skip_analysis = forms.BooleanField(
        label="Только загрузка (без анализа)",
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )
    web_server = forms.ModelChoiceField(
        label="Веб-сервер (опционально)",
        queryset=WebServer.objects.all(),
        required=False,
        empty_label="— не задано —",
        widget=forms.Select(attrs={"class": "form-select"}),
    )

