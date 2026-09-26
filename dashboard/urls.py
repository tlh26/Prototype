from django.urls import path

from . import views

app_name = "dashboard"

urlpatterns = [
    path("", views.index, name="index"),
    path("correlations/", views.correlations, name="correlations"),
    path("evidence/", views.evidence, name="evidence"),
    path(
        "evidence/<str:evidence_id>/",
        views.evidence_detail,
        name="evidence_detail",
    ),
]

