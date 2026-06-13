
from django.contrib import admin
from django.urls import path, include
from django.shortcuts import render


def index(request):
    return render(request, "index.html")

urlpatterns = [
    path("", index),
    path('admin/', admin.site.urls),
    path("", include("core.urls")),
]

