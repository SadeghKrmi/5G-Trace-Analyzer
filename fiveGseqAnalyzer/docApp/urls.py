from django.urls import path
from docApp import views

urlpatterns = [
    path('', views.documentation.as_view(), name = "docs"),
]
