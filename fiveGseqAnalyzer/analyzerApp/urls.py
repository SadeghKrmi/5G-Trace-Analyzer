from django.urls import path
from analyzerApp import views


urlpatterns = [
    path('', views.TraceView.as_view(), name="analyaerApp"),
    path('ajax/AnalyzeTrace', views.TraceAnalyzeView.as_view(), name="AnalyzeTrace"),
    path('ajax/TraceUpdater', views.TraceUpdater, name = "TraceUpdater"),
    path('ajax/TraceDelete', views.TraceDelete, name = "TraceDelete"),
    path('ajax/loadTraceSVG', views.loadTraceSVG, name = "loadTraceSVG"),
    path('ajax/downloadTrace', views.downloadTrace, name = "downloadTrace"),
    path('ajax/diagramUpdater', views.diagramUpdater, name = "diagramUpdater"),
    path('ajax/wiresharkUpdater', views.wiresharkUpdater, name = "wiresharkUpdater"),
    
    path('ajax/http2Updater', views.http2Updater, name = "http2Updater"),

    path('ajax/pfcpUpdater', views.pfcpUpdater, name = "pfcpUpdater"),
    path('ajax/pfcpEditor', views.pfcpEditor, name = "pfcpEditor"),
    path('ajax/pfcpReset', views.pfcpReset, name = "pfcpReset"),
    
    path('ajax/ngapUpdater', views.ngapUpdater, name = "ngapUpdater"),
    path('ajax/ngapEditor', views.ngapEditor, name = "ngapEditor"),
    path('ajax/ngapReset', views.ngapReset, name = "ngapReset"),
    
    path('ajax/analyzerScenario', views.analyzerScenario, name = "analyzerScenario"),
    path('ajax/analyzerScenarioLoader', views.analyzerScenarioLoader, name = "analyzerScenarioLoader"),
    path('ajax/analyzerScenarioAction', views.analyzerScenarioAction, name = "analyzerScenarioAction"),
    
    path('ajax/loadSeqLinkText', views.loadSeqLinkText, name = "loadSeqLinkText"),
]

