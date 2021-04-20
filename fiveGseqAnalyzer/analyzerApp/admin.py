from django.contrib import admin
from analyzerApp.models import UploadedTracesModel, AnalyzerScenarioModel
# Register your models here.

class UploadedTracesModelAdmin(admin.ModelAdmin):
    readonly_fields = ('id','uploaded_at',)

class AnalyzerScenarioModelAdmin(admin.ModelAdmin):
    readonly_fields = ('id','uploaded_at',)

admin.site.register(UploadedTracesModel, UploadedTracesModelAdmin)
admin.site.register(AnalyzerScenarioModel, AnalyzerScenarioModelAdmin)
