
from django.db import models
from django.utils import timezone

# Create your models here.
class UploadedTracesModel(models.Model):
    id = models.AutoField(primary_key=True)
    TestName = models.CharField(max_length=50, unique=True)
    realFileName = models.CharField(max_length=50)
    status = models.CharField(max_length=20, null=True, blank=True)
    uploaded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        verbose_name = 'Uploaded Trace'
        verbose_name_plural = 'Uploaded Traces'
    def __str__(self):
        return self.TestName



# Create your models here.
class AnalyzerScenarioModel(models.Model):
    id = models.AutoField(primary_key=True)
    scenarioName = models.CharField(max_length=100, unique=True)
    scenarioDescription = models.CharField(max_length=100)
    uploaded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        verbose_name = 'Analyzer Scenario'
        verbose_name_plural = 'Analyzer Scenario'
    def __str__(self):
        return self.scenarioName
