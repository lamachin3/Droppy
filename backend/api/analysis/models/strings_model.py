from django.db import models
from django.utils import timezone


class StringsAnalysisModel(models.Model):
    """
    Stores the result of the string-based analysis for one file.
    Linked to DropperModel via OneToOneField (strings_results).
    """

    scanned_at = models.DateTimeField(default=timezone.now)
    
    # Raw matches from the StringEngine
    matches = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return f"StringsAnalysis(id={self.id}, status={self.status})"

