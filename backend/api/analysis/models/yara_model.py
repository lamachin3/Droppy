from django.db import models
from django.utils import timezone


class YaraScan(models.Model):
    """
    Stores the YARA scanning results for one file.
    Linked to DropperModel via OneToOneField (yara_results).
    """

    scanned_at = models.DateTimeField(default=timezone.now)

    # Could be: 'clean', 'suspicious', 'malicious', 'error'
    status = models.CharField(max_length=20, default="pending")

    # Raw YARA matches, stored as JSON (rules, tags, metadata, strings)
    matches = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return f"YaraScan {self.id} - {self.status}"
