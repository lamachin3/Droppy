from django.db import models
from django.utils import timezone


class VirusTotalModel(models.Model):
    queried_at = models.DateTimeField(default=timezone.now)

    file_hash = models.CharField(max_length=128, db_index=True, default="")

    detection_ratio = models.CharField(max_length=20, blank=True, null=True)
    community_score = models.IntegerField(blank=True, null=True)

    first_submission_date = models.DateTimeField(blank=True, null=True)
    last_submission_date = models.DateTimeField(blank=True, null=True)

    permalink = models.URLField(max_length=500, blank=True, null=True)

    def __str__(self):
        if self.detection_ratio:
            return f"VirusTotal: {self.file_hash} ({self.detection_ratio})"

        return f"VirusTotal: {self.file_hash} - Not found"
