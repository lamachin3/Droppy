from rest_framework import serializers
from .models import VirusTotalModel


class VirusTotalSerializer(serializers.ModelSerializer):
    class Meta:
        model = VirusTotalModel
        fields = [
            "id",
            "queried_at",
            "file_hash",
            "detection_ratio",
            "community_score",
            "first_submission_date",
            "last_submission_date",
            "permalink",
        ]
