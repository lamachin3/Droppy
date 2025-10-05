from rest_framework import serializers
from .models import StringsAnalysisModel

class StringsAnalysisSerializer(serializers.ModelSerializer):
    class Meta:
        model = StringsAnalysisModel
        fields = [
            "id",
            "scanned_at",
            "matches",
        ]
