from rest_framework import serializers
from ..models import YaraScan


class YaraScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = YaraScan
        fields = [
            "id",
            "scanned_at",
            "status",
            "matches",
        ]
