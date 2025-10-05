from django.db import models
from api.core.models import FileModel
from .dropper_config_model import DropperConfigModel
from api.analysis.models import StringsAnalysisModel, YaraScan, VirusTotalModel


class DropperModel(FileModel):
    config = models.ForeignKey(DropperConfigModel, on_delete=models.CASCADE)
    strings_results = models.OneToOneField(StringsAnalysisModel, on_delete=models.SET_NULL, null=True, blank=True)
    yara_results = models.OneToOneField(YaraScan, on_delete=models.SET_NULL, null=True, blank=True)
    vt_results = models.OneToOneField(VirusTotalModel, on_delete=models.SET_NULL, null=True, blank=True)
