import logging
from typing import Any, Dict, Optional

import vt
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


class VirusTotalEngine:

    def __init__(self, file_hash: str):
        self.api_key = getattr(settings, "VIRUSTOTAL_API_KEY", None)
        if not self.api_key:
            raise ValueError("VirusTotal API key not configured in settings (VIRUSTOTAL_API_KEY).")

        self.file_hash = file_hash

    def _vt_get_file_object(self) -> Optional[Any]:
        try:
            with vt.Client(self.api_key) as client:
                vt_obj = client.get_object("/files/{}", self.file_hash)
                return vt_obj
        except vt.error.APIError as e:
            logger.warning("VirusTotal API error while fetching %s: %s", self.file_hash, e)
            return None
        except Exception as e:
            logger.exception("Unexpected error contacting VirusTotal: %s", e)
            return None

    def check_file(self) -> Dict[str, Any]:
        queried_at = timezone.now()
        vt_obj = self._vt_get_file_object()

        if not vt_obj:
            return {
                "found": False,
                "hash": self.file_hash,
                "queried_at": queried_at,
                "scan_data": None,
            }

        malicious = vt_obj.last_analysis_stats.get("malicious", 0)
        total = sum(v for v in vt_obj.last_analysis_stats.values() if isinstance(v, int))
        detection_ratio = f"{malicious}/{total}" if total > 0 else "0/0"

        community_score = vt_obj.reputation
        tags = vt_obj.get("capabilities_tags", [])
        first_submission = vt_obj.first_submission_date
        last_submission = vt_obj.last_submission_date
        permalink = f"https://www.virustotal.com/gui/file/{self.file_hash}"

        vt_data = {
            "detection_ratio": detection_ratio,
            "community_score": community_score,
            "tags": tags,
            "first_submission_date": first_submission,
            "last_submission_date": last_submission,
            "permalink": permalink,
        }

        return {
            "found": True,
            "hash": self.file_hash,
            "queried_at": queried_at,
            "scan_data": vt_data,
        }
