import os
import yara
from django.utils import timezone
from api.analysis.models import YaraScan


class YaraEngine:
    """
    Singleton-like class to manage YARA rules and perform scans.
    """
    _last_results = None
    _last_status = None

    def __init__(self, rules_path=None):
        try:
            self.rules_path = rules_path or os.path.join(
                os.path.dirname(__file__), "rules"
            )
            self.rules = self._load_rules()
            self._last_results = None
        except Exception as e:
            print(f"Error loading Yara rules: {e}")
            self.rules = None
            self._last_results = None

    def _load_rules(self):
        """
        Load and compile all YARA rules from the rules directory.
        Returns a compiled rules object.
        """
        rule_files = {}
        for root, _, files in os.walk(self.rules_path):
            for filename in files:
                if filename.endswith(".yar") or filename.endswith(".yara"):
                    full_path = os.path.join(root, filename)
                    rule_files[filename] = full_path

        if not rule_files:
            raise RuntimeError(f"No YARA rules found in {self.rules_path}")

        return yara.compile(filepaths=rule_files)

    def _determine_status(self):
        """
        Determine file status based on YARA matches.
        Returns 'clean', 'suspicious', or 'malicious'.
        """
        if not self._last_results:
            return "clean"

        # Collect all severities from matched rules
        severities = []
        for match in self._last_results:
            meta = match.get("meta", {})
            severity = meta.get("severity", 0)
            severities.append(severity)

        max_severity = max(severities) if severities else 0

        # Thresholds (tunable)
        if max_severity >= 60:
            return "malicious"
        elif max_severity >= 20:
            return "suspicious"
        else:
            return "clean"

    def scan_file(self, file_path):
        """
        Scan a file using the loaded rules.
        Returns a structured dictionary of matches.
        """
        try:
            matches = self.rules.match(file_path)

            results = []
            for m in matches:
                match_info = {
                    "rule": m.rule,
                    "tags": m.tags,
                    "meta": m.meta,
                    "strings": []
                }

                for s in m.strings:
                    for inst in s.instances:
                        match_info["strings"].append(
                            {
                                "identifier": s.identifier,
                                "offset": inst.offset,
                                "data": inst.matched_data.decode(errors="ignore")
                                if isinstance(inst.matched_data, (bytes, bytearray))
                                else str(inst.matched_data)
                            }
                        )

                results.append(match_info)

            self._last_results = results

            yara_scan_data = {
                "matches": results,
                "status": self._determine_status(),
                "scanned_at": timezone.now(),
            }
            yara_scan = YaraScan.objects.create(**yara_scan_data)

            return yara_scan

        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
            yara_scan_data = {
                "matches": [],
                "status": self._determine_status(),
                "scanned_at": timezone.now(),
            }
            YaraScan.objects.create(**yara_scan_data)
            return []


    def get_results(self):
        """
        Fetch results from the last scan.
        """
        return self._last_results or []
