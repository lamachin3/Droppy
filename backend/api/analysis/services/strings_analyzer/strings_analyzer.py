from django.core.cache import cache
import requests
from api.analysis.models import StringsAnalysisModel
import lief
import re
from django.utils import timezone


def fetch_malicious_strings(ttl=3600):
    """
    Fetches malicious strings from API with caching.
    ttl = cache time in seconds (default 1 hour)
    """
    api_url = "https://unprotect.it/api/featured_api/"
    cache_key = "malicious_strings"
    cached = cache.get(cache_key)
    #if cached:
    #    return cached

    strings = []
    page = 1
    while True:
        response = requests.get(f"{api_url}?page={page}")
        if response.status_code != 200:
            break

        data = response.json()
        results = data.get("results", [])

        if not results:
            break

        for item in results:
            strings.append({
                "name": item.get("name"), 
                "caution_level": item.get("caution_level"),
            })

        if not data.get("next", None):
            break
        page += 1

    # store in cache
    ca = cache.set(cache_key, strings, ttl)
    return strings


class StringEngine:
    def __init__(self):
        self.malicious_strings = fetch_malicious_strings()
        self._last_results = None

    def extract_strings(self, file_path, min_len=4):
        """
        Extract all printable ASCII and UTF-16LE strings from the binary using lief.
        Returns list of dicts: {'offset': ..., 'string': ...}
        """
        strings = []
        try:
            binary = lief.parse(file_path)
            if not binary:
                return strings

            # Iterate over sections to get raw content
            for section in binary.sections:
                data = section.content
                # Convert to bytes if lief returns list of ints
                if isinstance(data, list):
                    data = bytes(data)

                # ASCII strings
                ascii_strings = [
                    {"offset": m.start(), "string": m.group()}
                    for m in re.finditer(rb"[\x20-\x7E]{%d,}" % min_len, data)
                ]
                strings.extend(ascii_strings)

                # UTF-16LE strings
                utf16le_strings = [
                    {"offset": m.start(), "string": m.group().decode("utf-16le")}
                    for m in re.finditer(rb"(?:[\x20-\x7E]\x00){%d,}" % min_len, data)
                ]
                strings.extend(utf16le_strings)

        except Exception as e:
            print(f"Error extracting strings from {file_path}: {e}")

        return strings

    def scan_file(self, file_path):
        """
        Compare extracted strings against malicious strings.
        Returns matches grouped by string with their offsets and caution levels.
        """
        extracted = self.extract_strings(file_path)
        # Dictionary to store string -> {'offsets': [], 'caution_level': int}
        matches_dict = {}
        
        # Create a mapping of string names to their caution levels for quick lookup
        malicious_strings_map = {
            item['name']: item['caution_level']
            for item in self.malicious_strings
            if item.get('name')
        }
        
        for s in extracted:
            string_val = s['string']
            if isinstance(string_val, bytes):
                string_val = string_val.decode(errors='ignore')  # decode bytes to str
            
            if string_val in malicious_strings_map:
                if string_val not in matches_dict:
                    matches_dict[string_val] = {
                        'offsets': [],
                        'caution_level': malicious_strings_map[string_val],
                        'type': 'API Function'
                    }
                matches_dict[string_val]['offsets'].append(s['offset'])
            elif string_val.lower().endswith(".dll") and not "api-ms-win" in string_val.lower() and string_val.lower() != ".dll":
                if string_val.lower() not in matches_dict:
                    matches_dict[string_val.lower()] = {
                        'offsets': [],
                        'caution_level': None,
                        'type': 'DLL Reference'
                    }
                matches_dict[string_val.lower()]['offsets'].append(s['offset'])
            elif string_val.lower().startswith("http"):
                if string_val.lower() not in matches_dict:
                    matches_dict[string_val.lower()] = {
                        'offsets': [],
                        'caution_level': None,
                        'type': 'URL'
                    }
                matches_dict[string_val.lower()]['offsets'].append(s['offset'])
        
        # Convert to list of dicts
        matches = [
            {
                'string': string,
                'offsets': data['offsets'],
                'caution_level': data['caution_level'],
                'type': data['type']
            }
            for string, data in matches_dict.items()
        ]
        
        # Sort matches by type and then by string value
        matches.sort(key=lambda x: (x['type'], x['string']))
        
        self._last_results = matches

        strings_analysis = StringsAnalysisModel.objects.create(
            scanned_at=timezone.now(),
            matches=matches,
        )

        return strings_analysis
