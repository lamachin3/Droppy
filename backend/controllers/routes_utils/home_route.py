import os
import math
from datetime import datetime
from collections import Counter


def _compute_pe_file_entropy(file_path):
    """
    Computes the Shannon entropy of a Windows PE (Portable Executable) file.
    :param file_path: Path to the PE file
    :return: Entropy value (0 to 8)
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Count occurrences of each byte value (0-255)
        byte_counts = Counter(data)
        total_bytes = len(data)
        
        # Compute entropy using Shannon formula
        entropy = -sum((count / total_bytes) * math.log2(count / total_bytes) 
                       for count in byte_counts.values())
        
        return round(entropy, 1)
    except Exception as e:
        print(f"Error reading file: {e}")
        return None
    
def list_droppers(app):
    """
    Lists all dropper files in the output directory.
    :return: List of dropper files
    """
    files = os.listdir(app.config['OUTPUT_FOLDER'])

    files_details = []
    for file in files:
        file_path = os.path.join(app.config['OUTPUT_FOLDER'], file)
        file_size = os.path.getsize(file_path)
        file_modified_time = os.path.getmtime(file_path)
        file_modified_time_str = datetime.fromtimestamp(file_modified_time).strftime('%Y-%m-%d %H:%M:%S')
        files_details.append({
            'name': file,
            'size': file_size,
            'modified_time': file_modified_time_str,
            'modified_timestamp': file_modified_time,
            'entropy': _compute_pe_file_entropy(os.path.join(app.config['OUTPUT_FOLDER'], file))
        })
    
    files_details.sort(key=lambda x: x['modified_timestamp'], reverse=True)
    return files_details