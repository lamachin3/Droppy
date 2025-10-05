from typing import Dict, Any, Optional
from datetime import datetime

from .file_analysis import FileAnalyzer


class DataEnrichmentService:
    """
    Main service for enriching data with various analyzers.
    """
    
    @staticmethod
    def enrich_dropper(dropper_instance) -> Dict[str, Any]:
        """
        Enrich a dropper instance with various types of analysis.
        
        Args:
            dropper_instance: The dropper instance to enrich
            
        Returns:
            Dict containing enriched data
        """
        if not dropper_instance:
            return {}
            
        enriched_data = {}
        
        # Add file analysis if file exists
        if hasattr(dropper_instance, 'file') and dropper_instance.file:
            file_analysis = {}

            with open(dropper_instance.file.path, 'rb') as file_obj:
                file_analyzer = FileAnalyzer(file_obj)
                file_analysis = file_analyzer.analyze()
            
            # Map file analysis to the expected format
            enriched_data.update({
                'size': file_analysis.get('size'),
                'type': file_analysis.get('type', 'Unknown'),
                'architecture': file_analysis.get('architecture', 'Unknown'),
                'entropy': file_analysis.get('entropy'),
                'analyzed_at': file_analysis.get('analyzed_at')
            })
        
        return enriched_data
