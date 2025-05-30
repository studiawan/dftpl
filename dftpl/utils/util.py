import re
from urllib.parse import urlparse
from dftpl.events.LowLevelEvent import LowLevelEvent


class Utils:
    """Utility functions for extracting information from events - standardized to use LowLevelEvent"""
        
    @staticmethod
    def get_file_path(low_level_event: LowLevelEvent) -> str:
        """Extract file path from the low level event"""
        return low_level_event.path
    
    @staticmethod
    def get_timestamp(low_level_event: LowLevelEvent) -> str:
        """Extract timestamp from the low level event"""
        return low_level_event.date_time_min
    
    @staticmethod
    def get_event_type(low_level_event: LowLevelEvent) -> str:
        """Extract event type from the low level event"""
        return low_level_event.type
    
    @staticmethod
    def get_plugin_name(low_level_event: LowLevelEvent) -> str:
        """Extract plugin name from the low level event"""
        return low_level_event.plugin
    
    @staticmethod
    def get_evidence(low_level_event: LowLevelEvent) -> str:
        """Extract evidence from the low level event"""
        return low_level_event.evidence

    @staticmethod
    def get_browser(low_level_event: LowLevelEvent) -> str:
        """Extract browser information from plugin string"""
        browsers = {
            "firefox": "Mozilla Firefox",
            "chrome": "Chromium based Browser",
            "edge": "Microsoft Edge",
            "safari": "Safari",
        }
        
        # Get plugin from the low level event
        plugin = low_level_event.plugin
        if not plugin:
            return "Unknown Browser"
            
        plugin_lower = plugin.lower()
        for key, value in browsers.items():
            if key in plugin_lower:
                return value
        return "Unknown Browser"

    @staticmethod
    def extract_url(low_level_event: LowLevelEvent) -> str:
        """Extract URL from evidence string"""
        evidence = low_level_event.evidence
            
        # First try to get URL before any parentheses
        url_match = evidence.split(" (")[0].strip()
        if url_match.startswith(("http://", "https://", "www.")):
            return url_match

        # If that fails, try to find URL in the full string
        url_pattern = r'https?://[^\s()"]+'
        match = re.search(url_pattern, evidence)
        if match:
            return match.group(0)

        return ""
    
    @staticmethod
    def extract_domain_from_url(low_level_event: LowLevelEvent) -> str:
        """Extract URL from evidence string"""
        url = Utils.extract_url(low_level_event)
        if url:
            # Parse the URL and extract the domain (netloc)
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Remove 'www.' prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]
                
            return domain

        return ""
    
    @staticmethod
    def extract_youtube_video_title(low_level_event: LowLevelEvent) -> str:
        """Extract YouTube video title from evidence string"""
        evidence = low_level_event.evidence 
        
        # Look for title in parentheses after the URL
        # Pattern: (Title - YouTube) or (Title)
        title_pattern = r'\(([^)]+(?:\s*-\s*YouTube)?)\)'
        match = re.search(title_pattern, evidence)
        
        if match:
            title = match.group(1)
            return title.strip()
        
        return ""
    
    @staticmethod
    def extract_search_term(low_level_event: LowLevelEvent) -> str:
        """Extract search term from evidence - useful for search history analysis"""
        evidence = low_level_event.evidence
            
        # Look for common search patterns
        search_patterns = [
            r'q=([^&\s]+)',  # URL parameter q=
        ]
        
        for pattern in search_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return ""