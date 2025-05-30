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
    
    @staticmethod
    def extract_useradd_activity_type(low_level_event: LowLevelEvent) -> str:
        """Extract the type of useradd activity (new user, new group, failed)"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        if 'new user:' in evidence:
            return "User Created"
        elif 'new group:' in evidence:
            return "Group Created"
        elif 'failed adding user' in evidence:
            return "User Creation Failed"
        
        return "Unknown Activity"
    
    @staticmethod
    def extract_useradd_username(low_level_event: LowLevelEvent) -> str:
        """Extract username from useradd log entry"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for new user: name=username
        user_match = re.search(r'name=([^\s]+)', evidence)
        if user_match:
            return user_match.group(1)
        
        # Pattern for failed adding user 'username'
        failed_match = re.search(r"failed adding user '([^']+)'", evidence)
        if failed_match:
            return failed_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_useradd_creator(low_level_event: LowLevelEvent) -> str:
        """Extract the user who created the new user (from sudo logs)"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Look for sudo log pattern: username : TTY=pts/0 ; PWD=/path ; USER=root ; COMMAND=/usr/sbin/useradd
        sudo_match = re.search(r'(\w+)\s*:\s*TTY=.*COMMAND=.*useradd', evidence)
        if sudo_match:
            return sudo_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_useradd_uid(low_level_event: LowLevelEvent) -> str:
        """Extract UID from useradd log entry"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        uid_match = re.search(r'UID=(\d+)', evidence)
        if uid_match:
            return uid_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_useradd_gid(low_level_event: LowLevelEvent) -> str:
        """Extract GID from useradd log entry"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        gid_match = re.search(r'GID=(\d+)', evidence)
        if gid_match:
            return gid_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_useradd_home(low_level_event: LowLevelEvent) -> str:
        """Extract home directory from useradd log entry"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        home_match = re.search(r'home=([^\s]+)', evidence)
        if home_match:
            return home_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_useradd_shell(low_level_event: LowLevelEvent) -> str:
        """Extract shell from useradd log entry"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        shell_match = re.search(r'shell=([^\s]+)', evidence)
        if shell_match:
            return shell_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_useradd_exit_code(low_level_event: LowLevelEvent) -> str:
        """Extract exit code from failed useradd attempts"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        exit_code_match = re.search(r'exit code:\s*(\d+)', evidence)
        if exit_code_match:
            return exit_code_match.group(1)
        
        return ""
    