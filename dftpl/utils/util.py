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
    
    @staticmethod
    def extract_usermod_activity_type(low_level_event: LowLevelEvent) -> str:
        """Extract the type of usermod activity"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        if 'add' in evidence and 'to group' in evidence:
            if 'shadow group' in evidence:
                return "Added to Shadow Group"
            else:
                return "Added to Group"
        elif 'COMMAND=' in evidence and 'usermod' in evidence:
            return "User Modification Command"
        elif 'usermod' in evidence:
            return "User Modified"
        
        return "Unknown Modification"
    
    @staticmethod
    def extract_usermod_target_user(low_level_event: LowLevelEvent) -> str:
        """Extract the target username being modified"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for: add 'username' to group 'groupname'
        add_group_match = re.search(r"add '([^']+)' to (?:shadow )?group", evidence)
        if add_group_match:
            return add_group_match.group(1)
        
        # Pattern for sudo command: COMMAND=/usr/sbin/usermod -aG group username
        command_match = re.search(r'COMMAND=.*usermod.*\s+([^\s]+)', evidence)
        if command_match:
            return command_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_usermod_creator(low_level_event: LowLevelEvent) -> str:
        """Extract the user who executed the usermod command"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Look for sudo log pattern: username : TTY=pts/0 ; PWD=/path ; USER=root ; COMMAND=/usr/sbin/usermod
        sudo_match = re.search(r'(\w+)\s*:\s*TTY=.*COMMAND=.*usermod', evidence)
        if sudo_match:
            return sudo_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_usermod_group(low_level_event: LowLevelEvent) -> str:
        """Extract the group name from usermod activity"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for: add 'username' to group 'groupname'
        group_match = re.search(r"to (?:shadow )?group '([^']+)'", evidence)
        if group_match:
            return group_match.group(1)
        
        # Pattern for command arguments: -aG groupname
        command_group_match = re.search(r'-aG\s+([^\s]+)', evidence)
        if command_group_match:
            return command_group_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_usermod_group_type(low_level_event: LowLevelEvent) -> str:
        """Extract whether it's a regular or shadow group"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        if 'shadow group' in evidence:
            return "shadow"
        elif 'to group' in evidence:
            return "regular"
        
        return ""
    
    @staticmethod
    def extract_usermod_command_args(low_level_event: LowLevelEvent) -> str:
        """Extract the full command arguments from usermod command"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Extract arguments from COMMAND=/usr/sbin/usermod [args]
        command_match = re.search(r'COMMAND=.*usermod\s+(.+)', evidence)
        if command_match:
            return command_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_auth_failure_type(low_level_event: LowLevelEvent) -> str:
        """Extract the type of authentication failure"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        if 'Failed password for invalid user' in evidence:
            return "Failed Password (Invalid User)"
        elif 'Failed password for' in evidence:
            return "Failed Password"
        elif 'authentication failure' in evidence:
            return "Authentication Failure"
        elif 'PAM' in evidence and 'authentication failure' in evidence:
            return "PAM Authentication Failure"
        elif 'Disconnected from' in evidence and 'preauth' in evidence:
            return "Disconnected (Preauth)"
        
        return "Unknown Auth Failure"
    
    @staticmethod
    def extract_auth_target_user(low_level_event: LowLevelEvent) -> str:
        """Extract the target username from authentication attempt"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for: Failed password for [invalid user] username
        failed_password_match = re.search(r'Failed password for (?:invalid user )?([^\s]+)', evidence)
        if failed_password_match:
            return failed_password_match.group(1)
        
        # Pattern for: Disconnected from invalid user username
        disconnected_match = re.search(r'Disconnected from (?:invalid user )?([^\s]+)', evidence)
        if disconnected_match:
            return disconnected_match.group(1)
        
        # Pattern for PAM auth failure: user=username
        pam_match = re.search(r'user=([^\s]+)', evidence)
        if pam_match:
            return pam_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_auth_source_ip(low_level_event: LowLevelEvent) -> str:
        """Extract source IP address from authentication attempt"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for: from IP_ADDRESS port
        ip_port_match = re.search(r'from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', evidence)
        if ip_port_match:
            return ip_port_match.group(1)
        
        # Pattern for: rhost=IP_ADDRESS
        rhost_match = re.search(r'rhost=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', evidence)
        if rhost_match:
            return rhost_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_auth_source_port(low_level_event: LowLevelEvent) -> str:
        """Extract source port from authentication attempt"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for: from IP port PORT_NUMBER
        port_match = re.search(r'port (\d+)', evidence)
        if port_match:
            return port_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_auth_service(low_level_event: LowLevelEvent) -> str:
        """Extract the service/daemon that handled the authentication"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Extract service from log format: [service_name pid: ####]
        service_match = re.search(r'\[([^\s\]]+)', evidence)
        if service_match:
            return service_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_auth_user_validity(low_level_event: LowLevelEvent) -> str:
        """Extract whether the user is valid or invalid"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        if 'invalid user' in evidence:
            return "invalid"
        elif 'Failed password for' in evidence or 'authentication failure' in evidence:
            return "valid"
        
        return ""
    
    @staticmethod
    def extract_auth_tty(low_level_event: LowLevelEvent) -> str:
        """Extract TTY information from authentication attempt"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for: tty=TTY_VALUE
        tty_match = re.search(r'tty=([^\s]+)', evidence)
        if tty_match:
            return tty_match.group(1)
        
        return ""
    
    @staticmethod
    def extract_auth_remote_host(low_level_event: LowLevelEvent) -> str:
        """Extract remote host information"""
        evidence = getattr(low_level_event, 'evidence', '')
        if not evidence:
            return ""
        
        # Pattern for: rhost=HOSTNAME (usually same as IP for direct connections)
        rhost_match = re.search(r'rhost=([^\s]+)', evidence)
        if rhost_match and rhost_match.group(1):
            return rhost_match.group(1)
        
        return ""